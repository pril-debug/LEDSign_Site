#!/usr/bin/env python3
import io
import ipaddress
import json
import os
import secrets
import subprocess
from datetime import timedelta
from pathlib import Path
from flask import Flask, request, redirect, url_for, render_template, session, flash, send_file, abort
from werkzeug.security import check_password_hash, generate_password_hash
from PIL import Image, UnidentifiedImageError
import device
import activity

APP_ROOT = Path(__file__).resolve().parents[1]
CONF_PATH = APP_ROOT / 'config/settings.json'
LOGO_DEFAULT = APP_ROOT / 'config/Logo-White.png'
LOGO_CUSTOM = APP_ROOT / 'config/customer_logo.png'
SCRIPTS_DIR = APP_ROOT / 'scripts'
app = Flask(__name__)
# Persistent secret supports multiple workers and service restarts; never replace settings.
def secret():
    if os.environ.get('SC_SECRET'):
        return os.environ['SC_SECRET']
    path = APP_ROOT / 'config/.web-secret'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    with os.fdopen(fd, 'w') as f:
        value = secrets.token_hex(32)
        f.write(value)
    return value
app.secret_key = secret()
app.config.update(MAX_CONTENT_LENGTH=4*1024*1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=timedelta(hours=8))


def load_conf():
    return json.loads(CONF_PATH.read_text())


def save_conf(conf):
    tmp = CONF_PATH.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        os.chmod(tmp, 0o600)
        json.dump(conf, f, indent=2)
    os.replace(tmp, CONF_PATH)


def auth_version():
    import hashlib
    return hashlib.sha256(load_conf()['auth']['password_hash'].encode()).hexdigest()


@app.before_request
def protect():
    public = {'landing', 'login', 'static', 'health'}
    if request.endpoint not in public:
        if not session.get('auth') or session.get('version') != auth_version():
            session.clear()
            return redirect(url_for('login'))
    if request.method == 'POST':
        if not secrets.compare_digest(session.get('csrf', ''), request.form.get('csrf', '')) or not session.get('csrf'):
            abort(400, 'The form expired. Reload the page and try again.')


@app.context_processor
def globals_():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(32)
    import hashlib
    assets = b''.join((Path(app.static_folder) / name).read_bytes() for name in ('style.css', 'app.js'))
    return dict(csrf=session['csrf'], custom_logo_exists=LOGO_CUSTOM.exists(), asset_version=hashlib.sha256(assets).hexdigest()[:12])


@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response


@app.get('/')
def landing():
    return render_template('landing.html', title='Full-Color LED Race Clock')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conf = load_conf()['auth']
        if request.form.get('username', '').strip() == conf['username'] and check_password_hash(conf['password_hash'], request.form.get('password', '')):
            session.clear()
            session.update(auth=True, version=auth_version(), permanent=True)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html', title='Admin login')


@app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))


@app.get('/dashboard')
def dashboard():
    return render_template('dashboard.html', title='Dashboard', status=device.status())


@app.get('/display')
def display():
    return render_template('display.html', title='Display', conf=load_conf())


@app.get('/settings')
def settings():
    return render_template('settings.html', title='Settings', status=device.status())


@app.get('/logs')
def logs():
    filters = dict(service=request.args.get('service', 'all'), window=request.args.get('window', 'day'),
                   query=request.args.get('q', '').strip(), level=request.args.get('level', 'all'))
    error = None
    history = dict(events=[], total=0, scanned=0, limited=False, page=1, pages=1)
    try:
        page = int(request.args.get('page', '1'))
        history = activity.read_history(**filters, page=page)
    except ValueError as e:
        error = str(e) if not str(e).startswith('invalid literal') else 'Choose a valid page number.'
    page_args = dict(service=filters['service'], window=filters['window'], q=filters['query'], level=filters['level'])
    return render_template('logs.html', title='Logging', status=device.status(), history=history,
                           filters=filters, error=error, windows=activity.WINDOWS, levels=activity.LEVELS,
                           page_args=page_args)


@app.get('/network')
def network():
    return render_template('network.html', title='Network', status=device.status(), aps=None)


def helper(action, payload):
    result = subprocess.run(['sudo', '-n', '/usr/local/libexec/flexclock/web_network.py', action],
                            input=json.dumps(payload), text=True, capture_output=True, timeout=50)
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'Network operation failed. Check the device logs.')
    return json.loads(result.stdout)


@app.get('/wifi/scan')
def wifi_scan():
    aps = []
    try:
        aps = helper('scan', {})
        if not aps:
            flash('Scan completed; no named networks found. You can enter a hidden SSID manually.', 'ok')
    except (ValueError, OSError, subprocess.TimeoutExpired) as e:
        flash(str(e), 'error')
    return render_template('network.html', title='Network', status=device.status(), aps=aps)


def network_payload(form):
    mode = form.get('mode')
    if mode not in ('dhcp', 'static'):
        raise ValueError('Select DHCP or static.')
    data = dict(mode=mode)
    if mode == 'static':
        address = ipaddress.IPv4Interface(f"{form.get('ip', '')}/{form.get('cidr', '')}")
        gateway = ipaddress.IPv4Address(form.get('gw', ''))
        if gateway not in address.network or address.ip in (address.network.network_address, address.network.broadcast_address):
            raise ValueError('Use a host IP and a gateway in the same subnet.')
        dns = form.get('dns', '').replace(',', ' ').split()
        if not dns:
            raise ValueError('Provide at least one DNS server for static configuration.')
        data.update(address=str(address), gateway=str(gateway), dns=[str(ipaddress.IPv4Address(d)) for d in dns])
    return data


@app.post('/network/apply')
def network_apply():
    try:
        data = network_payload(request.form)
        if request.form.get('confirm') != 'yes':
            raise ValueError('Confirm the Ethernet connectivity change before applying.')
        result = helper('ethernet', data)
        flash(result['message'], 'ok')
    except (ValueError, OSError, subprocess.TimeoutExpired) as e:
        flash(str(e), 'error')
    return redirect(url_for('network'))


@app.post('/wifi/apply')
def wifi_apply():
    try:
        if request.form.get('confirm') != 'yes':
            raise ValueError('Review and confirm the Wi-Fi operation first.')
        result = helper('wifi', dict(ssid=request.form.get('ssid', ''), psk=request.form.get('psk', ''),
                                    security=request.form.get('security'), disconnect=request.form.get('disconnect') == 'yes'))
        flash(result['message'], 'ok')
    except (ValueError, OSError, subprocess.TimeoutExpired) as e:
        flash(str(e), 'error')
    return redirect(url_for('network'))


@app.post('/logo/upload')
def logo_upload():
    try:
        upload = request.files.get('logo')
        if not upload or not upload.filename:
            raise ValueError('Choose an image.')
        raw = upload.read()
        with Image.open(io.BytesIO(raw)) as img:
            if img.format not in ('PNG', 'JPEG', 'GIF') or img.width * img.height > 4_000_000:
                raise ValueError('Use a PNG, JPEG or GIF up to 4 million pixels.')
            img.verify()
        with Image.open(io.BytesIO(raw)) as img:
            output = io.BytesIO()
            img.convert('RGBA').save(output, format='PNG')
        tmp = LOGO_CUSTOM.with_suffix('.tmp')
        tmp.write_bytes(output.getvalue())
        os.replace(tmp, LOGO_CUSTOM)
        flash('Customer logo validated and saved as PNG. This does not change the live display.', 'ok')
    except (ValueError, OSError, UnidentifiedImageError, Image.DecompressionBombError):
        flash('Invalid image. Use a PNG, JPEG or GIF under 4 MB and 4 million pixels.', 'error')
    return redirect(url_for('display'))


@app.post('/logo/remove')
def logo_remove():
    LOGO_CUSTOM.unlink(missing_ok=True)
    flash('Customer logo removed. Default logo preserved.', 'ok')
    return redirect(url_for('display'))


@app.get('/customer_logo.png')
def customer_logo():
    if not LOGO_CUSTOM.exists():
        abort(404)
    return send_file(LOGO_CUSTOM, mimetype='image/png')


@app.get('/default_logo.png')
def default_logo():
    return send_file(LOGO_DEFAULT, mimetype='image/png')


@app.post('/auth/change')
def auth_change():
    conf = load_conf()
    current, new = request.form.get('current', ''), request.form.get('new1', '')
    if not check_password_hash(conf['auth']['password_hash'], current):
        flash('Current password incorrect.', 'error')
    elif len(new) < 5 or len(new) > 128 or new != request.form.get('new2'):
        flash('New passwords must match and contain 5–128 characters.', 'error')
    else:
        conf['auth']['password_hash'] = generate_password_hash(new)
        save_conf(conf)
        session.clear()
        flash('Password updated. Sign in again.', 'ok')
        return redirect(url_for('login'))
    return redirect(url_for('settings'))


def hostname_operation(name):
    result = subprocess.run(['sudo', '-n', '/usr/local/libexec/flexclock/web_hostname.py'],
                            input=json.dumps({'hostname': name, 'confirm': True}), text=True,
                            capture_output=True, timeout=25)
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'The device name could not be saved.')
    return json.loads(result.stdout)


@app.post('/settings/hostname')
def hostname_save():
    name = request.form.get('hostname', '').strip().lower()
    try:
        if not device.valid_hostname(name):
            raise ValueError('Use letters, numbers and hyphens, with a letter or number at each end (up to 63 characters).')
        if request.form.get('confirm') != 'yes':
            raise ValueError('Confirm the device name change before saving.')
        result = hostname_operation(name)
        flash(result['message'], 'ok')
    except (ValueError, OSError, subprocess.TimeoutExpired) as e:
        flash(str(e) if isinstance(e, ValueError) else 'The device name service did not respond. Refresh Settings and try again.', 'error')
    return redirect(url_for('settings'))


@app.get('/health')
def health():
    return {'status': 'ok'}


@app.errorhandler(400)
@app.errorhandler(413)
def bad_request(error):
    return render_template('error.html', title='Request could not be completed', message=error.description), error.code


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(load_conf().get('web_port', 8000)))
