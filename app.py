#!/usr/bin/env python3
import os, json, secrets, subprocess
from pathlib import Path
from flask import Flask, request, redirect, url_for, render_template, session, flash, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Resolve /home/<user>/sign-controller from repo location
APP_ROOT = Path(__file__).resolve().parents[1]
CONF_PATH = APP_ROOT / "config" / "settings.json"
LOGO_DEFAULT = APP_ROOT / "config" / "Logo-White.png"
LOGO_CUSTOM  = APP_ROOT / "config" / "customer_logo.png"
SCRIPTS_DIR  = APP_ROOT / "scripts"

UPLOAD_ALLOWED = {"png","jpg","jpeg","gif"}

def load_conf():
    with open(CONF_PATH,"r") as f:
        return json.load(f)

def save_conf(conf):
    tmp = CONF_PATH.with_suffix(".tmp")
    with open(tmp,"w") as f:
        json.dump(conf,f,indent=2)
    os.replace(tmp, CONF_PATH)

def is_logged_in():
    return session.get("auth") is True

app = Flask(__name__, static_url_path="/static", static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SC_SECRET", secrets.token_hex(16))

@app.context_processor
def inject_globals():
    return {"custom_logo_exists": LOGO_CUSTOM.exists()}

@app.get("/")
def landing():
    return render_template("landing.html")

@app.route("/login", methods=["GET","POST"])
def login():
    conf = load_conf()
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if u == conf["auth"]["username"] and check_password_hash(conf["auth"]["password_hash"], p):
            session["auth"] = True
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.","error")
    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))

@app.get("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    conf = load_conf()
    return render_template("dashboard.html", conf=conf)

# ----- Ethernet network -----
@app.post("/network/apply")
def network_apply():
    if not is_logged_in():
        return redirect(url_for("login"))
    mode = request.form.get("mode","dhcp")
    ip   = request.form.get("ip","")
    mask = request.form.get("mask","")
    gw   = request.form.get("gw","")
    payload = json.dumps({"mode": mode, "ip": ip, "mask": mask, "gw": gw})
    try:
        subprocess.run(
            ["sudo", str(SCRIPTS_DIR/"apply_network.sh")],
            input=payload.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        flash("Network settings applied. dhcpcd restarting…","ok")
    except subprocess.CalledProcessError as e:
        flash((e.stderr or e.stdout).decode() or "Apply failed","error")
    return redirect(url_for("dashboard"))

# ----- Wi-Fi scan/join -----
@app.get("/wifi/scan")
def wifi_scan():
    if not is_logged_in():
        return redirect(url_for("login"))
    try:
        out = subprocess.check_output(["sudo", str(SCRIPTS_DIR/"wifi_scan.sh")], stderr=subprocess.STDOUT, timeout=20)
        aps = json.loads(out.decode() or "[]")
    except Exception as e:
        aps = []
        flash(f"Wi-Fi scan failed: {e}", "error")
    return render_template("wifi.html", aps=aps)

@app.post("/wifi/apply")
def wifi_apply():
    if not is_logged_in():
        return redirect(url_for("login"))
    ssid = request.form.get("ssid","")
    psk  = request.form.get("psk","")
    payload = json.dumps({"ssid": ssid, "psk": psk})
    try:
        subprocess.run(
            ["sudo", str(SCRIPTS_DIR/"apply_wifi.sh")],
            input=payload.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        flash("Wi-Fi settings applied. Reconfiguring…","ok")
    except subprocess.CalledProcessError as e:
        flash((e.stderr or e.stdout).decode() or "Wi-Fi apply failed","error")
    return redirect(url_for("wifi_scan"))

# ----- Customer logo upload -----
def allowed_file(fn:str) -> bool:
    return "." in fn and fn.rsplit(".",1)[1].lower() in UPLOAD_ALLOWED

@app.post("/logo/upload")
def logo_upload():
    if not is_logged_in():
        return redirect(url_for("login"))
    f = request.files.get("logo")
    if not f or f.filename == "":
        flash("No file selected.","error"); return redirect(url_for("dashboard"))
    if not allowed_file(f.filename):
        flash("Unsupported file type.","error"); return redirect(url_for("dashboard"))
    f.save(LOGO_CUSTOM)
    flash("Customer logo uploaded.","ok")
    return redirect(url_for("dashboard"))

# ----- Change admin password -----
@app.post("/auth/change")
def auth_change():
    if not is_logged_in():
        return redirect(url_for("login"))
    current = request.form.get("current","")
    new1 = request.form.get("new1","")
    new2 = request.form.get("new2","")
    conf = load_conf()
    if not check_password_hash(conf["auth"]["password_hash"], current):
        flash("Current password incorrect.","error"); return redirect(url_for("dashboard"))
    if not new1 or new1 != new2:
        flash("New passwords do not match.","error"); return redirect(url_for("dashboard"))
    conf["auth"]["password_hash"] = generate_password_hash(new1)
    save_conf(conf)
    flash("Password updated.","ok")
    return redirect(url_for("dashboard"))

@app.get("/customer_logo.png")
def customer_logo():
    if LOGO_CUSTOM.exists():
        return send_from_directory(LOGO_CUSTOM.parent, LOGO_CUSTOM.name)
    return "", 404

@app.get("/health")
def health():
    return {"status":"ok"}

if __name__ == "__main__":
    try:
        with open(CONF_PATH) as f:
            port = int(json.load(f).get("web_port", 8000))
    except Exception:
        port = 8000
    app.run(host="0.0.0.0", port=port)
