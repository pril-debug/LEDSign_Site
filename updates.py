"""Read-only update status and release discovery; installation is a separate service."""
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import urllib.request

STATE = Path('/var/lib/flexclock-updates')
CACHE = Path(__file__).resolve().parents[1]/'config/update-releases.json'
API = 'https://api.github.com/repos/pril-debug/LEDSign/releases?per_page=50'
TAG = re.compile(r'v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?\Z')


def read(path, fallback):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return fallback


def newer(candidate, installed):
    def parts(value):
        match = TAG.fullmatch(value)
        if not match:
            return None
        numbers = re.match(r'^v?(\d+)\.(\d+)(?:\.(\d+))?', value).groups()
        return tuple(int(number or 0) for number in numbers)
    remote, local = parts(candidate), parts(installed)
    return bool(remote and (local is None or remote > local))


def snapshot():
    installed = read(STATE/'installed.json', {})
    status = read(STATE/'status.json', dict(phase='idle', message='Ready.'))
    cached = read(CACHE, {})
    releases = cached.get('releases', [])
    version = installed.get('version', 'Not configured')
    return dict(checked=bool(cached), checked_at=cached.get('checked_at'), configured=bool(installed), installed=version,
                previous=installed.get('previous_version'), status=status,
                busy=status.get('phase') in ('queued', 'downloading', 'validating', 'preparing', 'installing', 'restarting', 'verifying', 'restoring'),
                releases=releases, latest=releases[0] if releases else None,
                available=bool(releases and newer(releases[0]['version'], version)),
                history=list(reversed(read(STATE/'history.json', []))))


def check():
    request = urllib.request.Request(API, headers={'Accept':'application/vnd.github+json', 'User-Agent':'FlexClock-Dashboard'})
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(2*1024*1024+1)
    if len(raw) > 2*1024*1024:
        raise ValueError('Release information is too large.')
    releases = []
    for item in json.loads(raw):
        tag = item.get('tag_name', '')
        if not TAG.fullmatch(tag) or item.get('draft') or item.get('prerelease'):
            continue
        asset = next((a for a in item.get('assets', []) if a.get('name') == 'ledsign-release.tar.gz'), {})
        releases.append(dict(version=tag, notes=(item.get('body') or '')[:30000],
                             installable=bool(re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or ''))))
    releases.sort(key=lambda item: tuple(int(number or 0) for number in re.match(r'v?(\d+)\.(\d+)(?:\.(\d+))?', item['version']).groups()), reverse=True)
    tmp = CACHE.with_suffix('.tmp')
    tmp.write_text(json.dumps(dict(releases=releases, checked_at=datetime.now(timezone.utc).isoformat())))
    tmp.replace(CACHE)
    return snapshot()



def connection():
    checked_at = datetime.now(timezone.utc).isoformat()
    request = urllib.request.Request('https://github.com/pril-debug/LEDSign/releases',
                                     method='HEAD', headers={'User-Agent':'FlexClock-Dashboard'})
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            connected = 200 <= response.status < 400
    except (OSError, ValueError):
        connected = False
    return dict(connected=connected, checked_at=checked_at,
                message='Update service connected.' if connected else
                'Cannot reach the update service. Check the clock’s internet connection and try again.')


def start(action, version):
    result = subprocess.run(['sudo', '-n', '/usr/local/libexec/flexclock/software_updates.py'],
                            input=json.dumps(dict(action=action, version=version)),
                            text=True, capture_output=True, timeout=15)
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = {}
    if result.returncode or not data.get('ok'):
        known = ('An update is already in progress.', 'No previous version is available.', 'Choose a versioned release.')
        raise ValueError(data.get('message') if data.get('message') in known else 'The software operation could not start.')
    return data
