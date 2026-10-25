"""Read-only device observations. Missing tools are unknown, never healthy."""
import json
import socket
import subprocess
from pathlib import Path


def run(args, timeout=4):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def stack():
    if run(['systemctl', 'is-active', 'NetworkManager']) == 'active':
        return 'NetworkManager'
    if run(['systemctl', 'is-active', 'dhcpcd']) == 'active':
        return 'dhcpcd'
    return 'Unknown'


def status():
    try:
        interfaces = json.loads(run(['ip', '-j', 'address']) or '[]')
    except ValueError:
        interfaces = []
    networks = []
    for name in ('eth0', 'wlan0'):
        item = next((i for i in interfaces if i['ifname'] == name), {})
        addresses = [f"{a['local']}/{a['prefixlen']}" for a in item.get('addr_info', [])]
        networks.append(dict(name=name, state=item.get('operstate', 'Unknown'), addresses=addresses))
    try:
        seconds = int(float(Path('/proc/uptime').read_text().split()[0]))
        uptime = f'{seconds // 86400}d {seconds // 3600 % 24}h {seconds // 60 % 60}m'
    except (OSError, ValueError):
        uptime = 'Unknown'
    services = dict.fromkeys(('sign-web', 'sign-ui', 'wpa_supplicant', 'dhcpcd', 'NetworkManager'))
    for s in services:
        services[s] = run(['systemctl', 'show', s, '--property=ActiveState', '--value']) or 'Unknown'
    return dict(hostname=socket.gethostname(), uptime=uptime, networks=networks, services=services,
                stack=stack(), ssid=run(['iwgetid', 'wlan0', '-r']) or 'Not associated / unavailable',
                gateway=run(['ip', 'route', 'show', 'default', 'dev', 'eth0']) or 'Unavailable',
                dns=run(['resolvconf', '-l', 'eth0']) or 'Unavailable',
                receiver=run(['ss', '-H', '-lntu']) or 'Unavailable')
