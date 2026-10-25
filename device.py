"""Bounded read-only device observations and plain-language status mappings."""
import json
import re
import socket
import subprocess
from pathlib import Path

SERVICE_LABELS = {'sign-web': 'Web Dashboard', 'sign-ui': 'LED Display Controller',
                  'wpa_supplicant': 'Wi-Fi Service', 'dhcpcd': 'Network Service',
                  'NetworkManager': 'Network Manager'}


def run(args, timeout=4):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def valid_hostname(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value) is not None


def stack():
    if run(['systemctl', 'is-active', 'NetworkManager']) == 'active':
        return 'NetworkManager'
    if run(['systemctl', 'is-active', 'dhcpcd']) == 'active':
        return 'dhcpcd'
    return 'Unknown'


def service_status(active, sub='', restarts=0):
    if sub == 'auto-restart' or active == 'activating' and restarts > 0:
        return dict(label='Restarting', tone='danger', note=f'{restarts} automatic restarts recorded. The service needs attention.')
    if active == 'activating':
        return dict(label='Starting', tone='warning', note='The service has not finished starting.')
    if active == 'failed':
        return dict(label='Failed', tone='danger', note='The service could not run. Check its logs.')
    if active == 'active':
        return dict(label='Running' if sub == 'running' else 'Active', tone='success',
                    note=f'{restarts} automatic restarts recorded. Check the logs if this keeps increasing.' if restarts else '')
    if active in ('inactive', 'deactivating'):
        return dict(label='Stopped' if active == 'inactive' else 'Stopping', tone='neutral' if active == 'inactive' else 'warning', note='')
    return dict(label='Unavailable', tone='neutral', note='Service status could not be read.')


def network_status(state, ipv4, ssid=None):
    if state == 'UP' and ipv4:
        return dict(label='Connected', tone='success')
    if state == 'ERROR':
        return dict(label='Error', tone='danger')
    if state in ('DOWN', 'LOWERLAYERDOWN', 'NOTPRESENT'):
        return dict(label='Disconnected', tone='danger')
    if state == 'UP' or ssid:
        return dict(label='Connecting', tone='warning')
    return dict(label='Unavailable', tone='neutral')


def status():
    try:
        interfaces = json.loads(run(['ip', '-j', 'address']) or '[]')
    except ValueError:
        interfaces = []
    ssid = run(['iwgetid', 'wlan0', '-r']) or ''
    networks = []
    for name in ('eth0', 'wlan0'):
        item = next((i for i in interfaces if i['ifname'] == name), {})
        addresses = [f"{a['local']}/{a['prefixlen']}" for a in item.get('addr_info', [])]
        ipv4 = [a['local'] for a in item.get('addr_info', []) if a['family'] == 'inet']
        state = item.get('operstate', 'Unknown')
        networks.append(dict(name=name, state=state, addresses=addresses, ipv4=ipv4,
                             badge=network_status(state, ipv4, ssid if name == 'wlan0' else None)))
    try:
        seconds = int(float(Path('/proc/uptime').read_text().split()[0]))
        uptime = f'{seconds // 86400}d {seconds // 3600 % 24}h {seconds // 60 % 60}m'
    except (OSError, ValueError):
        uptime = 'Unknown'
    services = {}
    for name, label in SERVICE_LABELS.items():
        raw = run(['systemctl', 'show', name, '--property=ActiveState,SubState,NRestarts,Result']) or ''
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        restarts = int(values.get('NRestarts', '0')) if values.get('NRestarts', '0').isdigit() else 0
        services[name] = dict(name=name, title=label, active=values.get('ActiveState', 'unknown'),
                              sub=values.get('SubState', 'unknown'), restarts=restarts,
                              **service_status(values.get('ActiveState'), values.get('SubState'), restarts))
    return dict(hostname=socket.gethostname(), uptime=uptime, networks=networks, services=services,
                stack=stack(), ssid=ssid, gateway=run(['ip', 'route', 'show', 'default', 'dev', 'eth0']) or 'Unavailable',
                dns=run(['resolvconf', '-l', 'eth0']) or 'Unavailable')
