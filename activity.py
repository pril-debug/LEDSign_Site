"""Read-only service history with bounded queries and plain-language events."""
from datetime import datetime, timezone
import json
import subprocess
from device import SERVICE_LABELS

WINDOWS = {'hour': ('Last hour', '-1h'), 'day': ('Last 24 hours', '-24h'), 'week': ('Last 7 days', '-7d')}
LEVELS = {'all': 'All activity', 'error': 'Errors', 'warning': 'Warnings', 'info': 'Updates'}


def describe(message, priority):
    """Never put raw diagnostics, tracebacks or credentials into user-facing history."""
    text = message.lower()
    patterns = [
        (('address already in use', 'port 8000 is in use'), 'Unable to start: another program is using the same connection.', 'error'),
        (('scheduled restart', 'restart counter'), 'An automatic restart was scheduled.', 'warning'),
        (('failed with result', 'main process exited', 'failed to start'), 'The service stopped because of an error.', 'error'),
        (('permission denied', 'access denied', 'not authorized'), 'The service could not access something it needs.', 'error'),
        (('wrong_key', 'pre-shared key may be incorrect', 'incorrect password'), 'The Wi-Fi password was not accepted.', 'error'),
        (('ctrl-event-connected',), 'Wi-Fi connected.', 'info'),
        (('ctrl-event-disconnected',), 'Wi-Fi disconnected.', 'warning'),
        (('no lease', 'dhcp timeout', 'timed out'), 'A connection or response took too long.', 'warning'),
        (('leased ', 'bound to ', 'dhcp lease acquired'), 'A network address was assigned.', 'info'),
        (('no carrier', 'carrier lost', 'link is down'), 'A network connection was lost.', 'warning'),
        (('carrier acquired', 'link is up'), 'A network connection became available.', 'info'),
        (('serving on', 'listening on'), 'The service is ready to accept connections.', 'info'),
        (('starting ',), 'The service is starting.', 'info'),
        (('started ',), 'The service started.', 'info'),
        (('stopping ',), 'The service is stopping.', 'info'),
        (('stopped ', 'deactivated successfully'), 'The service stopped.', 'info'),
        (('traceback', 'exception', 'error:'), 'An internal error was reported.', 'error'),
    ]
    for needles, description, kind in patterns:
        if any(needle in text for needle in needles):
            return description, kind
    try:
        number = int(priority)
    except (ValueError, TypeError):
        number = 6
    if number <= 3:
        return 'The service reported an error.', 'error'
    if number == 4:
        return 'The service reported a warning.', 'warning'
    return 'Service activity was recorded.', 'info'


def read_history(service='all', window='day', query='', level='all', page=1):
    if service != 'all' and service not in SERVICE_LABELS:
        raise ValueError('Choose a service from the list.')
    if window not in WINDOWS or level not in LEVELS or len(query) > 120:
        raise ValueError('Check the search filters and try again.')
    selected = list(SERVICE_LABELS) if service == 'all' else [service]
    command = ['journalctl', '--no-pager', '--quiet', '--output=json', '--lines=1000', '--since=' + WINDOWS[window][1]]
    command += ['--unit=' + name + '.service' for name in selected]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Activity could not be loaded. Try again.')
    if result.returncode or 'permission' in result.stderr.lower():
        raise ValueError('Activity is unavailable. The dashboard needs permission to read service history.')
    events = []
    scanned = 0
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                continue
            # Unit= is used for service lifecycle events emitted by systemd itself.
            unit = record.get('UNIT') or record.get('_SYSTEMD_UNIT', '')
            name = unit.removesuffix('.service')
            if name not in selected:
                continue
            stamp = datetime.fromtimestamp(int(record['__REALTIME_TIMESTAMP']) / 1_000_000, timezone.utc)
            message = record.get('MESSAGE', '')
            if not isinstance(message, str):
                message = ''
            description, kind = describe(message, record.get('PRIORITY'))
            scanned += 1
            event = dict(time=stamp.isoformat(), display_time=stamp.strftime('%b %d, %Y · %H:%M:%S UTC'),
                         service=SERVICE_LABELS[name], message=description, kind=kind,
                         label={'error':'Error', 'warning':'Warning', 'info':'Update'}[kind],
                         tone={'error':'danger', 'warning':'warning', 'info':'info'}[kind])
            if level != 'all' and kind != level:
                continue
            if query.casefold() not in (' '.join([event['service'], description, event['label']])).casefold():
                continue
            events.append(event)
        except (ValueError, KeyError, TypeError, OverflowError, OSError):
            continue
    events.sort(key=lambda e: e['time'], reverse=True)
    total = len(events)
    pages = max(1, (total + 49) // 50)
    page = min(max(1, page), pages)
    return dict(events=events[(page-1)*50:page*50], total=total, scanned=scanned,
                limited=len(result.stdout.splitlines()) >= 1000, page=page, pages=pages)
