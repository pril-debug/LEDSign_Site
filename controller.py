"""Bounded local connection to the running LED controller."""
import json
from pathlib import Path
import re
import socket

MODES = ('Count Up', 'Count Down', 'Lap Counter', 'Round Counter', 'FinishLynx')
SOCKET_PATH = Path(__file__).resolve().parents[1] / 'config/controller.sock'


def select_mode(mode, value=None):
    return command('set_time' if value is not None else 'select', mode, value=value)


def command(action, mode, value=None, number=None):
    if mode not in MODES:
        raise ValueError('Select a mode.')
    if action not in ('select', 'set_time', 'start', 'pause', 'lap_plus', 'lap_minus', 'lap_set'):
        raise ValueError('Choose a clock control.')
    body = dict(action=action, mode=mode)
    if action == 'set_time':
        if mode not in (MODES[0], MODES[1], MODES[3]):
            raise ValueError('This mode does not use a start time.')
        if not isinstance(value, str) or not re.fullmatch(r'[0-9]{2}:[0-5][0-9]:[0-5][0-9]', value):
            raise ValueError('Enter a time as HH:MM:SS.')
        if mode == MODES[3] and value == '00:00:00':
            raise ValueError('Set a round time greater than zero.')
        body['time'] = value
    if action in ('start', 'pause') and mode not in (MODES[0], MODES[1], MODES[3]):
        raise ValueError('Select a timer mode first.')
    if action.startswith('lap_') and mode != 'Lap Counter':
        raise ValueError('Select Lap Counter first.')
    if action == 'lap_set':
        if not isinstance(number, str) or not re.fullmatch(r'[0-9]{1,6}', number):
            raise ValueError('Enter a lap number from 0 to 999999.')
        body['number'] = int(number)
    return exchange(body)


def status():
    try:
        return exchange(dict(action='status'), status=True)
    except RuntimeError:
        return dict(connected=False, mode=None, phase='unavailable', frame=None, value=None, revision=0)


def exchange(command, status=False):
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(SOCKET_PATH))
            connection.sendall(json.dumps(command).encode() + b'\n')
            data = bytearray()
            while b'\n' not in data and len(data) <= 512*1024:
                part = connection.recv(8192)
                if not part:
                    break
                data.extend(part)
            reply = json.loads(data)
    except (OSError, ValueError):
        raise RuntimeError('The clock did not respond. Check the display before trying again.') from None
    if not isinstance(reply, dict):
        raise RuntimeError('The clock response was unavailable.')
    if not status and reply.get('ok') is not True:
        raise RuntimeError(reply.get('message', 'The clock could not complete the change.'))
    return reply
