import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from PIL import Image
from werkzeug.security import generate_password_hash
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as web
import device
import importlib.util
spec = importlib.util.spec_from_file_location('network_helper', Path(__file__).resolve().parents[2] / 'scripts/web_network.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class Website(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = root / 'settings.json'
        self.config.write_text(json.dumps({'auth': {'username': 'admin', 'password_hash': generate_password_hash('original-password')}, 'led_rows': 64, 'other_device_setting': 42}))
        self.patches = [patch.object(web, 'CONF_PATH', self.config), patch.object(web, 'LOGO_CUSTOM', root / 'customer.png'), patch.object(web, 'LOGO_DEFAULT', root / 'default.png')]
        for p in self.patches: p.start()
        Image.new('RGB', (8, 8)).save(root / 'default.png')
        web.app.config['TESTING'] = True
        self.client = web.app.test_client()

    def tearDown(self):
        for p in self.patches: p.stop()
        self.temp.cleanup()

    def csrf(self):
        self.client.get('/login')
        with self.client.session_transaction() as sess: return sess['csrf']

    def post(self, path, data=None):
        data = dict(data or {})
        data['csrf'] = self.csrf()
        return self.client.post(path, data=data)

    def login(self):
        return self.post('/login', dict(username='admin', password='original-password'))

    def test_public_and_protected_routes(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        for route in ['/dashboard', '/display', '/network', '/settings', '/wifi/scan', '/customer_logo.png', '/default_logo.png']:
            self.assertEqual(self.client.get(route).status_code, 302)
        self.assertNotIn(b'192.168', self.client.get('/').data)

    def test_login_logout_csrf(self):
        self.assertEqual(self.client.post('/login', data={}).status_code, 400)
        self.assertIn(b'Invalid username', self.post('/login', dict(username='admin', password='wrong')).data)
        self.assertEqual(self.login().location, '/dashboard')
        self.assertEqual(self.post('/logout').location, '/')
        self.assertEqual(self.client.get('/settings').status_code, 302)

    def test_pages_and_unknown_status(self):
        self.login()
        for path in ['/dashboard', '/network', '/settings']:
            self.assertEqual(self.client.get(path).status_code, 200)
        self.assertIn(b'Clock Control', self.client.get('/dashboard').data)

    def test_dashboard_mode_controls(self):
        for path in ('/api/controller/status', '/finishlynx'):
            self.assertEqual(self.client.get(path).status_code, 302)
        self.assertEqual(self.client.post('/api/controller/mode').status_code, 302)
        self.login()
        self.assertEqual(self.client.post('/api/controller/mode', data={'mode': 'Count Up'}).status_code, 400)
        for action, mode, extra in [('set_time', 'Count Down', {'time':'00:12:36'}),
                                    ('start', 'Count Down', {}), ('select', 'Round Counter', {}),
                                    ('lap_set', 'Lap Counter', {'number':'42'})]:
            with patch.object(web.controller, 'command', return_value={'ok': True, 'message': 'Confirmed.'}) as send:
                response = self.post('/api/controller/mode', dict(action=action, mode=mode, **extra))
                self.assertEqual(response.status_code, 200)
                send.assert_called_once_with(action, mode, value=extra.get('time'), number=extra.get('number'))
        for error, status in [(ValueError('Select a mode.'), 400), (RuntimeError('Clock unavailable.'), 503)]:
            with patch.object(web.controller, 'command', side_effect=error):
                response = self.post('/api/controller/mode', {'action': 'select', 'mode': 'Count Up'})
                self.assertEqual(response.status_code, status)
                self.assertFalse(response.json['ok'])
        page = self.client.get('/dashboard').data
        self.assertIn(b'On the clock', page)
        self.assertNotIn(b'<select', page)
        self.assertNotIn(b'href="/updates"', page)
        self.assertNotIn(b'href="/logs"', page)
        self.assertIn(b'href="/finishlynx"', page)
        self.assertNotIn(b'Keyboard controls on the clock remain available.', page)
        settings = self.client.get('/settings').data
        self.assertIn(b'Manage software updates', settings)
        self.assertIn(b'View all activity', settings)
        finishlynx = self.client.get('/finishlynx')
        self.assertEqual(finishlynx.status_code, 200)
        self.assertIn(b'Use FinishLynx mode', finishlynx.data)
        self.assertIn(b'Download FlexClock.lss', finishlynx.data)
        self.assertIn(b'Results Auto', finishlynx.data)
        with patch.object(web.controller, 'status', return_value={'connected':False, 'frame':None}):
            self.assertFalse(self.client.get('/api/controller/status').json['connected'])

    def test_password_validation_persistence_and_sessions(self):
        self.login()
        old_session = dict()
        with self.client.session_transaction() as s: old_session.update(s)
        self.post('/auth/change', dict(current='wrong', new1='new-password-long', new2='new-password-long'))
        self.assertEqual(self.client.get('/settings').status_code, 200)
        self.post('/auth/change', dict(current='original-password', new1='four', new2='four'))
        self.assertEqual(self.post('/auth/change', dict(current='original-password', new1='new-password-long', new2='new-password-long')).location, '/login')
        self.assertEqual(json.loads(self.config.read_text())['other_device_setting'], 42)
        with self.client.session_transaction() as s: s.update(old_session)
        self.assertEqual(self.client.get('/settings').status_code, 302)
        self.assertEqual(self.post('/login', dict(username='admin', password='new-password-long')).location, '/dashboard')

    def test_logo_validation_conversion_remove(self):
        self.login()
        self.post('/logo/upload', {'logo': (io.BytesIO(b'fake'), 'fake.png')})
        self.assertFalse(web.LOGO_CUSTOM.exists())
        buf = io.BytesIO()
        Image.new('RGB', (16, 16)).save(buf, format='JPEG')
        response = self.post('/logo/upload', {'logo': (io.BytesIO(buf.getvalue()), 'actual.jpg')})
        self.assertEqual(response.location, '/settings')
        with Image.open(web.LOGO_CUSTOM) as image:
            self.assertEqual(image.format, 'PNG')
        response = self.client.get('/customer_logo.png')
        self.assertEqual(response.status_code, 200)
        response.close()
        self.assertEqual(self.post('/logo/remove').location, '/settings')
        self.assertFalse(web.LOGO_CUSTOM.exists())
        self.assertTrue(web.LOGO_DEFAULT.exists())

    def test_ethernet_requires_validation_and_confirmation(self):
        self.login()
        with patch.object(web, 'helper') as operation:
            self.post('/network/apply', dict(mode='static', ip='bad', cidr='24', gw='192.168.0.1', dns='1.1.1.1', confirm='yes'))
            self.post('/network/apply', dict(mode='dhcp'))
            operation.assert_not_called()
            operation.return_value = {'message': 'rebind requested'}
            self.post('/network/apply', dict(mode='static', ip='192.168.0.50', cidr='24', gw='192.168.0.1', dns='1.1.1.1', confirm='yes'))
            self.assertEqual(operation.call_args.args[0], 'ethernet')

    def test_scan_error_and_escaped_ssid(self):
        self.login()
        with patch.object(web, 'helper', side_effect=ValueError('socket unavailable')):
            self.assertIn(b'socket unavailable', self.client.get('/wifi/scan').data)
        with patch.object(web, 'helper', return_value=[dict(ssid='<script>bad</script>', signal=-50, freq=5180, security='Secured')]):
            page = self.client.get('/wifi/scan').data
            self.assertIn(b'&lt;script&gt;', page)
            self.assertNotIn(b'<script>bad', page)

    def test_wifi_failure_and_confirmation(self):
        self.login()
        with patch.object(web, 'helper', side_effect=ValueError('association timed out')) as operation:
            self.post('/wifi/apply', dict(ssid='test'))
            operation.assert_not_called()
            self.post('/wifi/apply', dict(ssid='test', confirm='yes'))
            self.assertIn(b'association timed out', self.client.get('/network').data)

    def test_five_character_password_accepted_and_session_invalidated(self):
        self.login()
        response = self.post('/auth/change', dict(current='original-password', new1='abcde', new2='abcde'))
        self.assertEqual(response.location, '/login')
        self.assertEqual(self.client.get('/settings').status_code, 302)
        self.assertEqual(self.post('/login', dict(username='admin', password='abcde')).location, '/dashboard')

    def test_short_and_mismatched_passwords_rejected(self):
        self.login()
        original = self.config.read_bytes()
        for new, confirmation in [('1234', '1234'), ('abcde', 'other'), ('', '')]:
            self.post('/auth/change', dict(current='original-password', new1=new, new2=confirmation))
            self.assertEqual(self.config.read_bytes(), original)
        page = self.client.get('/settings').data
        self.assertIn(b'minlength="5"', page)
        self.assertIn(b'At least 5 characters', page)

    def test_hostname_requires_authentication_csrf_and_confirmation(self):
        with patch.object(web, 'hostname_operation') as operation:
            self.assertEqual(self.client.post('/settings/hostname', data={'hostname': 'race-clock', 'confirm': 'yes'}).status_code, 302)
            self.login()
            self.assertEqual(self.client.post('/settings/hostname', data={'hostname': 'race-clock', 'confirm': 'yes'}).status_code, 400)
            self.post('/settings/hostname', {'hostname': 'race-clock'})
            operation.assert_not_called()
            self.assertIn(b'Confirm the device name change', self.client.get('/settings').data)

    def test_hostname_success_and_backend_failure(self):
        self.login()
        with patch.object(web, 'hostname_operation', return_value={'message': 'Device name saved.'}) as operation:
            self.post('/settings/hostname', {'hostname': 'race-clock', 'confirm': 'yes'})
            operation.assert_called_once_with('race-clock')
            self.assertIn(b'Device name saved.', self.client.get('/settings').data)
        with patch.object(web, 'hostname_operation', side_effect=ValueError('Hostname service failed')):
            self.post('/settings/hostname', {'hostname': 'race-clock', 'confirm': 'yes'})
            self.assertIn(b'Hostname service failed', self.client.get('/settings').data)

    def test_hostname_rejects_invalid_input_without_operation(self):
        self.login()
        with patch.object(web, 'hostname_operation') as operation:
            for name in ['bad;reboot', '-invalid', 'end-', 'two words', 'x'*64, 'a.b', '']:
                self.post('/settings/hostname', {'hostname': name, 'confirm': 'yes'})
            operation.assert_not_called()

    def test_mixed_case_hostname_normalized_before_save(self):
        self.login()
        with patch.object(web, 'hostname_operation', return_value={'message':'Device name saved.'}) as operation:
            response = self.post('/settings/hostname', {'hostname':' FlexClock1 ', 'confirm':'yes'})
            self.assertEqual(response.location, '/settings')
            operation.assert_called_once_with('flexclock1')
        page = self.client.get('/settings').data
        self.assertIn(b'pattern="[A-Za-z0-9]', page)
        self.assertIn(b'id="confirmation-modal"', page)
        self.assertNotIn(b'type="checkbox" name="confirm"', page)

    def test_hostname_helper_uses_stdin_and_reports_errors(self):
        import subprocess
        result = subprocess.CompletedProcess([], 0, '{"message":"saved"}', '')
        with patch.object(web.subprocess, 'run', return_value=result) as operation:
            self.assertEqual(web.hostname_operation('clock')['message'], 'saved')
            self.assertEqual(operation.call_args.args[0], ['sudo', '-n', '/usr/local/libexec/flexclock/web_hostname.py'])
            self.assertEqual(json.loads(operation.call_args.kwargs['input']), {'hostname':'clock', 'confirm':True})
        with patch.object(web.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'Save failed')):
            with self.assertRaises(ValueError): web.hostname_operation('clock')

    def test_dashboard_statuses_and_ipv4_only(self):
        self.login()
        observations = device.status()
        observations['networks'][0].update(ipv4=['192.0.2.4'], addresses=['192.0.2.4/24', '2001:db8::abcd/64'], badge=device.network_status('UP', ['192.0.2.4']))
        observations['services']['sign-ui'].update(device.service_status('activating', 'auto-restart', 25))
        with patch.object(web.device, 'status', return_value=observations):
            page = self.client.get('/dashboard').data
        self.assertIn(b'Restarting', page)
        self.assertNotIn(b'25 automatic restarts', page)
        self.assertIn(b'192.0.2.4', page)
        self.assertNotIn(b'2001:db8', page)
        self.assertIn(b'pill success', page)

    def test_branding_and_asset_versions(self):
        page = self.client.get('/').data
        self.assertIn(b'Full-Color LED Race Clock', page)
        for removed in (b'LED Track Sign', b'Illustration', b'Precision at the Track'):
            self.assertNotIn(removed, page)
        self.assertIn(b'style.css?v=', page)
        self.assertIn(b'led-digits', page)



class NetworkHelpers(unittest.TestCase):
    def test_scan_bss_boundaries_and_bands(self):
        text = 'BSS aa\n freq: 2412\n signal: -70.00 dBm\n SSID: one\n RSN:\nBSS bb\n freq: 5180\n signal: -40 dBm\n SSID: two\n'
        aps = helper.parse_scan(text)
        self.assertEqual([a['ssid'] for a in aps], ['two', 'one'])
        self.assertEqual(aps[0]['security'], 'Open')
        self.assertEqual(aps[1]['security'], 'Secured')

    def test_unknown_stack_refuses_changes(self):
        with patch.object(helper, 'active', return_value=False):
            with self.assertRaises(ValueError): helper.require_stack()

    def test_missing_socket_refuses_wifi(self):
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=ValueError('socket unavailable')):
            with self.assertRaises(ValueError): helper.wifi(dict(ssid='test'))

    def test_wifi_success_only_after_completed(self):
        calls = []
        def wpa(*args):
            calls.append(args)
            return {'ping': 'PONG', 'add_network': '2', 'status': 'wpa_state=COMPLETED\nid=2'}.get(args[0], 'OK')
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=wpa), patch.object(helper, 'run', return_value=''), patch.object(helper, 'wifi_events'), patch.object(helper, 'authentication_failed', return_value=False), patch.object(helper, 'wait_address', return_value=None):
            result = helper.wifi(dict(ssid='hidden', psk='password123', security='wpa2'))
        self.assertEqual('Connected, but no IP address was assigned.', result['message'])
        self.assertIn(('save_config',), calls)
        self.assertIn(('set_network', '2', 'scan_ssid', '1'), calls)
        self.assertTrue(all('eth0' not in args for args in calls))

    def test_wifi_failure_rolls_back(self):
        calls = []
        def wpa(*args):
            calls.append(args)
            if args[0] == 'set_network': raise ValueError('rejected')
            return {'ping': 'PONG', 'add_network': '3'}.get(args[0], 'OK')
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=wpa), patch.object(helper, 'wifi_events'), patch.object(helper, 'authentication_failed', return_value=False):
            with self.assertRaises(ValueError): helper.wifi(dict(ssid='test', psk='password123', security='wpa2'))
        self.assertIn(('remove_network', '3'), calls)
        self.assertIn(('reconfigure',), calls)

    def test_ethernet_config_preserves_other_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'dhcpcd.conf'
            original = 'hostname\ninterface wlan0\nmetric 300\n'
            config.write_text(original)
            def mapped(path):
                return root / Path(path).name
            with patch.object(helper, 'require_stack'), patch.object(helper, 'Path', side_effect=mapped), patch.object(helper, 'run', return_value='') as operation, patch.object(helper,'ipv4_addresses',return_value=[]):
                helper.ethernet(dict(mode='static', address='192.168.0.50/24', gateway='192.168.0.1', dns=['1.1.1.1']))
                self.assertIn(original, config.read_text())
                self.assertEqual((root / 'dhcpcd.conf.flexclock-backup').read_text(), original)
                self.assertIn('static ip_address=192.168.0.50/24', config.read_text())
                operation.assert_called_once_with(['dhcpcd', '-n', 'eth0'])
                helper.ethernet(dict(mode='dhcp'))
                self.assertNotIn('static ip_address', config.read_text())
                self.assertEqual(config.read_text().count('# LEDSign eth0 BEGIN'), 1)

    def test_ethernet_rejects_unmanaged_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'dhcpcd.conf'
            config.write_text('interface eth0\nstatic ip_address=10.0.0.1/24\n')
            with patch.object(helper, 'require_stack'), patch.object(helper, 'Path', return_value=config), patch.object(helper, 'run') as operation:
                with self.assertRaises(ValueError): helper.ethernet(dict(mode='dhcp'))
                operation.assert_not_called()

    def test_disconnect_only_targets_wifi(self):
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=['PONG', 'OK', 'OK', 'OK', 'wpa_state=DISCONNECTED']) as operation:
            helper.wifi(dict(disconnect=True))
            self.assertEqual([call.args for call in operation.call_args_list], [('ping',), ('disable_network', 'all'), ('save_config',), ('disconnect',), ('status',)])

    def test_status_failures_unknown(self):
        with patch.object(device, 'run', return_value=None):
            s = device.status()
        self.assertEqual(s['stack'], 'Unknown')
        self.assertEqual(s['networks'][0]['state'], 'Unknown')


class DeviceSettings(unittest.TestCase):
    def test_service_status_mapping(self):
        for active, sub, restarts, label, tone in [
            ('active','running',0,'Running','success'),
            ('activating','start',0,'Starting','warning'),
            ('activating','auto-restart',20,'Restarting','danger'),
            ('failed','failed',1,'Failed','danger'),
            ('inactive','dead',0,'Stopped','neutral'),
            ('unknown','',0,'Unavailable','neutral')]:
            result = device.service_status(active, sub, restarts)
            self.assertEqual((result['label'],result['tone']), (label,tone))
        self.assertIn('10 automatic restarts', device.service_status('active','running',10)['note'])

    def test_network_status_mapping(self):
        for state, ip, ssid, label, tone in [
            ('UP',['192.0.2.1'],None,'Connected','success'),
            ('DOWN',[],None,'Disconnected','danger'),
            ('UP',[],'race-wifi','Connecting','warning'),
            ('Unknown',[],None,'Unavailable','neutral'),
            ('ERROR',[],None,'Error','danger')]:
            result = device.network_status(state, ip, ssid)
            self.assertEqual((result['label'], result['tone']), (label,tone))

    def test_hostname_system_validation_and_operation(self):
        spec = importlib.util.spec_from_file_location('hostname_helper', Path(__file__).resolve().parents[2] / 'scripts/web_hostname.py')
        hostname = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hostname)
        import subprocess
        for value in ['a', 'race-clock', 'a'*63, '123']:
            self.assertTrue(device.valid_hostname(value))
            self.assertEqual(hostname.validate_hostname(value), value)
        for value in ['-bad', 'bad-', 'bad_name', 'bad;id', 'a'*64, '', None, 'é']:
            self.assertFalse(device.valid_hostname(value))
            with self.assertRaises(ValueError): hostname.validate_hostname(value)
        self.assertEqual(hostname.validate_hostname(' FlexClock1 '), 'flexclock1')
        with patch.object(hostname.subprocess, 'run') as operation:
            with self.assertRaises(ValueError): hostname.set_hostname({'hostname': 'race-clock'})
            operation.assert_not_called()
        with patch.object(hostname.subprocess, 'run', side_effect=[subprocess.CompletedProcess([],0,'',''),subprocess.CompletedProcess([],0,'race-clock\n','')]) as operation:
            self.assertIn('saved', hostname.set_hostname({'hostname':'Race-Clock','confirm':True})['message'])
            self.assertEqual(operation.call_args_list[0].args[0], ['/usr/bin/hostnamectl', 'set-hostname', 'race-clock'])
        with patch.object(hostname.subprocess, 'run', return_value=subprocess.CompletedProcess([],1,'','denied')):
            with self.assertRaises(ValueError): hostname.set_hostname({'hostname':'race-clock','confirm':True})
        with patch.object(hostname.subprocess, 'run', side_effect=OSError('missing')):
            with self.assertRaises(ValueError): hostname.set_hostname({'hostname':'race-clock','confirm':True})



class ServiceLogging(unittest.TestCase):
    def setUp(self):
        import activity
        self.activity = activity

    def record(self, message='Started service.', unit='sign-web.service', stamp=1792938000000000, priority='6'):
        return json.dumps(dict(UNIT=unit, MESSAGE=message, __REALTIME_TIMESTAMP=str(stamp), PRIORITY=priority))

    def response(self, lines, code=0, error=''):
        import subprocess
        return subprocess.CompletedProcess([], code, '\n'.join(lines), error)

    def test_plain_language_and_no_diagnostics_or_secrets(self):
        for raw, expected in [('Address already in use','Unable to start'),('Scheduled restart job','automatic restart'),('Traceback secret=abc','internal error')]:
            message, level = self.activity.describe(raw, '6')
            self.assertIn(expected, message)
            self.assertNotIn('secret=', message)
        message, level = self.activity.describe('password=do-not-display /home/admin/private.py', '6')
        self.assertEqual(message, 'Service activity was recorded.')
        self.assertEqual(self.activity.describe('opaque', '3')[1], 'error')
        self.assertEqual(self.activity.describe('opaque', '4')[1], 'warning')

    def test_allowlist_and_filters_reject_without_reading(self):
        with patch.object(self.activity.subprocess, 'run') as operation:
            for args in [dict(service='ssh'),dict(service='sign-web;reboot'),dict(window='anything'),dict(level='invalid'),dict(query='x'*121)]:
                with self.assertRaises(ValueError): self.activity.read_history(**args)
            operation.assert_not_called()

    def test_search_and_service_scoping(self):
        response = self.response([self.record('Address already in use','sign-ui.service'),self.record('Started dashboard.'),self.record('private','ssh.service')])
        with patch.object(self.activity.subprocess,'run',return_value=response) as operation:
            history=self.activity.read_history(service='sign-ui',query='ANOTHER PROGRAM',level='error')
        self.assertEqual(history['total'],1)
        self.assertEqual(history['events'][0]['service'],'LED Display Controller')
        command=operation.call_args.args[0]
        self.assertIn('--unit=sign-ui.service',command)
        self.assertIn('--lines=1000',command)
        self.assertNotIn('ANOTHER PROGRAM',command)
        self.assertEqual(operation.call_args.kwargs['timeout'],8)

    def test_pagination_and_newest_first(self):
        rows=[self.record(stamp=1792938000000000+i*1000000) for i in range(65)]
        with patch.object(self.activity.subprocess,'run',return_value=self.response(rows)):
            first=self.activity.read_history(page=1)
            second=self.activity.read_history(page=2)
        self.assertEqual((len(first['events']),len(second['events'])),(50,15))
        self.assertGreater(first['events'][0]['time'],second['events'][0]['time'])
        self.assertEqual(first['pages'],2)

    def test_history_failures_are_not_empty_success(self):
        import subprocess
        for result in [self.response([],1),self.response([],0,'insufficient permissions')]:
            with patch.object(self.activity.subprocess,'run',return_value=result):
                with self.assertRaises(ValueError):self.activity.read_history()
        for error in [OSError('missing'),subprocess.TimeoutExpired('journalctl',8)]:
            with patch.object(self.activity.subprocess,'run',side_effect=error):
                with self.assertRaises(ValueError):self.activity.read_history()

    def test_malformed_rows_and_real_empty_history(self):
        with patch.object(self.activity.subprocess,'run',return_value=self.response(['bad','[]','{}',self.record(stamp='bad')])):
            self.assertEqual(self.activity.read_history()['total'],0)

    def test_logging_requires_auth_and_settings_have_no_expanders(self):
        client=web.app.test_client()
        self.assertEqual(client.get('/logs').status_code,302)
        # Authentication in this rendering test uses the real hash version, without changing it.
        with client.session_transaction() as session:
            session.update(auth=True,version=web.auth_version())
        with patch.object(web.activity,'read_history',return_value=dict(events=[],total=0,scanned=0,limited=False,page=1,pages=1)):
            page=client.get('/logs').data
            self.assertIn(b'No activity in this period',page)
            self.assertIn(b'Search activity',page)
            self.assertNotIn(b'<details',page)
        settings=client.get('/settings').data
        self.assertIn(b'Logging',settings)
        self.assertIn(b'View all activity',settings)
        self.assertNotIn(b'<details',settings)
        self.assertNotIn(b'Technical details',settings)

    def test_failure_and_invalid_page_render_cleanly(self):
        client=web.app.test_client()
        with client.session_transaction() as session:session.update(auth=True,version=web.auth_version())
        with patch.object(web.activity,'read_history',side_effect=ValueError('Activity could not be loaded. Try again.')):
            self.assertIn(b'Activity could not be loaded',client.get('/logs').data)
        self.assertIn(b'Choose a valid page number.',client.get('/logs?page=nope').data)



class ConnectionInformation(unittest.TestCase):
    def test_dns_is_matched_to_each_connection(self):
        dns=device.parse_dns('# resolv.conf from eth0.dhcp\nnameserver 192.168.0.1\n# resolv.conf from wlan0.dhcp\nnameserver 10.0.0.1\nnameserver bad\n# resolv.conf from eth0.ra\nnameserver 2001:db8::1\n')
        self.assertEqual(dns['eth0'],['192.168.0.1','2001:db8::1'])
        self.assertEqual(dns['wlan0'],['10.0.0.1'])
        self.assertEqual(device.parse_dns(None),{})

    def test_masks_gateway_mac_and_assignment(self):
        item=dict(ifname='eth0',address='aa:bb:cc:dd:ee:ff',addr_info=[dict(family='inet',local='192.168.0.10',prefixlen=24,dynamic=True)])
        routes=[dict(dev='eth0',dst='default',gateway='192.168.0.1',protocol='dhcp',metric=1002),dict(dev='wlan0',dst='default',gateway='10.0.0.1')]
        with patch.object(device.Path,'read_text',return_value=''):
            result=device.connection_details(item,routes,{'eth0':['192.168.0.1']})
        self.assertEqual(result['masks'],['255.255.255.0'])
        self.assertEqual(result['gateways'],['192.168.0.1'])
        self.assertEqual(result['dns'],['192.168.0.1'])
        self.assertEqual(result['mac'],'aa:bb:cc:dd:ee:ff')
        self.assertEqual(result['assignment'],'Automatic (DHCP)')

    def test_missing_values_remain_unknown(self):
        with patch.object(device.Path,'read_text',side_effect=OSError()):
            result=device.connection_details({'ifname':'wlan0'},[],{})
        self.assertEqual(result['assignment'],'Unavailable')
        self.assertEqual(result['mac'],'Unavailable')
        self.assertEqual(result['gateways'],[])
        self.assertEqual(result['dns'],[])
        self.assertEqual(result['signal'],'Unavailable')

    def test_static_config_and_signal(self):
        with patch.object(device.Path,'read_text',return_value='interface eth0\nstatic ip_address=192.0.2.5/24\n'):
            result=device.connection_details({'ifname':'eth0'},[],{},signal=-55)
            self.assertEqual(result['assignment'],'Fixed address (Static)')
            self.assertEqual(result['signal'],'Strong')
            other=device.connection_details({'ifname':'wlan0'},[],{},signal=-80)
            self.assertEqual(other['assignment'],'Unavailable')
            self.assertEqual(other['signal'],'Weak')

    def test_dotted_subnet_form_and_legacy_prefix(self):
        data=dict(mode='static',ip='192.168.0.50',mask='255.255.255.0',gw='192.168.0.1',dns='192.168.0.1')
        self.assertEqual(web.network_payload(data)['address'],'192.168.0.50/24')
        data.pop('mask');data['cidr']='24'
        self.assertEqual(web.network_payload(data)['address'],'192.168.0.50/24')
        data['mask']='255.0.255.0'
        with self.assertRaisesRegex(ValueError,'subnet mask'):web.network_payload(data)

    def test_helper_errors_do_not_expose_commands(self):
        import subprocess
        with patch.object(web.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','sudo /private/helper.py failed')):
            with self.assertRaisesRegex(ValueError,'No networks could be loaded'):web.helper('scan',{})
        with patch.object(web.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','Wi-Fi is not ready.')):
            with self.assertRaisesRegex(ValueError,'Wi-Fi is not ready'):web.helper('wifi',{})

    def test_network_layout_has_no_expanders_commands_or_checks(self):
        client=web.app.test_client()
        with client.session_transaction() as session:session.update(auth=True,version=web.auth_version())
        page=client.get('/network').data
        for unwanted in [b'<details',b'<summary',b'<pre',b'wpa_cli',b'dhcpcd',b'wlan0',b'eth0',b'type="checkbox"',b'proto dhcp',b'CIDR']:
            self.assertNotIn(unwanted,page)
        for wanted in [b'network-columns',b'ethernet-connection',b'wifi-connection',b'Subnet mask',b'MAC address',b'DNS servers']:
            self.assertIn(wanted,page)
        self.assertLess(page.index(b'ethernet-connection'),page.index(b'wifi-connection'))



class WifiAddressSettings(unittest.TestCase):
    def test_wifi_address_updates_only_wifi_and_preserves_ethernet(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            config=root/'dhcpcd.conf'
            original='hostname\n# LEDSign eth0 BEGIN\ninterface eth0\nstatic ip_address=192.0.2.3/24\n# LEDSign eth0 END\n'
            config.write_text(original)
            def mapped(path):return root/Path(path).name
            with patch.object(helper,'require_stack'),patch.object(helper,'Path',side_effect=mapped),patch.object(helper,'run',return_value='') as run,patch.object(helper,'wait_address',return_value='192.0.2.10'),patch.object(helper,'ipv4_addresses',return_value=[]):
                result=helper.set_address({'mode':'static','address':'192.0.2.10/24','gateway':'192.0.2.1','dns':['192.0.2.1']},'wlan0')
                self.assertTrue(result['applied'])
                self.assertIn(original,config.read_text())
                self.assertIn('metric 3000',config.read_text())
                self.assertIn('static ip_address=192.0.2.10/24',config.read_text())
                run.assert_called_once_with(['dhcpcd','-n','wlan0'])
                run.reset_mock()
                helper.set_address({'mode':'dhcp'},'wlan0')
                self.assertIn(original,config.read_text())
                self.assertNotIn('static ip_address=192.0.2.10',config.read_text())
                self.assertEqual(config.read_text().count('# LEDSign wlan0 BEGIN'),1)
                run.assert_called_once_with(['dhcpcd','-n','wlan0'])

    def test_bad_static_values_never_rebind(self):
        with patch.object(helper,'require_stack'),patch.object(helper,'run') as operation:
            with self.assertRaises(ValueError):helper.set_address({'mode':'static','address':'bad','gateway':'bad','dns':[]},'wlan0')
            operation.assert_not_called()

    def test_wrong_password_is_reported_and_profile_cleaned_up(self):
        calls=[]
        def wpa(*args):
            calls.append(args)
            return {'ping':'PONG','list_networks':'network id / ssid / bssid / flags','add_network':'4'}.get(args[0],'OK')
        with patch.object(helper,'require_stack'),patch.object(helper,'wpa',side_effect=wpa),patch.object(helper,'wifi_events'),patch.object(helper,'authentication_failed',return_value=True):
            with self.assertRaisesRegex(ValueError,'Incorrect Wi-Fi password'):helper.wifi({'ssid':'Test','psk':'test-passphrase','security':'wpa2'})
        self.assertIn(('remove_network','4'),calls)
        self.assertNotIn(('save_config',),calls)

    def test_address_verification_does_not_accept_stale_static_for_dhcp(self):
        with patch.object(helper,'ipv4_addresses',side_effect=[[{'local':'192.0.2.8','dynamic':False}],[{'local':'192.0.2.9','dynamic':True}]]),patch.object(helper.time,'sleep'):
            self.assertEqual(helper.wait_address('wlan0','dhcp'),'192.0.2.9')

    def test_wifi_address_route_auth_confirmation_and_validation(self):
        client=web.app.test_client()
        self.assertEqual(client.post('/wifi/address',data={}).status_code,302)
        with client.session_transaction() as session:session.update(auth=True,version=web.auth_version(),csrf='test-token')
        self.assertEqual(client.post('/wifi/address',data={'mode':'dhcp'}).status_code,400)
        with patch.object(web,'helper') as operation:
            client.post('/wifi/address',data={'csrf':'test-token','mode':'dhcp'})
            client.post('/wifi/address',data={'csrf':'test-token','mode':'static','ip':'bad','confirm':'yes'})
            operation.assert_not_called()
            operation.return_value={'applied':True,'ip':'192.0.2.7'}
            client.post('/wifi/address',data={'csrf':'test-token','mode':'dhcp','confirm':'yes'})
            operation.assert_called_once_with('wifi_address',{'mode':'dhcp'})
        page=client.get('/network').data
        self.assertIn(b'Wi-Fi address settings applied.',page)
        self.assertIn(b'/wifi/address',page)
        self.assertNotIn(b'Connection changes are currently unavailable.',page)

    def test_static_verification_waits_until_dhcp_address_is_replaced(self):
        observations=[[{'local':'192.0.2.8','prefixlen':24,'dynamic':True}],[{'local':'192.0.2.8','prefixlen':24}]]
        with patch.object(helper,'ipv4_addresses',side_effect=observations),patch.object(helper.time,'sleep'):
            self.assertEqual(helper.wait_address('wlan0','static','192.0.2.8/24'),'192.0.2.8')

    def test_static_route_protocol_does_not_mislabel_assignment(self):
        item={'ifname':'wlan0','addr_info':[{'family':'inet','local':'192.0.2.8','prefixlen':24}]}
        with patch.object(device.Path,'read_text',return_value='interface wlan0\nstatic ip_address=192.0.2.8/24\n'):
            result=device.connection_details(item,[{'dev':'wlan0','dst':'default','protocol':'dhcp','gateway':'192.0.2.1'}],{})
        self.assertEqual(result['assignment'],'Fixed address (Static)')

    def test_sudo_warning_does_not_hide_wrong_password_message(self):
        import subprocess
        result=subprocess.CompletedProcess([],1,'','sudo: unable to resolve host test-device\nIncorrect Wi-Fi password.\n')
        with patch.object(web.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(ValueError,'Incorrect Wi-Fi password'):
                web.helper('wifi',{})

    def test_missing_interface_command_has_plain_error(self):
        with patch.object(helper,'run',side_effect=ValueError('wpa_cli failed')):
            with self.assertRaisesRegex(ValueError,'Wi-Fi is not ready'):
                helper.wpa('ping')

    def test_saving_profiles_keeps_credentials_private(self):
        with patch.object(helper,'run',return_value='OK'),patch.object(helper.Path,'exists',return_value=True),patch.object(helper.os,'chmod') as chmod:
            helper.wpa('save_config')
        self.assertEqual(chmod.call_count,2)
        self.assertTrue(all(call.args[1]==0o600 for call in chmod.call_args_list))

    def test_other_connection_ip_cannot_be_reused(self):
        with patch.object(helper,'require_stack'),patch.object(helper,'ipv4_addresses',return_value=[{'local':'192.0.2.8'}]):
            with self.assertRaisesRegex(ValueError,'already used'):
                helper.set_address({'mode':'static','address':'192.0.2.8/24','gateway':'192.0.2.1','dns':['192.0.2.1']},'wlan0')

    def test_wait_address_timeout_is_not_success(self):
        with patch.object(helper,'ipv4_addresses',return_value=[]),patch.object(helper.time,'monotonic',side_effect=[0,0,30]),patch.object(helper.time,'sleep'):
            self.assertIsNone(helper.wait_address('wlan0'))



if __name__ == '__main__': unittest.main()
