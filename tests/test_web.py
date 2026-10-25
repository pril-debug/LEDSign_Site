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
        for path in ['/dashboard', '/display', '/network', '/settings']:
            self.assertEqual(self.client.get(path).status_code, 200)
        self.assertIn(b'Display status unavailable', self.client.get('/dashboard').data)

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
        self.post('/logo/upload', {'logo': (io.BytesIO(buf.getvalue()), 'actual.jpg')})
        with Image.open(web.LOGO_CUSTOM) as image:
            self.assertEqual(image.format, 'PNG')
        response = self.client.get('/customer_logo.png')
        self.assertEqual(response.status_code, 200)
        response.close()
        self.post('/logo/remove')
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
            for name in ['bad;reboot', '-invalid', 'end-', 'two words', 'UPPER', 'x'*64, 'a.b', '']:
                self.post('/settings/hostname', {'hostname': name, 'confirm': 'yes'})
            operation.assert_not_called()

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
        self.assertIn(b'25 automatic restarts', page)
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
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=wpa), patch.object(helper, 'run', return_value=''):
            result = helper.wifi(dict(ssid='hidden', psk='password123', security='wpa2'))
        self.assertIn('IPv4 lease pending', result['message'])
        self.assertIn(('save_config',), calls)
        self.assertIn(('set_network', '2', 'scan_ssid', '1'), calls)
        self.assertTrue(all('eth0' not in args for args in calls))

    def test_wifi_failure_rolls_back(self):
        calls = []
        def wpa(*args):
            calls.append(args)
            if args[0] == 'set_network': raise ValueError('rejected')
            return {'ping': 'PONG', 'add_network': '3'}.get(args[0], 'OK')
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=wpa):
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
            with patch.object(helper, 'require_stack'), patch.object(helper, 'Path', side_effect=mapped), patch.object(helper, 'run', return_value='') as operation:
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
        with patch.object(helper, 'require_stack'), patch.object(helper, 'wpa', side_effect=['PONG', 'OK', 'OK', 'OK']) as operation:
            helper.wifi(dict(disconnect=True))
            self.assertEqual([call.args for call in operation.call_args_list], [('ping',), ('disable_network', 'all'), ('save_config',), ('disconnect',)])

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
        for value in ['-bad', 'bad-', 'bad_name', 'bad;id', 'a'*64, '', 'Upper', None, 'é']:
            self.assertFalse(device.valid_hostname(value))
            with self.assertRaises(ValueError): hostname.validate_hostname(value)
        with patch.object(hostname.subprocess, 'run') as operation:
            with self.assertRaises(ValueError): hostname.set_hostname({'hostname': 'race-clock'})
            operation.assert_not_called()
        with patch.object(hostname.subprocess, 'run', side_effect=[subprocess.CompletedProcess([],0,'',''),subprocess.CompletedProcess([],0,'race-clock\n','')]) as operation:
            self.assertIn('saved', hostname.set_hostname({'hostname':'race-clock','confirm':True})['message'])
            self.assertEqual(operation.call_args_list[0].args[0], ['/usr/bin/hostnamectl', 'set-hostname', 'race-clock'])
        with patch.object(hostname.subprocess, 'run', return_value=subprocess.CompletedProcess([],1,'','denied')):
            with self.assertRaises(ValueError): hostname.set_hostname({'hostname':'race-clock','confirm':True})
        with patch.object(hostname.subprocess, 'run', side_effect=OSError('missing')):
            with self.assertRaises(ValueError): hostname.set_hostname({'hostname':'race-clock','confirm':True})



if __name__ == '__main__': unittest.main()
