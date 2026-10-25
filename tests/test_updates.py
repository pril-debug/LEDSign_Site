import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as web
import updates


class SoftwareUpdates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conf = self.root/'settings.json'
        self.conf.write_text(json.dumps(dict(auth=dict(username='admin', password_hash=generate_password_hash('secret-password')))))
        self.patches = [patch.object(web, 'CONF_PATH', self.conf), patch.object(updates, 'STATE', self.root),
                        patch.object(updates, 'CACHE', self.root/'cache.json')]
        for p in self.patches:
            p.start()
        web.app.config['TESTING'] = True
        self.client = web.app.test_client()
        (self.root/'installed.json').write_text(json.dumps(dict(version='v1.0.0', previous_version='v0.9.0', current='/app')))

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def csrf(self):
        self.client.get('/login')
        with self.client.session_transaction() as session:
            return session['csrf']

    def post(self, route, **data):
        return self.client.post(route, data=dict(csrf=self.csrf(), **data))

    def login(self):
        self.post('/login', username='admin', password='secret-password')

    def test_authentication_csrf_confirmation_and_invalid_release(self):
        for route in ('/updates', '/updates/status'):
            self.assertEqual(self.client.get(route).status_code, 302)
        self.login()
        self.assertEqual(self.client.post('/updates/action', data={}).status_code, 400)
        with patch.object(updates, 'start') as start:
            self.assertEqual(self.post('/updates/action', action='rollback').status_code, 400)
            self.assertEqual(self.post('/updates/action', action='install', version='main', confirm='yes').status_code, 400)
            start.assert_not_called()
            self.assertEqual(self.post('/updates/action', action='rollback', confirm='yes').status_code, 202)
            start.assert_called_once_with('rollback', '')

    def test_release_check_filters_orders_and_escapes_notes(self):
        self.login()
        releases = [dict(tag_name='v1.0.0', body='old', assets=[]),
                    dict(tag_name='v2.0.0', body='<script>alert(1)</script>', assets=[dict(name='ledsign-release.tar.gz', digest='sha256:'+'a'*64)]),
                    dict(tag_name='v9.0.0', draft=True), dict(tag_name='main'), dict(tag_name='v3.0.0', prerelease=True)]
        with patch.object(updates.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(releases).encode())):
            reply = self.post('/updates/check')
        self.assertEqual(reply.status_code, 200)
        data = reply.json['update']
        self.assertEqual(data['latest']['version'], 'v2.0.0')
        self.assertTrue(data['available'])
        self.assertEqual(len(data['releases']), 2)
        page = self.client.get('/updates')
        self.assertNotIn(b'<script>alert(1)</script>', page.data)
        self.assertIn(b'&lt;script&gt;', page.data)
        with patch.object(updates, 'start') as start:
            self.assertEqual(self.post('/updates/action', action='install', version='v2.0.0', confirm='yes').status_code, 202)
            start.assert_called_once_with('install', 'v2.0.0')

    def test_offline_status_history_and_rollback_need_no_github(self):
        self.login()
        history = [dict(date='2026-10-25T12:00:00+00:00', previous='v0.9.0', version='v1.0.0', action='install', success=True, message='Update installed.')]
        (self.root/'history.json').write_text(json.dumps(history))
        with patch.object(updates.urllib.request, 'urlopen', side_effect=OSError('offline')):
            self.assertEqual(self.client.get('/updates/status').json['history'], history)
            self.assertIn(b'v1.0.0', self.client.get('/updates').data)
            self.assertEqual(self.post('/updates/check').status_code, 503)
            with patch.object(updates, 'start'):
                self.assertEqual(self.post('/updates/action', action='rollback', confirm='yes').status_code, 202)

    def test_progress_is_readable_while_worker_runs(self):
        self.login()
        (self.root/'status.json').write_text(json.dumps(dict(phase='preparing', message='Preparing application…')))
        with patch.object(updates, 'start') as start:
            response = self.client.get('/updates/status')
            self.assertTrue(response.json['busy'])
            self.assertEqual(response.json['status']['phase'], 'preparing')
            start.assert_not_called()

    def test_current_and_newer_install_do_not_claim_update(self):
        for installed, available in [('v1.0.0', True), ('v2.0.0', False), ('v3.0.0', False), ('Local build abc', True)]:
            self.assertEqual(updates.newer('v2.0.0', installed), available)

    def test_no_releases_is_a_valid_result(self):
        with patch.object(updates.urllib.request, 'urlopen', return_value=io.BytesIO(b'[]')):
            result = updates.check()
        self.assertIsNone(result['latest'])
        self.assertFalse(result['available'])
