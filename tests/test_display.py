import json
from unittest.mock import patch
import unittest
import test_web
from display_layout import default_layout


class DisplaySettings(unittest.TestCase):
    setUp = test_web.Website.setUp
    tearDown = test_web.Website.tearDown
    csrf = test_web.Website.csrf
    post = test_web.Website.post
    login = test_web.Website.login
    def test_save_preserves_other_settings_and_validates(self):
        self.login()
        layout = default_layout()
        response = self.post('/display/settings',{'action':'save','layout':json.dumps(layout)})
        self.assertTrue(response.json['ok'])
        conf=json.loads(self.config.read_text())
        self.assertEqual(conf['other_device_setting'],42)
        self.assertEqual(conf['display_layout'],layout)
        layout['panels'][0]['chain']=2
        response=self.post('/display/settings',{'action':'save','layout':json.dumps(layout)})
        self.assertEqual(response.status_code,400)
        self.assertEqual(json.loads(self.config.read_text())['display_layout'],default_layout())

    def test_apply_passes_validated_layout_and_reports_failure(self):
        self.login()
        with patch('app.subprocess.run') as run:
            run.return_value.returncode=0; run.return_value.stdout='{"ok":true}'
            response=self.post('/display/settings',{'action':'apply','layout':json.dumps(default_layout())})
            self.assertTrue(response.json['ok'])
            self.assertEqual(json.loads(run.call_args.kwargs['input'])['layout'],default_layout())
            self.assertNotIn('display_layout',json.loads(self.config.read_text()))
            run.return_value.returncode=1; run.return_value.stdout='{"ok":false,"error":"Display controller unavailable."}'
            response=self.post('/display/settings',{'action':'test','layout':json.dumps(default_layout())})
            self.assertEqual(response.status_code,503)
            self.assertFalse(response.json['ok'])

    def test_display_redirects_and_logos_share_one_settings_section(self):
        self.login()
        response = self.client.get('/display')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/dashboard')
        for path in ('/dashboard', '/settings', '/finishlynx'):
            self.assertNotIn(b'href="/display"', self.client.get(path).data)
        settings = self.client.get('/settings').data
        for label in (b'Clock logo', b'logo-settings-layout', b'/logo/upload', b'Customer logo'):
            self.assertIn(label, settings)
        self.assertNotIn(b'Default logo', settings)
        self.assertNotIn(b'src="/default_logo.png"', settings)
        self.assertNotIn(b'upload-card', settings)
        self.assertNotIn(b'logo-card', settings)
        self.assertIn(b'updates-settings', settings)
