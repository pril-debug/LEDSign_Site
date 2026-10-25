import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as web


class FinishLynxStatus(unittest.TestCase):
    def test_status_expires(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(web, 'APP_ROOT', Path(directory)):
            config = Path(directory)/'config'
            config.mkdir()
            self.assertFalse(web.finishlynx_status()['running'])
            report = dict(updated=time.time(), running=True, connected=True, port=2042, protocol='UDP', clock='12:34:56', event='Girls 1600m')
            path = config/'finishlynx-status.json'
            path.write_text(json.dumps(report))
            self.assertEqual(web.finishlynx_status()['label'], 'Connected')
            self.assertEqual(web.finishlynx_status()['event'], 'Girls 1600m')
            report['updated'] -= 10
            path.write_text(json.dumps(report))
            self.assertFalse(web.finishlynx_status()['connected'])
            self.assertEqual(web.finishlynx_status()['clock'], '')
            self.assertEqual(web.finishlynx_status()['event'], '')

    def test_templates_and_script(self):
        with web.app.test_request_context():
            for name in ('dashboard.html', 'finishlynx.html', 'settings.html'):
                web.app.jinja_env.get_template(name)
            response = web.finishlynx_script()
            self.assertEqual(response.status_code, 200)
            self.assertIn('FlexClock.lss', response.headers['Content-Disposition'])
            response.direct_passthrough = False
            self.assertEqual(response.get_data(), (web.APP_ROOT / 'FlexClock.lss').read_bytes())
            self.assertIn(b';;ResultsHeader', response.get_data())
            self.assertIn(b';;StartListHeader', response.get_data())
            response.close()
