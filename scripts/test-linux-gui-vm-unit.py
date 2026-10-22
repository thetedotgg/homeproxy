#!/usr/bin/env python3
"""Focused harness contracts; does not launch an app, driver, or daemon."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    'gui_vm_harness', Path(__file__).with_name('test-linux-gui-vm.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class HarnessContract(unittest.TestCase):
    def make_gui(self):
        gui = harness.NativeGui.__new__(harness.NativeGui)
        gui.click = Mock()
        gui.wd = Mock()
        return gui

    def test_http_success_returns_arbitrary_script_value_including_ui_error(self):
        gui = self.make_gui()
        gui.port = 17894
        values = [None, False, 7, 'text', [], {}, {
            'error': 'The response does not meet public cache rules.',
            'errorCode': 'private-response',
            'text': 'Public cache item was refused',
        }]
        for value in values:
            with self.subTest(value=value):
                response = io.BytesIO(json.dumps({'value': value}).encode())
                with patch.object(harness.urllib.request, 'urlopen', return_value=response):
                    returned = gui.request('POST', '/session/fixture/execute/sync', {
                        'script': 'return arguments[0]', 'args': [value],
                    })
                self.assertEqual(returned, value)

    def test_http_error_throws_sanitized_code_and_path_without_driver_secret(self):
        gui = self.make_gui()
        gui.port = 17894
        secret = 'webdriver-raw-body-secret'
        error = harness.urllib.error.HTTPError(
            'http://127.0.0.1:17894/session/fixture/execute/sync',
            500, secret, {}, io.BytesIO(json.dumps({
                'value': {'error': secret, 'message': secret},
            }).encode()))
        with patch.object(harness.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(AssertionError) as raised:
                gui.request('POST', '/session/fixture/execute/sync', {
                    'script': 'return arguments[0]', 'args': [secret],
                })
        self.assertEqual(str(raised.exception),
                         'WebDriver POST /session/fixture/execute/sync failed: HTTP 500')
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertNotIn(secret, ''.join(traceback.format_exception(raised.exception)))

    def test_edit_releases_control_before_typing(self):
        gui = self.make_gui()
        gui.field = Mock(return_value='abc')
        gui.type_in('#proxy-user', 'abc')
        actions = gui.wd.call_args.args[2]['actions'][0]['actions']
        release = actions.index({'type': 'keyUp', 'value': '\ue009'})
        self.assertLess(release, actions.index({'type': 'keyDown', 'value': 'b'}))
        self.assertEqual(actions[-1], {'type': 'keyUp', 'value': 'c'})
        self.assertEqual(gui.wd.call_args.args[:2], ('POST', '/actions'))

    def test_wait_preserves_failed_state_assertion(self):
        def assertion():
            harness.require(False, 'real state mismatch')
        with self.assertRaisesRegex(AssertionError, 'real state mismatch'):
            harness.wait_for('state', assertion, timeout=.01)

    def test_multiline_input_uses_native_enter(self):
        gui = self.make_gui()
        gui.field = Mock(return_value='a\nb')
        gui.type_in('#https-inspect-hosts', 'a\nb')
        actions = gui.wd.call_args.args[2]['actions'][0]['actions']
        downs = [action['value'] for action in actions if action['type'] == 'keyDown']
        self.assertEqual(downs[-3:], ['a', '\ue007', 'b'])
        self.assertNotIn('\n', downs)

    def test_wait_retries_transient_connection(self):
        predicate = Mock(side_effect=[OSError('not ready'), True])
        with patch.object(harness.time, 'sleep'):
            self.assertTrue(harness.wait_for('connection', predicate, timeout=1))
        self.assertEqual(predicate.call_count, 2)

    def test_screenshot_refuses_exposed_password(self):
        gui = self.make_gui()
        gui.js = Mock(return_value=False)
        with tempfile.TemporaryDirectory() as temporary:
            gui.artifacts = Path(temporary)
            with self.assertRaisesRegex(AssertionError, 'visible fixture password'):
                gui.shot('unsafe')
            self.assertFalse(list(gui.artifacts.iterdir()))
            gui.wd.assert_not_called()

    def test_native_select_respects_disabled_inspect(self):
        gui = self.make_gui()
        gui.js = Mock(return_value=[{'value': 'tunnel', 'disabled': False},
                                    {'value': 'inspect', 'disabled': True}])
        with self.assertRaisesRegex(AssertionError, 'is disabled'):
            gui.select('#https-mode', 'inspect')
        gui.click.assert_not_called()
        gui.wd.assert_not_called()

    def test_report_write_is_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            harness.write_json(path, {'result': 'fail'})
            self.assertEqual(path.read_text(), '{\n  "result": "fail"\n}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.with_suffix('.tmp').exists())

    def test_fixture_password_meets_production_minimum(self):
        # Regression: the previous 13-character fixture was rejected by the real GUI.
        self.assertGreaterEqual(len(harness.PASSWORD), 16)

    def test_failed_vm_preflight_replaces_previous_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / 'report.json'
            harness.write_json(report_path, {'result': 'pass', 'checks': ['old run']})
            arguments = ['test-linux-gui-vm.py', '--ack-disposable-vm', '--artifacts', temporary]
            with patch('sys.argv', arguments), patch.object(harness.socket, 'gethostname', return_value='homeproxy-qa'), \
                    patch.object(harness.os, 'getuid', return_value=0), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(AssertionError, 'not root'):
                    harness.main()
            report = json.loads(report_path.read_text())
            self.assertEqual(report['result'], 'fail')
            self.assertEqual(report['checks'], [])
            self.assertEqual(report['failure']['type'], 'AssertionError')

    def test_hostname_guard_has_no_artifact_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / 'report.json'
            harness.write_json(report_path, {'result': 'pass', 'checks': ['preserve outside guest']})
            old_report = report_path.read_bytes()
            arguments = ['test-linux-gui-vm.py', '--ack-disposable-vm', '--artifacts', temporary]
            with patch('sys.argv', arguments), patch.object(harness.socket, 'gethostname', return_value='real-workstation'):
                with self.assertRaisesRegex(AssertionError, 'disposable homeproxy-qa'):
                    harness.main()
            self.assertEqual(report_path.read_bytes(), old_report)


if __name__ == '__main__':
    unittest.main(verbosity=2)
