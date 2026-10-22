#!/usr/bin/env python3
"""Focused cache-upgrade VM harness contracts; never launches a GUI, driver, daemon or VM."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    'cache_upgrade_vm_harness', Path(__file__).with_name('test-linux-cache-upgrade-vm.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

KEY_A = 'a' * 64
KEY_B = 'b' * 64
KEY_C = 'c' * 64
PUBLIC = harness.url('/public.jpg')
HTTP = harness.url('/http.jpg', 'http')
PRIVATE = harness.url('/private.jpg')
COOKIE = harness.url('/cookie.jpg')
ZERO = harness.url('/zero-age.jpg')


def entry(label, state='stored', key=None, ready=False, pinned=False, error=None, size=harness.PAYLOAD_SIZE):
    stored = state == 'stored'
    return {'label': label, 'state': state, 'receivedBytes': size if stored else 0,
            'storedBytes': size if stored else 0, 'cacheKey': key, 'pinned': pinned,
            'offlineReady': ready, 'errorCode': error}


def status(items, pins=None, active=None, job_state='failed', used=2 * harness.PAYLOAD_SIZE, count=2):
    return {'activeJob': active, 'errorCode': None,
            'jobs': [{'id': 'offline-1-1', 'state': job_state, 'budgetBytes': 64 << 20,
                      'receivedBytes': 0, 'items': items}],
            'pins': pins if pins is not None else [
                {'key': KEY_A, 'label': PUBLIC, 'bytes': harness.PAYLOAD_SIZE, 'offlineReady': True},
                {'key': KEY_B, 'label': HTTP, 'bytes': harness.PAYLOAD_SIZE, 'offlineReady': True}],
            'pinUsage': {'usedBytes': used, 'limitBytes': 256 << 20, 'entryCount': count,
                         'degraded': False, 'error': None}}


def good_status():
    return status([entry(PUBLIC, key=KEY_A, ready=True, pinned=True),
                   entry(HTTP, key=KEY_B, ready=True, pinned=True),
                   entry(PRIVATE, 'failed', error='response-not-cacheable'),
                   entry(COOKIE, 'failed', error='response-not-cacheable'),
                   entry(ZERO, 'stored', key=KEY_C, pinned=True)], pins=[
                       {'key': KEY_A, 'label': PUBLIC, 'bytes': harness.PAYLOAD_SIZE, 'offlineReady': True},
                       {'key': KEY_B, 'label': HTTP, 'bytes': harness.PAYLOAD_SIZE, 'offlineReady': True},
                       {'key': KEY_C, 'label': ZERO, 'bytes': harness.PAYLOAD_SIZE, 'offlineReady': False}],
                  used=3 * harness.PAYLOAD_SIZE + 2048, count=3)


def response(lines, body=b''):
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


class GuardContract(unittest.TestCase):
    def test_hostname_guard_has_no_artifact_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / 'report.json'
            harness.write_json(report, {'result': 'pass'})
            old = report.read_bytes()
            with patch.object(harness.socket, 'gethostname', return_value='real-workstation'):
                with self.assertRaisesRegex(AssertionError, 'disposable homeproxy-qa'):
                    harness.main(['--ack-disposable-vm', '--artifacts', temporary])
            self.assertEqual(report.read_bytes(), old)
            self.assertEqual(sorted(path.name for path in Path(temporary).iterdir()), ['report.json'])

    def test_failed_guest_preflight_replaces_previous_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / 'report.json'
            harness.write_json(report, {'result': 'pass', 'checks': ['old run']})
            (Path(temporary) / 'cache-restart.done').write_text('stale\n')
            with patch.object(harness.socket, 'gethostname', return_value='homeproxy-qa'), \
                    patch.object(harness.os, 'getuid', return_value=0), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(AssertionError, 'not root'):
                    harness.main(['--ack-disposable-vm', '--artifacts', temporary])
            value = json.loads(report.read_text())
            self.assertEqual(value['result'], 'fail')
            self.assertEqual(value['checks'], [])
            self.assertEqual(value['failure']['type'], 'AssertionError')
            self.assertFalse((Path(temporary) / 'cache-restart.done').exists(), 'stale restart marker survived')
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    def guard_module(self, outputs, virt='kvm'):
        module = Mock()
        module.check_environment = Mock()

        def command(*args, **_):
            if args[0] == 'systemd-detect-virt':
                return virt + '\n'
            if args[:2] == ('systemctl', 'is-active'):
                return 'active\n'
            prop = args[3].split('=')[1]
            return outputs.get(prop, '') + '\n'
        module.command = Mock(side_effect=command)
        return module

    def canonical(self, **override):
        values = {'FragmentPath': '/usr/lib/systemd/system/homeproxy.service',
                  'DropInPaths': '/usr/lib/systemd/system/service.d/10-timeout-abort.conf',
                  'Environment': 'RUST_LOG=info'}
        values.update(override)
        return values

    def run_guards(self, module, socket_mode=stat.S_IFSOCK | 0o660):
        with patch.dict(os.environ, {}, clear=False), \
                patch.object(harness.os, 'lstat', return_value=Mock(st_mode=socket_mode)):
            for key in [key for key in os.environ if key.startswith('HOMEPROXY_')]:
                del os.environ[key]
            harness.check_vm_guards(module)

    def test_canonical_guest_passes_guards(self):
        module = self.guard_module(self.canonical())
        self.run_guards(module)
        module.check_environment.assert_called_once()

    def test_non_kvm_guest_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'KVM'):
            self.run_guards(self.guard_module(self.canonical(), virt='qemu'))

    def test_any_homeproxy_environment_override_is_rejected(self):
        for name in ('HOMEPROXY_SOCKET', 'HOMEPROXY_CONFIG_DIR'):
            with patch.dict(os.environ, {name: '/tmp/x'}):
                with self.assertRaisesRegex(AssertionError, 'overrides'):
                    harness.check_vm_guards(self.guard_module(self.canonical()))

    def test_symlinked_socket_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'canonical socket'):
            self.run_guards(self.guard_module(self.canonical()), socket_mode=stat.S_IFLNK | 0o777)

    def test_noncanonical_unit_and_overrides_are_rejected(self):
        cases = [({'FragmentPath': '/etc/systemd/system/homeproxy.service'}, 'packaged unit'),
                 ({'DropInPaths': '/etc/systemd/system/homeproxy.service.d/socket.conf'}, 'drop-in'),
                 ({'Environment': 'HOMEPROXY_SOCKET=/tmp/control.sock'}, 'environment overrides')]
        for override, message in cases:
            with self.subTest(override=override), self.assertRaisesRegex(AssertionError, message):
                self.run_guards(self.guard_module(self.canonical(**override)))

    def test_distribution_drop_ins_are_not_unit_overrides(self):
        self.assertEqual(harness.unit_overrides(
            '/usr/lib/systemd/system/service.d/10-timeout-abort.conf'), [])
        self.assertEqual(len(harness.unit_overrides(
            '/run/systemd/system/homeproxy.service.d/a.conf /etc/systemd/system/homeproxy-.service.d/b.conf')), 2)

    def test_arguments_require_ack_and_plain_separate_slow_path(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            harness.parse_args(['--artifacts', '/tmp/x'])
        for path in ('/../etc/passwd', 'slow.bin', '/slow.bin?x=1', '/public.jpg', '/uncached.jpg'):
            with self.subTest(path=path), self.assertRaises(AssertionError):
                harness.parse_args(['--ack-disposable-vm', '--artifacts', '/tmp/x', '--slow-path', path])
        args = harness.parse_args(['--ack-disposable-vm', '--artifacts', '/tmp/x'])
        self.assertEqual(args.slow_path, '/slow.bin')
        self.assertFalse(args.no_slow_fixture)

    def test_product_preconditions_require_inspected_trusted_fixture_host(self):
        settings = {'httpsMode': 'inspect', 'httpsClientTrustAcknowledged': True, 'cacheEnabled': True,
                    'httpsInspectHosts': [harness.HOST], 'httpsBypassHosts': []}
        harness.check_product_preconditions(settings, {'prepared': True})
        for change, message in (({'httpsMode': 'tunnel'}, 'Inspect'), ({'httpsInspectHosts': []}, 'allowlist'),
                                ({'httpsBypassHosts': ['fixture.test']}, 'bypassed'),
                                ({'cacheEnabled': False}, 'cache')):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, message):
                harness.check_product_preconditions(dict(settings, **change), {'prepared': True})
        with self.assertRaisesRegex(AssertionError, 'CA'):
            harness.check_product_preconditions(settings, {'prepared': False})

    def test_missing_coverage_is_never_pass(self):
        self.assertEqual(harness.final_result([]), 'pass')
        self.assertEqual(harness.final_result([{'check': 'cancellation', 'reason': 'no fixture'}]), 'incomplete')


class CliContract(unittest.TestCase):
    def test_error_code_is_extracted_without_raw_output(self):
        value = {'ok': False, 'error': {'code': 'engine', 'message': 'offline-preparation:private-target secret=hunter2'}}
        self.assertEqual(harness.error_code(value), 'private-target')
        self.assertEqual(harness.error_code({'ok': False, 'error': {'code': 'invalid_input', 'message': 'x'}}),
                         'invalid_input')
        self.assertEqual(harness.error_code(None, 'Error: password hunter2 rejected'), 'unknown')
        self.assertEqual(harness.error_code({'error': {'code': 'Has Spaces hunter2'}}), 'unknown')

    def test_cli_attempt_uses_stdin_and_reports_failure_code(self):
        failed = subprocess.CompletedProcess([], 1, '{"ok":false,"error":{"message":"offline-preparation:duplicate-url"}}', '')
        with patch.object(harness.subprocess, 'run', return_value=failed) as run:
            self.assertEqual(harness.cli_attempt('cache', 'prepare', '--file', '-', stdin='{}'), (False, 'duplicate-url'))
        self.assertEqual(run.call_args.args[0], ['/usr/bin/homeproxy', '--json', 'cache', 'prepare', '--file', '-'])
        self.assertEqual(run.call_args.kwargs['input'], '{}')
        ok = subprocess.CompletedProcess([], 0, '{"ok":true,"result":{"id":"offline-1-1"}}', '')
        with patch.object(harness.subprocess, 'run', return_value=ok):
            self.assertEqual(harness.cli_attempt('cache', 'prepared'), (True, {'id': 'offline-1-1'}))
        malformed = subprocess.CompletedProcess([], 0, 'not json', '')
        with patch.object(harness.subprocess, 'run', return_value=malformed):
            self.assertEqual(harness.cli_attempt('status'), (False, 'unknown'))


class JobContract(unittest.TestCase):
    def test_new_job_waits_then_requires_single_creation(self):
        current = good_status()
        self.assertIsNone(harness.new_job(['offline-1-1'], current))
        self.assertEqual(harness.new_job([], current)['id'], 'offline-1-1')
        current['jobs'].append(dict(current['jobs'][0], id='offline-2-2'))
        with self.assertRaisesRegex(AssertionError, 'one new'):
            harness.new_job([], current)

    def test_active_job_is_not_finished(self):
        self.assertIsNone(harness.job_finished(status([], job_state='running'), 'offline-1-1'))
        self.assertIsNone(harness.job_finished(status([], active='offline-1-1', job_state='completed'), 'offline-1-1'))
        self.assertIsNotNone(harness.job_finished(status([], job_state='cancelled'), 'offline-1-1'))

    def test_prepared_public_items_require_store_pin_and_ready(self):
        current = good_status()
        job = current['jobs'][0]
        self.assertEqual(harness.check_ready_item(current, job, PUBLIC)['cacheKey'], KEY_A)
        for change, message in (({'pinned': False}, 'pinned'), ({'offlineReady': False}, 'Offline Ready'),
                                ({'storedBytes': 10}, 'bytes'), ({'cacheKey': 'XYZ'}, 'cache key'),
                                ({'errorCode': 'pin-failed', 'state': 'failed'}, 'not stored')):
            broken = json.loads(json.dumps(current))
            broken['jobs'][0]['items'][0].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, message):
                harness.check_ready_item(broken, broken['jobs'][0], PUBLIC)
        unpinned = json.loads(json.dumps(current))
        unpinned['pins'] = unpinned['pins'][1:]
        with self.assertRaisesRegex(AssertionError, 'canonical pins'):
            harness.check_ready_item(unpinned, unpinned['jobs'][0], PUBLIC)

    def test_private_and_cookie_are_failures_never_offline_ready(self):
        current = good_status()
        job = current['jobs'][0]
        self.assertEqual(harness.check_unready_item(current, job, PRIVATE)['errorCode'], 'response-not-cacheable')
        self.assertEqual(harness.check_unready_item(current, job, ZERO, may_store=True)['state'], 'stored')
        with self.assertRaisesRegex(AssertionError, 'pinned'):
            harness.check_unready_item(current, job, ZERO)
        for change, message in (({'offlineReady': True}, 'Offline Ready'), ({'pinned': True}, 'pinned'),
                                ({'state': 'stored', 'errorCode': None, 'cacheKey': 'd' * 64,
                                  'storedBytes': 5}, 'preparation failure')):
            broken = json.loads(json.dumps(current))
            broken['jobs'][0]['items'][2].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, message):
                harness.check_unready_item(broken, broken['jobs'][0], PRIVATE)
        leaked = json.loads(json.dumps(current))
        leaked['pins'].append({'key': KEY_C, 'label': ZERO, 'bytes': 1, 'offlineReady': False})
        with self.assertRaisesRegex(AssertionError, 'canonical pins'):
            harness.check_unready_item(leaked, leaked['jobs'][0], ZERO, may_store=True)

    def test_pin_usage_must_account_for_pins_within_quota(self):
        self.assertEqual(harness.check_pin_usage(good_status(), 2, 2 * harness.PAYLOAD_SIZE)['entryCount'], 3)
        for change in ({'degraded': True}, {'entryCount': 1}, {'usedBytes': 512 << 20}):
            broken = good_status()
            broken['pinUsage'].update(change)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                harness.check_pin_usage(broken, 2, 2 * harness.PAYLOAD_SIZE)

    def test_unpin_releases_metadata_and_manifest_overhead_as_well_as_payload(self):
        before = good_status()['pinUsage']
        current = good_status()
        current['pins'] = [pin for pin in current['pins'] if pin['key'] != KEY_B]
        current['pinUsage'].update(usedBytes=before['usedBytes'] - harness.PAYLOAD_SIZE - 512,
                                   entryCount=before['entryCount'] - 1)
        self.assertEqual(harness.check_released_pin(current, before, KEY_B, harness.PAYLOAD_SIZE)
                         ['freedBytes'], harness.PAYLOAD_SIZE + 512)
        for change in ({'usedBytes': before['usedBytes']},
                       {'usedBytes': before['usedBytes'] - harness.PAYLOAD_SIZE + 1},
                       {'usedBytes': 0}, {'entryCount': before['entryCount']}, {'degraded': True}):
            broken = json.loads(json.dumps(current))
            broken['pinUsage'].update(change)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                harness.check_released_pin(broken, before, KEY_B, harness.PAYLOAD_SIZE)

    def test_duplicate_label_is_not_silently_chosen(self):
        current = good_status()
        current['jobs'][0]['items'].append(entry(PUBLIC))
        with self.assertRaisesRegex(AssertionError, 'exactly one'):
            harness.item(current['jobs'][0], PUBLIC)

    def test_persistent_view_ignores_live_readiness_but_not_pins(self):
        before = good_status()
        after = json.loads(json.dumps(before))
        after['jobs'][0]['items'][0]['offlineReady'] = False
        after['jobs'][0]['items'][0]['receivedBytes'] = 0
        self.assertEqual(harness.persistent_view(before), harness.persistent_view(after))
        after['pins'] = after['pins'][:1]
        self.assertNotEqual(harness.persistent_view(before), harness.persistent_view(after))
        interrupted = json.loads(json.dumps(before))
        interrupted['jobs'][0]['items'][2]['errorCode'] = 'interrupted'
        self.assertNotEqual(harness.persistent_view(before), harness.persistent_view(interrupted))


class LedgerContract(unittest.TestCase):
    def ledger(self, paths):
        requests = [{'path': path} for path, count in paths.items() for _ in range(count)]
        return {'total': len(requests), 'paths': dict(paths), 'requests': requests}

    def test_deltas_and_zero_egress(self):
        before = self.ledger({'/public.jpg': 2})
        after = self.ledger({'/public.jpg': 3, '/http.jpg': 1})
        self.assertEqual(harness.path_deltas(before, after), {'/http.jpg': 1, '/public.jpg': 1})
        self.assertEqual(harness.require_no_egress(before, json.loads(json.dumps(before)), 'x'),
                         {'newOriginRequests': 0})
        with self.assertRaisesRegex(AssertionError, '2 new requests'):
            harness.require_no_egress(before, after, 'offline')

    def test_ledger_rejects_unexpected_format(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'counts.json'
            path.write_text('{"total": 0}')
            with self.assertRaisesRegex(AssertionError, 'format'):
                harness.Ledger(path).read()
            path.write_text(json.dumps(self.ledger({})))
            self.assertEqual(harness.Ledger(path).read()['total'], 0)


class TrafficContract(unittest.TestCase):
    def test_digest_known_answer_rfc2617(self):
        challenge = ('Digest realm="testrealm@host.com", qop="auth,auth-int", '
                     'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')
        value = harness.digest_authorization(challenge, 'Mufasa', 'Circle Of Life', 'GET', '/dir/index.html',
                                             cnonce='0a4f113b')
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', value)
        self.assertIn('opaque="5ccc069c403ebaf9f0171e9517f40e41"', value)
        self.assertNotIn('Circle Of Life', value)
        with self.assertRaisesRegex(AssertionError, 'Digest'):
            harness.digest_authorization('Basic realm="x"', 'u', 'p', 'GET', '/')

    def exchange(self, method, raw, extra=None):
        client, server = socket.socketpair()
        with server:
            server.sendall(raw)
            result = harness.exchange(client, method, '/public.jpg', extra)
            server.settimeout(1)
            request = server.recv(65536).decode()
        return result, request

    def test_head_with_declared_length_does_not_wait_for_body(self):
        raw = response(['HTTP/1.1 200 OK', 'Content-Length: 131072', 'Cache-Status: HomeProxy; hit'])
        result, request = self.exchange('HEAD', raw)
        self.assertTrue(request.startswith('HEAD /public.jpg HTTP/1.1\r\n'))
        self.assertIn('Host: cache.fixture.test\r\n', request)
        evidence = harness.check_response(dict(result, issuer=['HomeProxy Local CA']), '/public.jpg', 'HEAD', hit=True)
        self.assertEqual(evidence['bytes'], 0)

    def test_cached_range_and_body_are_verified(self):
        body = harness.payload('/public.jpg')[1024:3072]
        raw = response(['HTTP/1.1 206 Partial Content', f'Content-Length: {len(body)}',
                        'Content-Range: bytes 1024-3071/131072', 'Cache-Status: HomeProxy; hit'], body)
        result, request = self.exchange('GET', raw, {'Range': 'bytes=1024-3071'})
        self.assertIn('Range: bytes=1024-3071\r\n', request)
        harness.check_response(dict(result, issuer=['HomeProxy Local CA']), '/public.jpg', status=206,
                               hit=True, ranged=True)
        with self.assertRaisesRegex(AssertionError, 'issuer'):
            harness.check_response(dict(result, issuer=['Fixture Origin CA']), '/public.jpg', status=206,
                                   hit=True, ranged=True)
        wrong = dict(result, issuer=['HomeProxy'], headers=dict(result['headers'], **{'content-range': 'bytes 0-1/2'}))
        with self.assertRaisesRegex(AssertionError, 'Content-Range'):
            harness.check_response(wrong, '/public.jpg', status=206, hit=True, ranged=True)

    def test_hit_and_miss_expectations(self):
        miss = {'status': 504, 'headers': {'cache-status': 'HomeProxy; fwd=miss'}, 'body': b'', 'issuer': None}
        harness.check_response(miss, '/uncached.jpg', status=504, hit=False)
        with self.assertRaisesRegex(AssertionError, 'expected HomeProxy cache hit'):
            harness.check_response(dict(miss, status=200, body=harness.payload('/x')), '/x', hit=True, tls=False)
        stale = {'status': 504, 'headers': {'cache-status': 'HomeProxy; hit'}, 'body': b'', 'issuer': None}
        with self.assertRaisesRegex(AssertionError, 'unexpected cache hit'):
            harness.check_response(stale, '/private.jpg', status=504, hit=False)
        changed = {'status': 200, 'headers': {'cache-status': 'HomeProxy; hit'}, 'body': b'x', 'issuer': None}
        with self.assertRaisesRegex(AssertionError, 'differs from the fixture'):
            harness.check_response(changed, '/http.jpg', hit=True, tls=False)

    def test_fixture_payload_and_long_url_match_product_rules(self):
        self.assertEqual(len(harness.payload('/public.jpg')), harness.PAYLOAD_SIZE)
        self.assertNotEqual(harness.payload('/public.jpg'), harness.payload('/http.jpg'))
        long_url = harness.url(harness.LONG_PATH)
        self.assertGreater(len(long_url), 250)
        self.assertLess(len(long_url), 4096)
        self.assertFalse(set('?#@ ') & set(long_url))
        self.assertTrue(long_url.isascii())


class GuiContract(unittest.TestCase):
    def make(self):
        gui = Mock()
        gate = Mock()
        gate.wait_for = lambda _label, predicate, timeout=30: predicate() or self.fail('predicate false')
        return gui, harness.PreparationGui(gui, gate)

    def test_keyboard_start_requires_tab_to_reach_enabled_button(self):
        gui, ui = self.make()
        ui.disabled = Mock(return_value=False)
        gui.js.side_effect = [None, 'prepare-offline']
        ui.start_by_keyboard()
        self.assertEqual([call.args[0] for call in gui.keys.call_args_list], [[chr(0xE004)], [chr(0xE007)]])
        gui.click.assert_not_called()

        gui, ui = self.make()
        ui.disabled = Mock(return_value=False)
        gui.js.side_effect = [None, 'preparation-quota']
        with self.assertRaisesRegex(AssertionError, 'not the start button'):
            ui.start_by_keyboard()
        self.assertEqual(gui.keys.call_count, 1, 'Enter must not be pressed on the wrong element')

    def test_pin_option_is_toggled_by_click_only_when_needed(self):
        gui, ui = self.make()
        gui.js.return_value = True
        ui.pin(True)
        gui.click.assert_not_called()
        gui.js.side_effect = [True, False]
        ui.pin(False)
        gui.click.assert_called_once_with('#preparation-pin')

    def test_reveal_older_item_clicks_matching_summary_and_survives_polling(self):
        gui, ui = self.make()
        opened = False

        def item(_script, label):
            self.assertEqual(label, PUBLIC)
            return {'jobIndex': 2, 'open': opened, 'visible': opened,
                    'ready': True, 'state': harness.READY_TEXT, 'error': None}

        def click(_selector):
            nonlocal opened
            opened = True
        gui.js.side_effect = item
        gui.click.side_effect = click
        with patch.object(harness.time, 'monotonic', side_effect=[0, 0, 1.5, 3.1, 3.3]), \
                patch.object(harness.time, 'sleep') as sleep:
            ui.reveal_item(PUBLIC)
        gui.click.assert_called_once_with('#preparation-jobs details.preparation-job:nth-of-type(3) > summary')
        self.assertEqual(sleep.call_count, 3)
        self.assertEqual(gui.js.call_count, 5)

    def test_reveal_visible_item_does_not_toggle_it_closed(self):
        gui, ui = self.make()
        gui.js.return_value = {'jobIndex': 1, 'open': True, 'visible': True}
        with patch.object(harness.time, 'monotonic', side_effect=[0, 0, 3.3]), \
                patch.object(harness.time, 'sleep'):
            ui.reveal_item(PUBLIC)
        gui.click.assert_not_called()

    def test_reveal_item_fails_if_polling_collapses_manual_expansion(self):
        gui, ui = self.make()
        closed = {'jobIndex': 1, 'open': False, 'visible': False}
        visible = {'jobIndex': 1, 'open': True, 'visible': True}
        gui.js.side_effect = [closed, visible, visible, closed]
        with patch.object(harness.time, 'monotonic', side_effect=[0, 0, 1.6]), \
                patch.object(harness.time, 'sleep'), \
                self.assertRaisesRegex(AssertionError, 'collapsed or became hidden during polling'):
            ui.reveal_item(PUBLIC)
        gui.click.assert_called_once_with('#preparation-jobs details.preparation-job:nth-of-type(2) > summary')

    def test_open_details_without_visible_row_is_not_a_revealed_item(self):
        gui, ui = self.make()
        gui.js.return_value = {'jobIndex': 1, 'open': True, 'visible': False}
        with self.assertRaisesRegex(AssertionError, 'predicate false'):
            ui.reveal_item(PUBLIC)
        gui.click.assert_not_called()

    def test_visible_copy_matches_product_sources(self):
        source = Path(__file__).resolve().parents[1] / 'src'
        text = ((source / 'i18n.ts').read_text(encoding='utf-8')
                + (source / 'offline-preparation.ts').read_text(encoding='utf-8'))
        expected = [*harness.EMPTY_TEXT.values(), *harness.REASONS.values(),
                    harness.READY_TEXT, harness.UNAVAILABLE_TEXT, harness.PINNED_TEXT]
        for value in expected:
            with self.subTest(value=value):
                self.assertIn(f'"{value}"', text)
        for selector in ('preparation-urls', 'preparation-budget', 'preparation-pin', 'prepare-offline',
                         'cancel-preparation', 'preparation-jobs', 'preparation-pins', 'clear-cache', 'cache-mode'):
            self.assertIn(f'id="{selector}"', (source / 'main.ts').read_text(encoding='utf-8'))
        self.assertNotIn(harness.READY_TEXT, harness.UNAVAILABLE_TEXT)


if __name__ == '__main__':
    unittest.main(verbosity=2)
