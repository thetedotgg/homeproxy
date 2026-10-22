#!/usr/bin/env python3
"""Real Linux daemon/CLI regression checks, isolated profiles and loopback only."""
import argparse
import json
import os
import resource
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries-dir', type=Path, default=Path('target/debug'))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    cli = (args.binaries_dir / 'homeproxy').resolve()
    daemon = (args.binaries_dir / 'homeproxyd').resolve()
    assert cli.is_file() and daemon.is_file(), 'Build homeproxy-cli and homeproxy-service first'
    passed = []
    processes = []
    with tempfile.TemporaryDirectory(prefix='homeproxy-service-') as temporary:
        root = Path(temporary)
        endpoint = root / 'run/control.sock'
        state = root / 'state'
        cache = root / 'cache'
        log_path = root / 'daemon.log'
        log = log_path.open('wb')
        command = [str(daemon), '--state-dir', str(state), '--cache-dir', str(cache), '--socket', str(endpoint), '--foreground']

        def check(label):
            passed.append(label)
            print(f'PASS {label}', flush=True)

        def invoke(*parts, success=True, stdin=None):
            result = subprocess.run([str(cli), '--socket', str(endpoint), '--json', *parts], input=stdin, text=True, capture_output=True, timeout=35)
            value = json.loads(result.stdout)
            assert (result.returncode == 0) == success, f'Unexpected CLI exit for {parts[0]}: {result.returncode}'
            assert value['ok'] == success
            return value['result'] if success else value['error']

        def wait_for(predicate, timeout=12):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    if predicate():
                        return
                except (OSError, ValueError, AssertionError):
                    pass
                time.sleep(0.05)
            raise AssertionError('Timed out waiting for service state')

        def boot():
            process = subprocess.Popen(command, stdout=log, stderr=log)
            processes.append(process)
            wait_for(lambda: process.poll() is None and endpoint.exists() and invoke('status')['platform'] == 'linux')
            return process

        def shutdown(process, sig=signal.SIGTERM):
            process.send_signal(sig)
            result = process.wait(timeout=15)
            assert result == (0 if sig == signal.SIGTERM else -sig)

        def rpc(method, version=1, **fields):
            payload = json.dumps({'version': version, 'command': {'method': method, **fields}}).encode()
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(5)
                stream.connect(str(endpoint))
                stream.sendall(struct.pack('!I', len(payload)) + payload)
                def receive(length):
                    data = b''
                    while len(data) < length:
                        chunk = stream.recv(length - len(data))
                        assert chunk, 'Truncated response'
                        data += chunk
                    return data
                length = struct.unpack('!I', receive(4))[0]
                assert length <= 32 * 1024 * 1024
                return json.loads(receive(length))['result']

        def free_port():
            with socket.socket() as stream:
                stream.bind(('127.0.0.1', 0))
                return stream.getsockname()[1]

        try:
            process = boot()
            initial = invoke('status')
            assert not initial['running'] and not initial['settings']['enabled']
            assert not (state / 'https-inspection-authority-v1.json').exists()
            assert stat.S_IMODE(endpoint.stat().st_mode) == 0o600
            for directory in (state, cache, endpoint.parent):
                assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            check('fresh headless profile is stopped, private and creates no CA')

            secret = invoke('credentials', 'show')['password']
            assert secret and secret not in json.dumps(initial)
            assert 'proxyPassword' not in initial['settings']
            assert secret not in log_path.read_text()
            check('ordinary status and logs exclude proxy credentials')

            invoke('config', 'apply', '--stdin', stdin='{"listenIp":"192.168.1.20","listenIps":["192.168.1.20"]}')
            invoke('config', 'set', 'listenIp', '"192.168.1.30"')
            assert invoke('status')['settings']['listenIps'] == ['192.168.1.30']
            invoke('config', 'set', 'listenIps', '["192.168.1.40"]')
            assert invoke('status')['settings']['listenIp'] == '192.168.1.40'
            invoke('config', 'apply', '--stdin', stdin='{"listenIp":"192.168.1.20","listenIps":["192.168.1.30"]}', success=False)
            complete = rpc('desktop_snapshot')['Ok']
            incomplete = dict(complete['settings'])
            del incomplete['deniedClientIps']
            assert rpc('apply_settings', settings=incomplete, expected_revision=complete['revision'])['Err']['code'] == 'invalid_config'
            assert invoke('status')['revision'] == complete['revision']
            invoke('config', 'set', 'listenIp', 'null')
            assert invoke('status')['settings']['listenIps'] == []
            check('address patches are unambiguous and incomplete replacement settings are refused')

            assert invoke('config', 'set', 'httpsMode', '"inspect"', success=False)['code'] == 'invalid_config'
            assert invoke('status')['settings']['httpsMode'] == 'tunnel'
            invoke('config', 'set', 'proxyPort', '0', success=False)
            invoke('config', 'set', 'enabled', 'true', success=False)
            assert invoke('doctor', success=False)['code'] == 'degraded' if invoke('status')['lastError'] else invoke('doctor')['health'] == 'ok'
            check('invalid settings and unacknowledged Inspect are rejected without changing configuration')

            ready = invoke('tls', 'status')
            assert ready['capability'] and not ready['prepared']
            assert invoke('tls', 'export', success=False)['code'] == 'tls_not_prepared'
            inspect_patch = {'httpsMode': 'inspect', 'httpsInspectHosts': ['example.com'], 'httpsClientTrustAcknowledged': True}
            assert invoke('config', 'apply', '--stdin', stdin=json.dumps(inspect_patch), success=False)['code'] == 'tls_not_prepared'
            prepared = invoke('tls', 'prepare')
            assert prepared['prepared'] and not prepared['inspectionEnabled'] and not prepared['localTrustInstalled']
            assert not prepared['clientTrustDeclared']
            record = state / 'https-inspection-authority-v1.json'
            assert stat.S_IMODE(record.stat().st_mode) == 0o600
            exported = invoke('tls', 'export', '--format', 'pem')
            assert exported['certificate'].startswith('-----BEGIN CERTIFICATE-----')
            assert 'PRIVATE' not in json.dumps(exported)
            assert exported['sha256Fingerprint'] == prepared['sha256Fingerprint']
            pem_output = root / 'authority.pem'
            der_output = root / 'authority.der'
            invoke('tls', 'export', '--format', 'pem', '--output', str(pem_output))
            invoke('tls', 'export', '--format', 'der', '--output', str(der_output))
            assert pem_output.read_text() == exported['certificate']
            assert bytes.fromhex(invoke('tls', 'export', '--format', 'der')['certificate']) == der_output.read_bytes()
            invoke('tls', 'export', '--output', str(pem_output), success=False)
            assert pem_output.read_text() == exported['certificate']
            invoke('config', 'apply', '--stdin', stdin=json.dumps(inspect_patch))
            assert invoke('status')['settings']['httpsMode'] == 'inspect'
            assert invoke('config', 'check')['valid']
            invoke('config', 'set', 'httpsMode', '"tunnel"')
            invoke('config', 'set', 'httpsClientTrustAcknowledged', 'false')
            shutdown(process)
            process = boot()
            assert invoke('tls', 'export')['sha256Fingerprint'] == prepared['sha256Fingerprint']
            assert not invoke('tls', 'status')['loaded']
            check('HTTPS authority requires explicit preparation, safely exports public PEM/DER and survives restart')

            history = invoke('history', 'status')
            assert history['healthy']
            history_output = root / 'usage.csv'
            invoke('history', 'export', '--format', 'csv', '--output', str(history_output))
            assert stat.S_IMODE(history_output.stat().st_mode) == 0o600
            assert 'identity' in history_output.read_text()
            invoke('history', 'export', '--output', str(history_output), success=False)
            check('private history reports and no-clobber CSV export use the live daemon')

            feed_path = root / 'trusted-domains.txt'
            feed_path.write_text('# trusted local source\n0.0.0.0 ads.imported.example\n||tracking.imported.example^\n')
            invoke('filter', 'import', '--name', 'Trusted feed', '--file', str(feed_path))
            feeds = invoke('filter', 'list')
            assert len(feeds) == 1 and feeds[0]['domainsSortedExact'] == ['ads.imported.example']
            feed_id = feeds[0]['id']
            old_revision = invoke('status')['revision']
            feed_path.write_text('updated.imported.example\n')
            invoke('filter', 'import', '--name', 'Trusted feed', '--file', str(feed_path))
            updated = invoke('filter', 'list')
            assert len(updated) == 1 and updated[0]['id'] == feed_id
            assert updated[0]['domainsSortedExact'] == ['updated.imported.example']
            forged = dict(updated[0])
            forged['domainsSortedExact'] = ['not_a_domain']
            assert rpc('import_filter_feed', feed=forged, expected_revision=invoke('status')['revision'])['Err']['code'] == 'invalid_config'
            assert invoke('filter', 'list') == updated
            assert rpc('remove_filter_feed', id=feed_id, expected_revision=old_revision)['Err']['code'] == 'conflict'
            feed_path.write_text('valid.example\n/unsupported[0-9]/\n')
            invoke('filter', 'import', '--name', 'Trusted feed', '--file', str(feed_path), success=False)
            assert invoke('filter', 'list') == updated
            shutdown(process)
            process = boot()
            assert invoke('filter', 'list') == updated
            invoke('filter', 'remove', feed_id)
            assert invoke('filter', 'list') == []
            check('trusted file filter imports replace atomically, reject unsupported syntax, enforce revisions and survive restart')

            cache_defaults = {
                'cacheLimitGib': 8, 'cacheMaxObjectMib': 1024,
                'responseBufferLimitMib': 8, 'responseBufferBudgetMib': 64,
            }
            current = invoke('config', 'show')
            assert all(current[key] == value for key, value in cache_defaults.items())
            shutdown(process)
            saved_path = state / 'settings.json'
            malformed = json.loads(saved_path.read_text())
            malformed['cacheLimitGib'] = 2000
            saved_path.write_text(json.dumps(malformed))
            retained = cache / ('a' * 64 + '.body')
            retained.write_bytes(b'preserve-until-valid-configuration')
            process = boot()
            assert not invoke('status')['running']
            assert invoke('config', 'check', success=False)['code'] == 'invalid_config'
            assert retained.read_bytes() == b'preserve-until-valid-configuration'
            invoke('config', 'set', 'cacheLimitGib', '8')
            assert invoke('config', 'check')['valid']
            check('invalid saved cache limits keep daemon controllable and preserve data until CLI repair')
            for key, invalid in (
                ('cacheLimitGib', [0, 1025, -1, 1.5, '20']),
                ('cacheMaxObjectMib', [0, 1025, -1, 1.5, '32']),
                ('responseBufferLimitMib', [-1, 9, 1.5]),
                ('responseBufferBudgetMib', [-1, 513, 1.5]),
            ):
                for value in invalid:
                    before = invoke('status')
                    rejected = invoke('config', 'apply', '--stdin',
                                      stdin=json.dumps({key: value}), success=False)
                    assert rejected['code'] == 'invalid_config', (key, value, rejected['code'])
                    after = invoke('status')
                    assert before['settings'] == after['settings']
                    assert before['revision'] == after['revision']
            rejected = invoke('config', 'apply', '--stdin',
                              stdin='{"responseBufferLimitMib":8,"responseBufferBudgetMib":7}', success=False)
            assert rejected['code'] == 'invalid_config'
            invoke('config', 'apply', '--stdin', stdin=json.dumps({
                'cacheLimitGib': 1024, 'cacheMaxObjectMib': 1,
                'responseBufferLimitMib': 0, 'responseBufferBudgetMib': 0,
            }))
            summary = invoke('cache', 'status')
            assert summary['limits']['cacheLimitGib'] == 1024
            assert summary['limits']['responseBufferBudgetMib'] == 0
            # Repeated status reads may deliberately return the last scan within 5 s.
            # Require a genuinely fresh measurement, rather than treating stale as current.
            def refresh_cache_summary():
                nonlocal summary
                summary = invoke('cache', 'status')
                return summary['usage']['measured'] and summary['usage']['usageIsCurrent']
            wait_for(refresh_cache_summary)
            assert not summary['usage']['measurementError']
            assert not summary['usage']['maintenanceError']
            assert summary['units'] == {'GiB': 1073741824, 'MiB': 1048576}
            assert summary['storage'] == 'disk'
            shutdown(process)
            process = boot()
            reloaded = invoke('config', 'show')
            assert reloaded['cacheLimitGib'] == 1024 and reloaded['cacheMaxObjectMib'] == 1
            assert reloaded['responseBufferLimitMib'] == reloaded['responseBufferBudgetMib'] == 0
            invoke('config', 'apply', '--stdin', stdin=json.dumps(cache_defaults))
            check('cache bounds reject atomically; custom limits, zero buffers and usage survive daemon restart')

            port, socks_port = free_port(), free_port()
            while port == socks_port:
                socks_port = free_port()
            invoke('config', 'apply', '--stdin', stdin=json.dumps({'proxyPort': port, 'socks5Port': socks_port, 'socks5Enabled': True, 'cacheEnabled': True}))
            assert invoke('config', 'check')['valid']
            assert invoke('start')['running']
            assert invoke('doctor')['health'] == 'ok'
            with socket.create_connection(('127.0.0.1', port), timeout=5) as proxy:
                proxy.sendall(b'GET http://doubleclick.net/ HTTP/1.1\r\nHost: doubleclick.net\r\nConnection: close\r\n\r\n')
                assert b'403' in proxy.recv(1024).split(b'\r\n', 1)[0]
            with socket.create_connection(('127.0.0.1', socks_port), timeout=5) as proxy:
                proxy.sendall(b'\x05\x01\x00')
                assert proxy.recv(2) == b'\x05\x00'
            assert invoke('status')['stats']['blockedRequests'] >= 1
            check('CLI starts real HTTP filtering and SOCKS5 listeners; counters reflect traffic')
            with socket.socket() as blocker:
                blocker.bind(('127.0.0.1', 0))
                blocker.listen()
                rejected = invoke('config', 'set', 'proxyPort', str(blocker.getsockname()[1]), success=False)
                assert rejected['code'] == 'listener_in_use'
                recovered = invoke('status')
                assert recovered['running'] and recovered['settings']['proxyPort'] == port
                assert not recovered['lastError']
                assert invoke('doctor')['health'] == 'ok'
            check('failed live port change reports its action error while restored service remains healthy')


            old = rpc('desktop_snapshot')['Ok']
            invoke('config', 'set', 'adblockMode', '"strict"')
            conflict = rpc('apply_settings', settings=old['settings'], expected_revision=old['revision'])
            assert conflict['Err']['code'] == 'conflict'
            assert invoke('status')['settings']['adblockMode'] == 'strict'
            check('stale desktop settings cannot overwrite a concurrent CLI change')

            edit = rpc('desktop_snapshot')['Ok']
            invoke('cache', 'clear')
            invoke('activity', 'clear')
            invoke('stop')
            invoke('start')
            assert rpc('apply_settings', settings=edit['settings'], expected_revision=edit['revision']).get('Ok')
            check('runtime actions do not invalidate a settings draft')

            assert rpc('status', version=999)['Err']['code'] == 'version_mismatch'
            assert rpc('start', shell='unexpected')['Err']['code'] == 'invalid_request'
            assert rpc('not_a_method')['Err']['code'] == 'invalid_request'
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(5)
                stream.connect(str(endpoint))
                stream.sendall(struct.pack('!I', 256 * 1024 + 1))
                assert stream.recv(1) == b''
            with socket.socket(socket.AF_UNIX) as slow:
                slow.connect(str(endpoint))
                assert invoke('status')['running']
            check('malformed, oversized, old-version and stalled IPC cannot block service control')

            duplicate = subprocess.run(command, capture_output=True, timeout=10)
            assert duplicate.returncode != 0 and b'Another HomeProxy daemon' in duplicate.stderr
            assert invoke('status')['running']
            check('second daemon cannot own the same profile')

            assert not invoke('stop')['running']
            shutdown(process)
            process = boot()
            assert not invoke('status')['running']
            check('explicit Stop stays disabled across daemon restart')

            invoke('start')
            shutdown(process)
            assert json.loads((state / 'settings.json').read_text())['enabled']
            invoke('status', success=False)
            process = boot()
            assert invoke('status')['running']
            assert invoke('doctor')['health'] == 'ok'
            check('SIGTERM preserves enabled state and restart restores proxy')

            shutdown(process, signal.SIGKILL)
            process = boot()
            assert invoke('status')['running']
            check('unclean crash releases locks and stale socket is safely recovered')

            shutdown(process)
            with socket.socket() as blocker:
                blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                blocker.bind(('127.0.0.1', port))
                blocker.listen()
                process = boot()
                assert not invoke('status')['running']
                assert invoke('doctor', success=False)['code'] == 'degraded'
            wait_for(lambda: invoke('status')['running'], timeout=12)
            check('occupied proxy port is diagnosed and saved enabled service recovers')

            shutdown(process)
            settings = state / 'settings.json'
            settings.rename(state / 'saved.json')
            settings.symlink_to(state / 'saved.json')
            denied = subprocess.run(command, capture_output=True, timeout=10)
            assert denied.returncode != 0 and b'Unsafe settings' in denied.stderr
            settings.unlink()
            (state / 'saved.json').rename(settings)
            endpoint.write_text('preserve this file')
            denied = subprocess.run(command, capture_output=True, timeout=10)
            assert denied.returncode != 0 and endpoint.read_text() == 'preserve this file'
            check('unsafe settings links and non-socket control paths are refused without replacement')
            endpoint.unlink()
            def limit_descriptors():
                resource.setrlimit(resource.RLIMIT_NOFILE, (40, 40))
            process = subprocess.Popen(command, stdout=log, stderr=log, preexec_fn=limit_descriptors)
            processes.append(process)
            wait_for(lambda: endpoint.exists() and invoke('status')['platform'] == 'linux')
            stalled = []
            try:
                for _ in range(55):
                    stream = socket.socket(socket.AF_UNIX)
                    stalled.append(stream)
                    stream.settimeout(.03)
                    try:
                        stream.connect(str(endpoint))
                    except (TimeoutError, BlockingIOError):
                        pass
                wait_for(lambda: b'control accept failed' in log_path.read_bytes(), timeout=3)
                assert process.poll() is None
            finally:
                for stream in stalled:
                    stream.close()
            wait_for(lambda: invoke('doctor')['health'] == 'ok')
            shutdown(process)
            check('descriptor exhaustion is retried and control recovers without a daemon crash')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            log.close()

    report = {'passed': passed, 'count': len(passed), 'network': 'isolated loopback only', 'system_changes': False}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(passed)} integration scenarios passed')


if __name__ == '__main__':
    main()
