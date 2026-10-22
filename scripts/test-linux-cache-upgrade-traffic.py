#!/usr/bin/env python3
"""Real installed cache traffic acceptance, exclusively on the disposable KVM guest.

Prerequisites: qa on homeproxy-qa; canonical installed homeproxy.service running;
Inspect/trust prepared for cache.fixture.test; fixture-origin.service active at
9.9.9.9; test-linux-cache-upgrade-vm.py beside this script. The seven fixture paths
must not already be cached (the script checks this and never clears cache/pins).
Run: python3 test-linux-cache-upgrade-traffic.py --ack-disposable-vm \
    --artifacts /home/qa/cache-upgrade-traffic

Uses the canonical CLI and socket, performs HTTPS and HTTP traffic, temporarily
changes only cacheMode and responseBuffer{Limit,Budget}Mib, and restores those
fields and verifies the entire visible saved settings/running state in finally.
Credentials and the public CA remain in memory. Reports must be outside Git.
Local helper checks: python3 test-linux-cache-upgrade-traffic.py --self-test
These checks exercise parsing/assertions only; they are not installed acceptance.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import resource
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


HOST = 'cache.fixture.test'
ORIGIN_IP = '9.9.9.9'
SOCKET = Path('/run/homeproxy/control.sock')
FIXTURE_SOURCE = Path('/opt/homeproxy-acceptance/fixture-origin.py')
ORIGIN_STATE = Path('/var/lib/fixture-origin/counts.json')
PATHS = ('/fragments.jpg', '/gzip.jpg', '/vary.jpg', '/head.jpg', '/age.jpg',
         '/no-cache.jpg', '/expires.jpg')
FIELDS = ('cacheMode', 'responseBufferLimitMib', 'responseBufferBudgetMib')
CA_ISSUER = 'HomeProxy Local HTTPS Inspection CA'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def payload(path):
    seed = ('HomeProxy disposable fixture PAYLOAD ' + path + '\n').encode()
    return (seed * (131072 // len(seed) + 1))[:131072]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fixture_body(path, extra=None):
    headers = {key.lower(): value for key, value in (extra or {}).items()}
    body = payload(path)
    if path == '/gzip.jpg' and headers.get('accept-encoding') == 'gzip':
        return gzip.compress(body, mtime=0)
    if path == '/vary.jpg':
        return headers.get('accept-language', 'none').encode('ascii') + b'\n' + body
    return body


def command(*args, stdin=None):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=35)
    # Never expose raw CLI/systemctl output or input in an error.
    require(result.returncode == 0, f'{Path(args[0]).name} command failed (exit {result.returncode})')
    return result.stdout


def cli(*args, stdin=None):
    value = json.loads(command('/usr/bin/homeproxy', '--json', *args, stdin=stdin))
    require(isinstance(value, dict) and value.get('ok', True) and 'result' in value,
            f'Installed CLI {args[0]} returned no successful result')
    return value['result']


def patch_settings(patch):
    require(set(patch) <= set(FIELDS), 'Only cache mode/response buffer settings may be changed')
    cli('config', 'apply', '--stdin', stdin=json.dumps(patch))


def helper_module():
    spec = importlib.util.spec_from_file_location(
        'cache_upgrade_vm', Path(__file__).with_name('test-linux-cache-upgrade-vm.py'))
    require(spec is not None and spec.loader is not None, 'Installed traffic helper dependency is missing')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Shared credentials() must also use our canonical CLI wrapper.
    module.cli = cli
    return module


def request_bytes(method, target, extra=None, authorization=None):
    require(method in ('GET', 'HEAD'), 'Unexpected traffic method')
    require('\r' not in target and '\n' not in target, 'Invalid traffic target')
    headers = {'host': HOST, 'accept': '*/*', 'accept-encoding': 'identity', 'connection': 'close'}
    for name, value in (extra or {}).items():
        name = name.lower()
        require(name in ('accept-encoding', 'accept-language', 'range'), 'Unsupported traffic header')
        require(isinstance(value, str) and '\r' not in value and '\n' not in value,
                'Invalid traffic header value')
        headers[name] = value
    if authorization:
        require('\r' not in authorization and '\n' not in authorization, 'Invalid proxy authorization')
        headers['proxy-authorization'] = authorization
    return (f'{method} {target} HTTP/1.1\r\n' + ''.join(
        f'{name}: {value}\r\n' for name, value in headers.items()) + '\r\n').encode('ascii')


def exchange(stream, method, target, extra=None, authorization=None, issuer=None):
    try:
        stream.sendall(request_bytes(method, target, extra, authorization))
        response = http.client.HTTPResponse(stream, method=method)
        response.begin()
        try:
            return {'status': response.status, 'body': response.read(), 'issuer': issuer,
                    'headers': {name.lower(): value for name, value in response.getheaders()}}
        finally:
            response.close()
    finally:
        stream.close()


def make_client(helper, port, certificate):
    context = ssl.create_default_context(cadata=certificate)

    class Client(helper.ProxyClient):
        def http(self, method, path, extra=None):
            target = f'http://{HOST}{path}'
            result = exchange(self.stream(), method, target, extra)
            if result['status'] == 407:
                result = exchange(self.stream(), method, target, extra,
                                  self.authorization(result['headers'], method, target))
            return result

        def https(self, method, path, extra=None):
            status, headers, stream = self.connect()
            if status == 407:
                status, headers, stream = self.connect(self.authorization(headers, 'CONNECT', f'{HOST}:443'))
            if status != 200:
                return {'status': status, 'headers': headers, 'body': b'', 'issuer': None}
            try:
                stream = context.wrap_socket(stream, server_hostname=HOST)
                issuer = [value for group in stream.getpeercert()['issuer']
                          for name, value in group if name == 'commonName']
            except BaseException:
                stream.close()
                raise
            return exchange(stream, method, path, extra, issuer=issuer)

    return Client(port, None)


def response_evidence(result, scheme, method, path, expected, status=200, hit=False,
                      byte_range=None, encoding=None):
    label = f'{scheme} {method} {path}'
    require(result['status'] == status, f'{label}: expected HTTP {status}, got {result["status"]}')
    headers = result['headers']
    cache_status = headers.get('cache-status', '')
    cache_hit = bool(re.search(r'(?:^|,)\s*homeproxy\s*;\s*hit(?:[;,\s]|$)', cache_status, re.I))
    require(cache_hit == hit, f'{label}: unexpected Cache-Status hit state')
    if scheme == 'https' and status in (200, 206):
        require(CA_ISSUER in (result['issuer'] or []), f'{label}: TLS was not inspected by HomeProxy')
    if status in (200, 206):
        require(headers.get('etag') == '"fixture-' + sha256(expected) + '"',
                f'{label}: fixture strong ETag differs')
        selected = expected
        if byte_range:
            start, end = byte_range
            require(headers.get('content-range') == f'bytes {start}-{end}/{len(expected)}',
                    f'{label}: incorrect Content-Range')
            selected = expected[start:end + 1]
        require(headers.get('content-length') == str(len(selected)), f'{label}: incorrect Content-Length')
        require(headers.get('content-encoding') == encoding, f'{label}: incorrect Content-Encoding')
        require(result['body'] == (b'' if method == 'HEAD' else selected), f'{label}: fixture bytes differ')
    return {'scheme': scheme, 'method': method, 'path': path, 'status': result['status'],
            'bytes': len(result['body']), 'sha256': sha256(result['body']),
            'hit': cache_hit, 'contentLength': headers.get('content-length'),
            'contentRange': headers.get('content-range'), 'contentEncoding': headers.get('content-encoding'),
            'etag': headers.get('etag')}


def ledger_delta(before, after):
    require(isinstance(before.get('total'), int) and isinstance(after.get('total'), int),
            'Origin ledger has no integer total')
    require(after['requests'][:len(before['requests'])] == before['requests'],
            'Origin ledger was reset or rewritten during traffic')
    delta = after['total'] - before['total']
    require(delta >= 0 and len(after['requests']) - len(before['requests']) == delta,
            'Origin ledger totals are inconsistent')
    paths = {path: after['paths'].get(path, 0) - before['paths'].get(path, 0)
             for path in sorted(set(before['paths']) | set(after['paths']))
             if after['paths'].get(path, 0) != before['paths'].get(path, 0)}
    require(sum(paths.values()) == delta and all(value >= 0 for value in paths.values()),
            'Origin ledger path totals are inconsistent')
    return {'newOriginRequests': delta, 'originPathDeltas': paths}


def no_egress(before, after):
    evidence = ledger_delta(before, after)
    require(evidence['newOriginRequests'] == 0 and before == after, 'Offline traffic reached the active origin')
    return evidence


def service_property(name, unit='homeproxy.service'):
    return command('systemctl', 'show', unit, f'--property={name}', '--value').strip()


def guards():
    require(sys.flags.optimize == 0, 'Python -O/-OO is forbidden for acceptance')
    require(socket.gethostname() == 'homeproxy-qa', 'Requires disposable homeproxy-qa guest')
    require(os.getuid() != 0 and pwd.getpwuid(os.getuid()).pw_name == 'qa', 'Run as the actual qa user')
    require(not any(name.startswith('HOMEPROXY_') for name in os.environ), 'HOMEPROXY_* overrides are forbidden')
    require(command('systemd-detect-virt').strip() == 'kvm', 'Requires the real KVM guest')
    require('homeproxy-admin' in command('id', '-nG').split(), 'qa must belong to homeproxy-admin')
    require(stat.S_ISSOCK(os.lstat(SOCKET).st_mode), 'Canonical control socket must be a socket, not a symlink')
    require(SOCKET.parent.resolve() == SOCKET.parent, 'Canonical socket directory must not be redirected')
    for name in ('homeproxy', 'homeproxyd'):
        path = Path('/usr/bin', name)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                f'Canonical installed {name} must be a root-owned regular binary')
    require(command('systemctl', 'is-active', 'homeproxy.service').strip() == 'active',
            'Canonical installed service must be active')
    require(service_property('FragmentPath') in ('/usr/lib/systemd/system/homeproxy.service',
                                               '/lib/systemd/system/homeproxy.service'),
            'Canonical packaged service unit is required')
    require(not any('/homeproxy.service.d/' in path or '/homeproxy-.service.d/' in path
                    for path in service_property('DropInPaths').split()), 'Unit-specific drop-ins are forbidden')
    require('HOMEPROXY_' not in service_property('Environment'), 'Service environment overrides are forbidden')
    require(re.search(r'argv\[\]=/usr/bin/homeproxyd --shared-socket\s*;', service_property('ExecStart')),
            'Canonical installed daemon command is required')
    require(service_property('User') == 'homeproxy' and service_property('Group') == 'homeproxy-admin',
            'Canonical packaged service identity is required')
    pid = int(service_property('MainPID'))
    require(pid > 0, 'Canonical installed service has no PID')
    require(command('systemctl', 'is-active', 'fixture-origin.service').strip() == 'active',
            'Fixture origin must remain active')
    require(str(FIXTURE_SOURCE) in service_property('ExecStart', 'fixture-origin.service'),
            'Fixture service does not use the expected source')
    info = FIXTURE_SOURCE.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Fixture source must be root-owned and immutable to qa')
    addresses = {entry[4][0] for entry in socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)}
    require(addresses == {ORIGIN_IP}, 'Fixture hostname must resolve exclusively to 9.9.9.9')
    interfaces = json.loads(command('ip', '-json', 'address', 'show'))
    require(any(entry.get('local') == ORIGIN_IP for interface in interfaces
                for entry in interface.get('addr_info', [])), '9.9.9.9 must belong to the disposable guest')
    return pid


def check_settings(state):
    require(state.get('running') is True, 'Canonical proxy must already be running')
    settings = state['settings']
    require(settings.get('httpsMode') == 'inspect' and settings.get('httpsClientTrustAcknowledged') is True,
            'Saved Inspect mode with acknowledged client trust is required')
    require(HOST in settings.get('httpsInspectHosts', []), 'Fixture host must be explicitly inspected')
    require(not any(HOST == rule or HOST.endswith('.' + rule.lstrip('*.'))
                    for rule in settings.get('httpsBypassHosts', [])), 'Fixture must not be bypassed')
    require(settings.get('cacheEnabled') is True and settings.get('cacheLimitGib', 0) > 0
            and settings.get('cacheMaxObjectMib', 0) >= 1, 'Enabled cache with fixture capacity is required')
    require(all(field in settings for field in FIELDS), 'Installed CLI lacks the required settings contract')
    require(cli('tls', 'status').get('prepared') is True, 'Existing installed HomeProxy CA must be prepared')
    return settings


def cpu_snapshot(pid):
    parts = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    ticks = os.sysconf('SC_CLK_TCK')
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'testProcessCpuSeconds': time.process_time(),
            'cliChildCpuSeconds': children.ru_utime + children.ru_stime,
            'serviceCpuSeconds': (int(parts[11]) + int(parts[12])) / ticks}


def timings_summary(values):
    require(bool(values), 'No latency samples were collected')
    ordered = sorted(values)
    return {'count': len(values), 'minSeconds': ordered[0], 'maxSeconds': ordered[-1],
            'meanSeconds': sum(values) / len(values),
            'p95Seconds': ordered[max(0, (len(values) * 95 + 99) // 100 - 1)]}


def write_report(path, report):
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


class Acceptance:
    def __init__(self, client, ledger, report, report_path, saved, pid):
        self.client, self.ledger, self.report, self.report_path = client, ledger, report, report_path
        self.saved, self.pid = saved, pid

    def phase(self, name):
        self.report.update(complete=False, phase=name)
        write_report(self.report_path, self.report)

    def mode(self, mode):
        self.phase('save-cache-mode-' + mode)
        patch_settings({'cacheMode': mode})
        expected = dict(self.saved, cacheMode=mode, responseBufferLimitMib=8, responseBufferBudgetMib=64)
        state = cli('status')
        require(state['running'] and state['settings'] == expected, 'Cache-mode mutation changed unexpected settings')

    def request(self, scheme, path, method='GET', extra=None, status=200, hit=False,
                byte_range=None, expect_origin=False):
        self.phase(f'{scheme}-{method}-{path[1:]}-{status}')
        before = self.ledger.read()
        started = time.monotonic()
        result = getattr(self.client, scheme)(method, path, extra)
        elapsed = time.monotonic() - started
        body = fixture_body(path, extra)
        request_headers = {name.lower(): value for name, value in (extra or {}).items()}
        encoding = 'gzip' if path == '/gzip.jpg' and request_headers.get('accept-encoding') == 'gzip' else None
        evidence = response_evidence(result, scheme, method, path, body, status, hit, byte_range, encoding)
        after = self.ledger.read()
        if expect_origin:
            delta = ledger_delta(before, after)
            require(delta == {'newOriginRequests': 1, 'originPathDeltas': {path: 1}},
                    f'{scheme} {method} {path}: expected exactly one fixture origin request')
            recorded = after['requests'][-1]
            selected = body if byte_range is None else body[byte_range[0]:byte_range[1] + 1]
            require(all(recorded.get(key) == value for key, value in {
                'path': path, 'scheme': scheme, 'status': status, 'bytes': len(selected),
                'sha256': sha256(selected), 'range': (extra or {}).get('Range')}.items()),
                f'{scheme} {method} {path}: origin ledger differs from requested fixture')
        else:
            # Keep observing the live origin after every offline action.
            time.sleep(.03)
            delta = no_egress(before, self.ledger.read())
        evidence.update(delta, elapsedSeconds=elapsed)
        self.report['cases'].append(evidence)
        write_report(self.report_path, self.report)
        return evidence

    def range(self, scheme, start, end, hit, expect_origin=False, path='/fragments.jpg', encoding=None):
        headers = {'Range': f'bytes={start}-{end}'}
        if encoding:
            headers['Accept-Encoding'] = encoding
        return self.request(scheme, path, extra=headers, status=206, hit=hit,
                            byte_range=(start, end), expect_origin=expect_origin)

    def baseline(self):
        self.mode('offline')
        for scheme in ('https', 'http'):
            for path in PATHS:
                variants = [{'Accept-Encoding': 'gzip'}, {'Accept-Encoding': 'identity'}] if path == '/gzip.jpg' else (
                    [{'Accept-Language': language} for language in ('en', 'cs', 'de')]
                    if path == '/vary.jpg' else [None])
                for headers in variants:
                    self.request(scheme, path, extra=headers, status=504)
            self.request(scheme, '/head.jpg', method='HEAD', status=504)

    def fragments(self, scheme):
        self.mode('online')
        self.range(scheme, 0, 65535, False, True)
        self.mode('offline')
        self.range(scheme, 0, 65535, True)
        self.request(scheme, '/fragments.jpg', extra={'Range': 'bytes=65536-131071'}, status=504)
        self.mode('online')
        self.range(scheme, 65536, 131071, False, True)
        self.mode('offline')
        self.request(scheme, '/fragments.jpg', hit=True)
        self.request(scheme, '/fragments.jpg', method='HEAD', hit=True)
        for start, end in ((0, 65535), (65536, 131071), (65520, 65560), (1024, 3071)):
            self.range(scheme, start, end, True)

    def representations(self, scheme):
        self.mode('online')
        self.request(scheme, '/gzip.jpg', extra={'Accept-Encoding': 'gzip'}, expect_origin=True)
        for language in ('en', 'cs'):
            self.request(scheme, '/vary.jpg', extra={'Accept-Language': language}, expect_origin=True)
        for path in ('/expires.jpg', '/age.jpg', '/no-cache.jpg'):
            self.request(scheme, path, expect_origin=True)
        self.mode('offline')
        self.request(scheme, '/gzip.jpg', extra={'Accept-Encoding': 'gzip'}, hit=True)
        self.range(scheme, 7, 63, True, path='/gzip.jpg', encoding='gzip')
        self.request(scheme, '/gzip.jpg', extra={'Accept-Encoding': 'identity'}, status=504)
        for language in ('en', 'cs'):
            self.request(scheme, '/vary.jpg', extra={'Accept-Language': language}, hit=True)
        self.request(scheme, '/vary.jpg', extra={'Accept-Language': 'de'}, status=504)
        self.request(scheme, '/expires.jpg', hit=True)
        for path in ('/age.jpg', '/no-cache.jpg'):
            self.request(scheme, path, status=504)

    def head_miss(self, scheme):
        self.mode('online')
        self.request(scheme, '/head.jpg', method='HEAD', expect_origin=True)
        self.mode('offline')
        self.request(scheme, '/head.jpg', status=504)
        self.mode('online')
        self.request(scheme, '/head.jpg', expect_origin=True)
        self.mode('offline')
        self.request(scheme, '/head.jpg', hit=True)
        self.request(scheme, '/head.jpg', method='HEAD', hit=True)

    def concurrent(self):
        self.mode('offline')
        self.phase('concurrent-canonical-cli-and-30-offline-hits')
        before = self.ledger.read()
        cpu_before = cpu_snapshot(self.pid)
        started = time.monotonic()
        stop = threading.Event()
        ready = {'status': threading.Event(), 'prepared': threading.Event()}
        samples = {'status': [], 'prepared': []}
        traffic_intervals = []

        def poll(name):
            while not stop.is_set():
                began = time.monotonic()
                value = cli('status') if name == 'status' else cli('cache', 'prepared')
                if name == 'status':
                    require(value['running'] and value['settings']['cacheMode'] == 'offline',
                            'Concurrent CLI status lost running Offline state')
                else:
                    require(isinstance(value.get('jobs'), list) and isinstance(value.get('pins'), list),
                            'Concurrent cache prepared lacks the installed contract')
                samples[name].append((began, time.monotonic()))
                ready[name].set()
                stop.wait(.01)

        evidence = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(poll, name) for name in ('status', 'prepared')]
            try:
                for event in ready.values():
                    require(event.wait(35), 'Concurrent canonical CLI never produced its initial result')
                for index in range(30):
                    scheme = 'https' if index % 2 == 0 else 'http'
                    began = time.monotonic()
                    result = getattr(self.client, scheme)('GET', '/fragments.jpg')
                    ended = time.monotonic()
                    item = response_evidence(result, scheme, 'GET', '/fragments.jpg',
                                             payload('/fragments.jpg'), hit=True)
                    item['elapsedSeconds'] = ended - began
                    evidence.append(item)
                    traffic_intervals.append((began, ended))
            finally:
                stop.set()
                for future in futures:
                    future.result()
        time.sleep(1)
        delta = no_egress(before, self.ledger.read())
        cpu_after = cpu_snapshot(self.pid)
        for name, intervals in samples.items():
            require(any(start < traffic_intervals[-1][1] and end > traffic_intervals[0][0]
                        for start, end in intervals), f'{name} CLI polling did not overlap real cached traffic')
        self.report['concurrent'] = dict(delta, hitCount=len(evidence),
            elapsedSeconds=time.monotonic() - started, cases=evidence,
            trafficLatency=timings_summary([entry['elapsedSeconds'] for entry in evidence]),
            cliLatency={name: timings_summary([end - start for start, end in intervals])
                        for name, intervals in samples.items()},
            cpuSeconds={name: cpu_after[name] - cpu_before[name] for name in cpu_before})
        write_report(self.report_path, self.report)


def artifact_directory(path):
    resolved = path.expanduser().resolve()
    for ancestor in (resolved, *resolved.parents):
        require(not (ancestor / '.git').exists(), 'Artifacts must be outside a Git checkout/worktree')
    require(not resolved.is_relative_to(Path(__file__).resolve().parent),
            'Artifacts must be outside the source scripts directory')
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(resolved.stat().st_uid == os.getuid(), 'Artifacts directory must belong to the current user')
    resolved.chmod(0o700)
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ack-disposable-vm', action='store_true')
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--self-test', action='store_true', help='Run local pure helper checks only (no installed acceptance)')
    args = parser.parse_args(argv)
    if args.self_test:
        require(sys.flags.optimize == 0, 'Python -O/-OO is forbidden for acceptance')
        return 0 if unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(HelperTests)).wasSuccessful() else 1
    if not args.ack_disposable_vm or args.artifacts is None:
        parser.error('--ack-disposable-vm and --artifacts are required for installed acceptance')
    artifacts = artifact_directory(args.artifacts)
    report_path = artifacts / 'traffic-report.json'
    report = {'complete': False, 'result': 'running', 'phase': 'guards', 'cases': [],
              'host': HOST, 'socket': str(SOCKET), 'originAddress': ORIGIN_IP}
    # Invalidate any old PASS before fallible host/service/fixture guards.
    write_report(report_path, report)
    saved = None
    saved_running = None
    modified = False
    failure = None
    started = time.monotonic()
    def interrupted(_signum, _frame):
        raise InterruptedError('Acceptance interrupted')
    previous_sigterm = signal.signal(signal.SIGTERM, interrupted)
    try:
        report['sourceSha256'] = sha256(Path(__file__).read_bytes())
        pid = guards()
        helper = helper_module()
        report['helperSha256'] = sha256(Path(helper.__file__).read_bytes())
        report['fixtureSource'] = {'path': str(FIXTURE_SOURCE), 'sha256': sha256(FIXTURE_SOURCE.read_bytes())}
        report['binarySha256'] = {name: sha256(Path('/usr/bin', name).read_bytes())
                                  for name in ('homeproxy', 'homeproxyd')}
        state = cli('status')
        saved = check_settings(state)
        saved_running = state['running']
        report['serviceVersion'] = state.get('serviceVersion')
        report['systemdMainPID'] = pid
        report['fixtures'] = {path: {'bytes': len(payload(path)), 'sha256': sha256(payload(path))} for path in PATHS}
        report['fixtures']['/gzip.jpg']['gzipSha256'] = sha256(fixture_body('/gzip.jpg', {'Accept-Encoding': 'gzip'}))
        certificate = cli('tls', 'export', '--format', 'pem').get('certificate')
        require(isinstance(certificate, str) and certificate.startswith('-----BEGIN CERTIFICATE-----\n')
                and 'PRIVATE KEY' not in certificate, 'Installed CLI lacks public CA export contract')
        client = make_client(helper, saved['proxyPort'], certificate)
        ledger = helper.Ledger(ORIGIN_STATE)
        ledger.read()
        acceptance = Acceptance(client, ledger, report, report_path, saved, pid)
        acceptance.phase('save-response-buffer')
        # A failed patch can still have partially reached the service: always restore.
        modified = True
        patch_settings({'responseBufferLimitMib': 8, 'responseBufferBudgetMib': 64})
        acceptance.baseline()
        for scheme in ('https', 'http'):
            acceptance.fragments(scheme)
            acceptance.representations(scheme)
            acceptance.head_miss(scheme)
        acceptance.concurrent()
        acceptance.phase('final-no-egress-and-canonical-service-check')
        before = ledger.read()
        time.sleep(1)
        no_egress(before, ledger.read())
        require(int(service_property('MainPID')) == pid, 'Canonical service was replaced during acceptance')
        require(command('systemctl', 'is-active', 'fixture-origin.service').strip() == 'active',
                'Fixture origin stopped during acceptance')
    except BaseException as error:
        failure = error
        report.update(result='fail', failure={'type': type(error).__name__})
        # Our assertions use static descriptions only. Other exceptions can echo
        # CLI credentials/settings; deliberately record their type without text.
        if isinstance(error, AssertionError):
            report['failure']['message'] = str(error)
    finally:
        report.update(complete=False, phase='restore-original-settings')
        # Report IO must never prevent restoration after a partially applied patch.
        try:
            write_report(report_path, report)
        except BaseException as error:
            failure = error
            report.update(result='fail', reportWriteFailure={'type': type(error).__name__})
        if modified:
            try:
                patch_settings({field: saved[field] for field in FIELDS})
                restored = cli('status')
                require(restored['settings'] == saved and restored['running'] == saved_running,
                        'Exact original visible settings/running state were not restored')
                report['restoration'] = {'settingsMatch': True, 'runningMatch': True,
                                         'modifiedFields': list(FIELDS), 'credentialsTouched': False}
            except BaseException as error:
                failure = error
                report.update(result='fail', restoration={'settingsMatch': False,
                              'failureType': type(error).__name__})
        signal.signal(signal.SIGTERM, previous_sigterm)
        report['elapsedSeconds'] = time.monotonic() - started
        if failure is None:
            report.update(complete=True, result='pass', phase='complete')
        write_report(report_path, report)
    print(f'RESULT {report["result"]}: {report_path}', flush=True)
    return 0 if report['complete'] else 1


class HelperTests(unittest.TestCase):
    """Pure local checks; never contact a daemon, fixture, or installed CLI."""

    def test_encoding_and_language_override_once(self):
        wire = request_bytes('GET', '/gzip.jpg', {'Accept-Encoding': 'gzip', 'Accept-Language': 'cs'})
        self.assertEqual(wire.lower().count(b'accept-encoding:'), 1)
        self.assertIn(b'accept-encoding: gzip\r\n', wire)
        self.assertNotIn(b'identity', wire)
        self.assertEqual(wire.lower().count(b'accept-language:'), 1)
        with self.assertRaises(AssertionError):
            request_bytes('GET', '/gzip.jpg', {'Accept-Encoding': 'gzip\r\nInjected: yes'})

    def test_raw_gzip_and_language_fixtures(self):
        raw = fixture_body('/gzip.jpg', {'Accept-Encoding': 'gzip'})
        self.assertEqual(gzip.decompress(raw), payload('/gzip.jpg'))
        self.assertEqual(fixture_body('/gzip.jpg'), payload('/gzip.jpg'))
        self.assertNotEqual(raw, payload('/gzip.jpg'))
        self.assertEqual(fixture_body('/vary.jpg', {'Accept-Language': 'cs'}), b'cs\n' + payload('/vary.jpg'))

    def test_encoded_range_checks_exact_bytes_and_length(self):
        raw = fixture_body('/gzip.jpg', {'Accept-Encoding': 'gzip'})
        result = {'status': 206, 'body': raw[7:64], 'issuer': [CA_ISSUER], 'headers': {
            'cache-status': 'HomeProxy; hit', 'content-length': '57', 'content-encoding': 'gzip',
            'content-range': f'bytes 7-63/{len(raw)}', 'etag': '"fixture-' + sha256(raw) + '"'}}
        evidence = response_evidence(result, 'https', 'GET', '/gzip.jpg', raw,
                                     status=206, hit=True, byte_range=(7, 63), encoding='gzip')
        self.assertEqual(evidence['sha256'], sha256(raw[7:64]))
        result['body'] = payload('/gzip.jpg')[7:64]
        with self.assertRaises(AssertionError):
            response_evidence(result, 'https', 'GET', '/gzip.jpg', raw,
                              status=206, hit=True, byte_range=(7, 63), encoding='gzip')

    def test_head_does_not_read_or_expect_a_body(self):
        result = {'status': 200, 'body': b'', 'issuer': None, 'headers': {
            'cache-status': 'HomeProxy; hit', 'content-length': '131072',
            'etag': '"fixture-' + sha256(payload('/head.jpg')) + '"'}}
        response_evidence(result, 'http', 'HEAD', '/head.jpg', payload('/head.jpg'), hit=True)
        with self.assertRaises(AssertionError):
            response_evidence(result, 'http', 'GET', '/head.jpg', payload('/head.jpg'), hit=True)

    def test_ledger_rejects_reset_egress_and_inconsistent_counts(self):
        before = {'total': 1, 'paths': {'/head.jpg': 1}, 'requests': [{'path': '/head.jpg'}]}
        self.assertEqual(no_egress(before, json.loads(json.dumps(before)))['newOriginRequests'], 0)
        after = {'total': 2, 'paths': {'/head.jpg': 2}, 'requests': before['requests'] + [{'path': '/head.jpg'}]}
        with self.assertRaises(AssertionError):
            no_egress(before, after)
        with self.assertRaises(AssertionError):
            ledger_delta(after, before)
        after['paths']['/head.jpg'] = 1
        with self.assertRaises(AssertionError):
            ledger_delta(before, after)

    def test_cache_status_must_name_actual_homeproxy_hit(self):
        result = {'status': 504, 'body': b'', 'issuer': None, 'headers': {'cache-status': 'OtherProxy; hit'}}
        response_evidence(result, 'http', 'GET', '/head.jpg', b'', status=504)
        result['headers']['cache-status'] = 'HomeProxy; hit'
        with self.assertRaises(AssertionError):
            response_evidence(result, 'http', 'GET', '/head.jpg', b'', status=504)

    def test_artifact_guard_rejects_git_checkout(self):
        with tempfile.TemporaryDirectory(prefix='homeproxy-traffic-unit-') as directory:
            root = Path(directory)
            (root / '.git').write_text('gitdir: /outside/worktree\n')
            with self.assertRaises(AssertionError):
                artifact_directory(root / 'reports')
            self.assertFalse((root / 'reports').exists())

    def test_report_invalidates_previous_complete_result(self):
        with tempfile.TemporaryDirectory(prefix='homeproxy-traffic-unit-') as directory:
            path = Path(directory) / 'report.json'
            write_report(path, {'complete': True, 'result': 'pass'})
            write_report(path, {'complete': False, 'phase': 'guards'})
            self.assertFalse(json.loads(path.read_text())['complete'])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(path.with_suffix('.tmp').exists())

    def test_partial_patch_failure_restores_only_original_changed_fields(self):
        # Orchestration failure check only: all service/traffic boundaries are mocked.
        saved = {'cacheMode': 'online', 'responseBufferLimitMib': 0,
                 'responseBufferBudgetMib': 0, 'proxyPort': 17893, 'unrelated': 'preserved'}
        helper = mock.Mock(__file__=__file__)
        helper.Ledger.return_value.read.return_value = {'total': 0, 'paths': {}, 'requests': []}

        def fake_cli(*args):
            if args == ('tls', 'export', '--format', 'pem'):
                return {'certificate': '-----BEGIN CERTIFICATE-----\npublic-test-placeholder'}
            self.assertEqual(args, ('status',))
            return {'running': True, 'settings': saved}

        with tempfile.TemporaryDirectory(prefix='homeproxy-traffic-unit-') as directory:
            with mock.patch(__name__ + '.guards', return_value=123), \
                    mock.patch(__name__ + '.helper_module', return_value=helper), \
                    mock.patch(__name__ + '.FIXTURE_SOURCE', Path(__file__)), \
                    mock.patch(__name__ + '.sha256', return_value='test-hash'), \
                    mock.patch.object(Path, 'read_bytes', return_value=b'test-source'), \
                    mock.patch(__name__ + '.check_settings', return_value=saved), \
                    mock.patch(__name__ + '.make_client', return_value=mock.Mock()), \
                    mock.patch(__name__ + '.cli', side_effect=fake_cli), \
                    mock.patch(__name__ + '.patch_settings', side_effect=[RuntimeError('partial patch'), None]) as patch, \
                    mock.patch('builtins.print'):
                self.assertEqual(main(['--ack-disposable-vm', '--artifacts', directory]), 1)
            actual = json.loads((Path(directory) / 'traffic-report.json').read_text())
            self.assertFalse(actual['complete'])
            self.assertTrue(actual['restoration']['settingsMatch'])
            self.assertTrue(actual['restoration']['runningMatch'])
            self.assertEqual(patch.call_args_list[-1].args[0], {field: saved[field] for field in FIELDS})
            self.assertNotIn('partial patch', json.dumps(actual))


if __name__ == '__main__':
    sys.exit(main())
