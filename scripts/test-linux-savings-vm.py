#!/usr/bin/env python3
"""Real savings acceptance on the disposable installed homeproxy-qa KVM guest.

Root traffic run (no external network/trust-store changes):
  python3 test-linux-savings-vm.py --ack-disposable-vm --jpeg /tmp/fixture.jpg \
      --report /home/qa/savings/traffic.json
Supply a valid baseline JFIF RGB JPEG, 32 KiB < size <= 8 MiB, no EXIF/ICC,
strongly compressible at Balanced (for example deterministic RGB quality=100).
The existing GdkPixbuf library decodes input/output; no Python imaging package
is needed. Uses /usr/bin/homeproxy and the existing /usr/bin/homeproxyd service.
Adds only guest loopback 1.1.1.123/32, serves HTTP there, restores changed settings
and removes the alias. Unique URLs avoid existing cache; created public fixture
entries remain until normal expiry (this script never clears unrelated cache).

Optional native GUI check, run separately as graphical qa with its actual Xorg
:0 DISPLAY/XAUTHORITY/DBUS_SESSION_BUS_ADDRESS (shared GUI helper beside script):
  python3 test-linux-savings-vm.py --ack-disposable-vm --gui-check \
      --report /home/qa/savings/gui.json
Verifies displayed image/cache/total savings against canonical service stats,
then draft-versus-saved compression controls, restoring only that field.
For HTTPS add --https-host savings.fixture.test --tls-fixture-dir /tmp/tls.
That directory must contain origin.crt/origin.key, signed by an origin CA that
the controller has already trusted before starting the daemon. The hostname
must resolve exclusively to 1.1.1.123, and existing saved Inspect allowlist/trust
must include it. This script never changes trust, Inspect settings or daemon PID.
Without these flags HTTPS is explicitly untested. Native icon/UI requires the
separate GUI check and desktop icon QA.

Local parser/accounting/cleanup regressions (no VM/service operations):
  python3 scripts/test-linux-savings-vm.py --self-test
"""

import argparse
import ctypes
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

ORIGIN = '1.1.1.123'
FIELDS = ('cacheEnabled', 'cacheMode', 'compressionPreset',
          'responseBufferLimitMib', 'responseBufferBudgetMib')
COUNTERS = ('originBytes', 'deliveredBytes', 'cacheBytesSaved',
            'compressionBytesSaved', 'savedBytes', 'compressedImages', 'cacheHits')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def command(*args, stdin=None):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=35)
    # Never echo CLI output/input, process arguments or service credentials.
    require(result.returncode == 0, f'{Path(args[0]).name} failed (exit {result.returncode})')
    return result.stdout


def cli(*args, stdin=None):
    envelope = json.loads(command('/usr/bin/homeproxy', '--json', *args, stdin=stdin))
    require(isinstance(envelope, dict) and envelope.get('ok', True)
            and 'result' in envelope, 'Canonical installed CLI did not succeed')
    return envelope['result']


def patch_settings(patch):
    require(set(patch) <= set(FIELDS), 'Refusing changes outside savings test settings')
    cli('config', 'apply', '--stdin', stdin=json.dumps(patch))
    saved = cli('status')['settings']
    require(all(saved[key] == value for key, value in patch.items()), 'Settings were not persisted')


def service_pid():
    return int(command('systemctl', 'show', 'homeproxy.service', '-p', 'MainPID', '--value'))


def wait_for(label, predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError(f'Timed out: {label}')


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def guest_guard(root):
    require(socket.gethostname() == 'homeproxy-qa', 'Refusing a non-QA host')
    require(command('systemd-detect-virt').strip() == 'kvm', 'Requires disposable KVM guest')
    require((os.geteuid() == 0) == root, 'Run traffic as root; native GUI as graphical qa')
    require(not os.environ.get('HOMEPROXY_SOCKET'), 'Custom control sockets are forbidden')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'Requires installed systemd')
    require(Path('/run/homeproxy/control.sock').is_socket(), 'Canonical control socket missing')
    require(command('systemctl', 'is-active', 'homeproxy.service').strip() == 'active',
            'Canonical service must already be active')
    require(command('dpkg-query', '-W', '-f=${Status}', 'homeproxy').strip()
            == 'install ok installed', 'Requires installed homeproxy package')
    pid = service_pid()
    require(pid > 1, 'Requires canonical installed daemon PID')
    if root:
        require(Path(f'/proc/{pid}/exe').resolve() == Path('/usr/bin/homeproxyd'),
                'Requires canonical installed daemon executable')
    else:
        require('/usr/bin/homeproxyd --shared-socket' in command(
            'systemctl', 'show', 'homeproxy.service', '-p', 'ExecStart', '--value'),
            'Requires canonical installed daemon ExecStart')
    require(Path('/usr/bin/homeproxy').is_file(), 'Requires canonical installed CLI')
    state = cli('status')
    require(state['running'], 'Installed proxy must already run')
    require(state['settings']['lanAuthEnabled'], 'Real daemon LAN authentication must remain enabled')
    return pid, state


def jpeg_dimensions(body):
    """Decode actual pixels with the GTK library already needed by installed GUI."""
    require(body.startswith(b'\xff\xd8') and body.endswith(b'\xff\xd9'), 'Invalid JPEG envelope')
    library = ctypes.CDLL('libgdk_pixbuf-2.0.so.0')
    objects = ctypes.CDLL('libgobject-2.0.so.0')
    library.gdk_pixbuf_new_from_file.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    library.gdk_pixbuf_new_from_file.restype = ctypes.c_void_p
    for name in ('gdk_pixbuf_get_width', 'gdk_pixbuf_get_height'):
        function = getattr(library, name)
        function.argtypes = [ctypes.c_void_p]
        function.restype = ctypes.c_int
    objects.g_object_unref.argtypes = [ctypes.c_void_p]
    with tempfile.TemporaryDirectory(prefix='homeproxy-savings-decode-') as directory:
        path = Path(directory, 'image.jpg')
        path.write_bytes(body)
        error = ctypes.c_void_p()
        pixbuf = library.gdk_pixbuf_new_from_file(os.fsencode(path), ctypes.byref(error))
        if error.value:
            glib = ctypes.CDLL('libglib-2.0.so.0')
            glib.g_error_free.argtypes = [ctypes.c_void_p]
            glib.g_error_free(error)
        require(pixbuf, 'GdkPixbuf cannot decode JPEG pixels')
        try:
            dimensions = (library.gdk_pixbuf_get_width(pixbuf), library.gdk_pixbuf_get_height(pixbuf))
            require(all(value > 0 for value in dimensions), 'JPEG dimensions must be positive')
            return dimensions
        finally:
            objects.g_object_unref(pixbuf)


def fixture_headers(case, body):
    policy = {'no-transform': 'public, max-age=3600, no-transform',
              'no-store': 'public, no-store', 'private': 'private, max-age=3600'}
    headers = {'Content-Type': 'image/jpeg', 'Content-Length': str(len(body)),
               'Cache-Control': policy.get(case, 'public, max-age=3600'),
               'ETag': '"savings-fixture-original"', 'Accept-Ranges': 'bytes',
               'Last-Modified': 'Thu, 01 Oct 2026 00:00:00 GMT', 'Connection': 'close'}
    if case == 'set-cookie':
        headers['Set-Cookie'] = 'savings-fixture=1; Path=/'
    return headers


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.lock:
            case = self.server.cases.get(self.path)
            if case is not None:
                self.server.hits[self.path] = self.server.hits.get(self.path, 0) + 1
                self.server.request_controls[self.path] = self.headers.get('Cache-Control')
        if case is None:
            self.send_error(404)
            return
        self.send_response(200)
        for key, value in fixture_headers(case, self.server.jpeg).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(self.server.jpeg)


def exchange(port, path, cookie=False, no_transform=False, https_host=None, tls_context=None):
    stream = socket.create_connection(('127.0.0.1', port), 8)
    try:
        stream.settimeout(8)
        if https_host:
            require(tls_context is not None, 'HTTPS acceptance requires a validating client context')
            authority = f'{https_host}:443'
            stream.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii'))
            response = http.client.HTTPResponse(stream)
            response.begin()
            require(response.status == 200, 'Inspect CONNECT did not return 200')
            response.close()
            stream = tls_context.wrap_socket(stream, server_hostname=https_host)
            issuer = [value for group in stream.getpeercert()['issuer']
                      for name, value in group if name == 'commonName']
            require(issuer == ['HomeProxy Local HTTPS Inspection CA'], 'HTTPS passed through without Inspect')
        host = https_host or ORIGIN
        target = path if https_host else f'http://{ORIGIN}{path}'
        headers = f'Host: {host}\r\nAccept: image/jpeg\r\nAccept-Encoding: identity\r\nConnection: close\r\n'
        if cookie:
            headers += 'Cookie: savings-fixture=request\r\n'
        if no_transform:
            headers += 'Cache-Control: no-transform\r\n'
        stream.sendall(f'GET {target} HTTP/1.1\r\n{headers}\r\n'.encode('ascii'))
        response = http.client.HTTPResponse(stream)
        response.begin()
        try:
            return {'status': response.status,
                    'headers': {name.lower(): value for name, value in response.getheaders()},
                    'body': response.read()}
        finally:
            response.close()
    finally:
        stream.close()


def validate_response(result, original, dimensions, transformed, case):
    body, headers = result['body'], result['headers']
    require(result['status'] == 200, 'Fixture GET did not return 200')
    require(headers.get('content-type', '').split(';')[0].strip() == 'image/jpeg', 'Incorrect image type')
    require(int(headers.get('content-length', -1)) == len(body), 'Content-Length does not match bytes')
    require(headers.get('cache-control') == fixture_headers(case, original)['Cache-Control'],
            'Proxy changed origin reuse policy')
    require(jpeg_dimensions(body) == dimensions, 'Decoded image dimensions changed')
    if transformed:
        require(len(body) < len(original), 'Balanced did not reduce valid JPEG')
        require('x-homeproxy-transformed' not in headers, 'Internal cache marker leaked to client')
        require(all(name not in headers for name in ('etag', 'last-modified', 'accept-ranges')),
                'Transformation kept stale origin validators/range headers')
    else:
        require(body == original, 'Bypass did not preserve original JPEG bytes')
        require('x-homeproxy-transformed' not in headers, 'Passthrough incorrectly claims transformation')
        require(headers.get('etag') == '"savings-fixture-original"', 'Passthrough lost ETag')
        require(headers.get('accept-ranges') == 'bytes', 'Passthrough lost range support')
        require(headers.get('last-modified') == 'Thu, 01 Oct 2026 00:00:00 GMT', 'Passthrough lost Last-Modified')
    require(headers.get('set-cookie') == ('savings-fixture=1; Path=/' if case == 'set-cookie' else None),
            'Cookie header was incorrectly added or removed')


def validate_delta(before, after, origin, delivered, image_saved, cache_saved, images=0, hits=0):
    expected = {'originBytes': origin, 'deliveredBytes': delivered,
                'compressionBytesSaved': image_saved, 'cacheBytesSaved': cache_saved,
                'savedBytes': image_saved + cache_saved, 'compressedImages': images, 'cacheHits': hits}
    delta = {key: after[key] - before[key] for key in COUNTERS}
    require(delta == expected, f'Incorrect savings/body accounting: expected {expected}, observed {delta}')
    require(after['savedBytes'] == after['cacheBytesSaved'] + after['compressionBytesSaved'],
            'Total savings double-count or omit component counters')
    return delta


def cache_usage():
    state = wait_for('current cache usage', lambda: (lambda state:
                     state if state['cache']['measured'] and state['cache']['usageIsCurrent']
                     and not state['cache']['pendingMaintenance'] else None)(cli('status')))
    usage = state['cache']
    require(not usage['measurementError'] and not usage['maintenanceError'], 'Cache measurement failed')
    return {key: usage[key] for key in ('usedBytes', 'entryCount')}


def restore_settings(original, fields, pid):
    patch_settings({key: original[key] for key in fields})
    after = cli('status')
    require(after['settings'] == original, 'Visible saved settings were not fully restored')
    require(after['running'] and after['settings']['lanAuthEnabled'], 'Restored proxy/auth not running')
    require(service_pid() == pid, 'Test replaced the installed daemon process')


def traffic(args):
    pid, initial = guest_guard(root=True)
    require(args.jpeg is not None, 'Traffic acceptance requires --jpeg')
    jpeg = args.jpeg.read_bytes()
    require(32768 < len(jpeg) <= 8 * 1024 * 1024,
            'Fixture must be larger than 32 KiB and at most the 8 MiB response limit')
    dimensions = jpeg_dimensions(jpeg)
    original = initial['settings']
    require(original['cacheLimitGib'] > 0 and original['cacheMaxObjectMib'] * 1024 * 1024 >= len(jpeg),
            'Existing cache object limit must fit the fixture; test does not resize/clear existing cache')
    require(f'{ORIGIN}/32' not in command('ip', '-4', 'address', 'show', 'dev', 'lo'),
            'Fixture alias already exists; refusing to take ownership')
    require(bool(args.https_host) == bool(args.tls_fixture_dir),
            'Supply both --https-host and --tls-fixture-dir for HTTPS acceptance')
    tls_context = origin_tls = None
    if args.https_host:
        require(original['httpsMode'] == 'inspect' and original['httpsClientTrustAcknowledged']
                and (original.get('httpsInspectionScope') == 'allSupportedHosts'
                     or args.https_host in original['httpsInspectHosts'])
                and args.https_host not in original['httpsBypassHosts'],
                'Controller must preconfigure saved Inspect scope/trust for the fixture host')
        require({entry[4][0] for entry in socket.getaddrinfo(
            args.https_host, 443, type=socket.SOCK_STREAM)} == {ORIGIN},
            'HTTPS fixture must resolve exclusively to the guest-only alias')
        origin_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        origin_tls.load_cert_chain(args.tls_fixture_dir / 'origin.crt', args.tls_fixture_dir / 'origin.key')
        certificate = cli('tls', 'export', '--format', 'pem').get('certificate')
        require(isinstance(certificate, str) and certificate.startswith('-----BEGIN CERTIFICATE-----')
                and 'PRIVATE KEY' not in certificate, 'Canonical CLI must export only public CA')
        tls_context = ssl.create_default_context(cadata=certificate)
    report = {'outcome': 'FAIL', 'checks': [], 'cleanup': [], 'systemdPid': pid,
              'packageVersion': command('dpkg-query', '-W', '-f=${Version}', 'homeproxy').strip(),
              'installedDaemonSha256': hashlib.sha256(Path('/usr/bin/homeproxyd').read_bytes()).hexdigest(),
              'jpegSha256': hashlib.sha256(jpeg).hexdigest(), 'jpegBytes': len(jpeg),
              'jpegDimensions': dimensions,
              'scope': 'real installed HTTP; guest loopback client; guest-only origin alias',
              'untested': ['HTTPS Inspect JPEG savings: controller TLS fixture/trust setup required',
                           'Native dashboard/settings/icon: use separate --gui-check and desktop icon QA',
                           'LAN authentication handshake; enabled saved policy checked, loopback bypass is intentional']}
    if args.https_host:
        report['untested'].pop(0)
        report['scope'] = 'real installed HTTP + validating HTTPS Inspect; guest loopback client; guest-only origins'
    server = tls_server = None
    alias_added = settings_changed = False
    failure = None
    token = uuid.uuid4().hex
    try:
        command('ip', 'address', 'add', f'{ORIGIN}/32', 'dev', 'lo')
        alias_added = True
        server = Origin((ORIGIN, 80), OriginHandler)
        server.jpeg, server.cases, server.hits, server.lock = jpeg, {}, {}, threading.Lock()
        server.request_controls = {}
        threading.Thread(target=server.serve_forever, daemon=True).start()
        if origin_tls:
            tls_server = Origin((ORIGIN, 443), OriginHandler)
            tls_server.jpeg, tls_server.cases = server.jpeg, server.cases
            tls_server.hits, tls_server.lock = server.hits, server.lock
            tls_server.request_controls = server.request_controls
            tls_server.socket = origin_tls.wrap_socket(tls_server.socket, server_side=True)
            threading.Thread(target=tls_server.serve_forever, daemon=True).start()
            # Validate controller origin trust/hostname without fetching any fixture body.
            with socket.create_connection((ORIGIN, 443), 8) as probe:
                with ssl.create_default_context().wrap_socket(probe, server_hostname=args.https_host):
                    pass
        settings_changed = True  # An apply can mutate successfully before its reply fails.
        patch_settings({'cacheMode': 'online', 'cacheEnabled': False, 'compressionPreset': 'balanced',
                        'responseBufferLimitMib': 8, 'responseBufferBudgetMib': 64})

        def request(label, path, case='public', transformed=False, hit=False, cookie=False, no_transform=False):
            before = cli('status')['stats']
            prior_hits = server.hits.get(path, 0)
            server.cases[path] = case
            result = exchange(original['proxyPort'], path, cookie, no_transform,
                              args.https_host if scheme == 'https' else None, tls_context)
            validate_response(result, jpeg, dimensions, transformed, case)
            delivered = len(result['body'])
            after = wait_for('complete response counters', lambda: (lambda value:
                             value if value['deliveredBytes'] >= before['deliveredBytes'] + delivered
                             else None)(cli('status')['stats']))
            delta = validate_delta(before, after, 0 if hit else len(jpeg), delivered,
                                   len(jpeg) - delivered if transformed and not hit else 0,
                                   delivered if hit else 0, images=int(transformed and not hit), hits=int(hit))
            require(server.hits.get(path, 0) == prior_hits + int(not hit), 'Origin request ledger disagrees with HIT')
            if no_transform:
                require(server.request_controls.get(path) == 'no-transform',
                        'Proxy removed request no-transform before forwarding to origin')
            cache_header = result['headers'].get('cache-status', '')
            if hit:
                require('HomeProxy; hit' in cache_header, 'Missing explicit HomeProxy HIT evidence')
            else:
                require('HomeProxy; hit' not in cache_header, 'Origin GET was mislabeled as HIT')
            require(cli('status')['settings']['lanAuthEnabled'], 'Traffic test disabled LAN auth')
            report['checks'].append({'name': label, 'scheme': scheme, 'delta': delta, 'bodyBytes': delivered,
                                     'bodySha256': hashlib.sha256(result['body']).hexdigest(),
                                     'cacheStatus': cache_header, 'originRequestsForPath': server.hits.get(path, 0)})
            return result

        for scheme in ('http', 'https') if args.https_host else ('http',):
            patch_settings({'cacheEnabled': False, 'compressionPreset': 'balanced',
                            'responseBufferLimitMib': 8, 'responseBufferBudgetMib': 64})
            usage = cache_usage()
            path = f'/savings-{token}-{scheme}/disabled-balanced.jpg'
            first = request('cache disabled + Balanced transforms JPEG', path, transformed=True)
            second = request('cache disabled repeat returns to origin', path, transformed=True)
            require(first['body'] == second['body'], 'Repeated deterministic transformation changed output')
            require(cache_usage() == usage, 'Cache-disabled transformations stored fixture data')

            patch_settings({'cacheEnabled': True, 'compressionPreset': 'off'})
            path = f'/savings-{token}-{scheme}/cache-off.jpg'
            first = request('cache enabled + Off first MISS', path)
            require('HomeProxy; fwd=miss; stored' in first['headers'].get('cache-status', ''), 'Cold public body was not stored')
            second = request('cache enabled + Off HIT saves exact original bytes', path, hit=True)
            require(first['body'] == second['body'], 'Cache HIT changed original bytes')

            patch_settings({'compressionPreset': 'balanced'})
            path = f'/savings-{token}-{scheme}/cache-balanced.jpg'
            first = request('cache enabled + Balanced MISS transforms once', path, transformed=True)
            require('HomeProxy; fwd=miss; stored' in first['headers'].get('cache-status', ''), 'Transformed body was not stored')
            second = request('compressed cache HIT counts cache savings without recompression', path, transformed=True, hit=True)
            require(first['body'] == second['body'], 'Compressed HIT changed stored representation')

            usage = cache_usage()
            request('request no-transform bypasses warmed transformed cache with zero savings',
                    path, no_transform=True)
            require(cache_usage() == usage, 'Request no-transform changed stored representation')
            # Existing transformed cache remains available to ordinary requests.
            request('ordinary GET still reuses transformed cache after no-transform bypass',
                    path, transformed=True, hit=True)

            # no-transform permits public storage; a subsequent HIT legitimately saves cache bytes.
            request('no-transform preserves JPEG and reports no image savings',
                    f'/savings-{token}-{scheme}/no-transform.jpg', case='no-transform')
            for case in ('no-store', 'private', 'set-cookie', 'request-cookie'):
                usage = cache_usage()
                path = f'/savings-{token}-{scheme}/{case}.jpg'
                for attempt in range(2):
                    request(f'{case} bypass {attempt + 1}: original bytes and zero savings', path,
                            case=case, cookie=case == 'request-cookie')
                require(cache_usage() == usage, f'{case} incorrectly stored private fixture data')

            patch_settings({'cacheEnabled': False, 'compressionPreset': 'off'})
            request('cache disabled + compression Off yields original and zero savings', f'/savings-{token}-{scheme}/off.jpg')
            for label, limits in (('zero response limit', (0, 64)), ('zero total budget', (0, 0))):
                patch_settings({'compressionPreset': 'balanced', 'responseBufferLimitMib': limits[0],
                                'responseBufferBudgetMib': limits[1]})
                usage = cache_usage()
                request(f'{label} streams original JPEG without savings', f'/savings-{token}-{scheme}/{limits[1]}-zero.jpg')
                require(cache_usage() == usage, 'Zero buffers unexpectedly stored response')
        final_stats = cli('status')['stats']
        report['finalCounters'] = {key: final_stats[key] for key in COUNTERS}
    except BaseException as error:
        # Our assertion messages contain only fixture evidence; avoid raw unknown exception text.
        failure = error
        report['failure'] = str(error) if isinstance(error, AssertionError) else type(error).__name__
    finally:
        errors = []
        actions = []
        if settings_changed:
            actions.append(('restore modified settings / full equality / same PID',
                            lambda: restore_settings(original, FIELDS, pid)))
        if server is not None:
            actions.append(('stop guest fixture HTTP server', lambda: (server.shutdown(), server.server_close())))
        if tls_server is not None:
            actions.append(('stop guest fixture HTTPS server', lambda: (tls_server.shutdown(), tls_server.server_close())))
        if alias_added:
            def remove_alias():
                command('ip', 'address', 'del', f'{ORIGIN}/32', 'dev', 'lo')
                require(f'{ORIGIN}/32' not in command('ip', '-4', 'address', 'show', 'dev', 'lo'),
                        'Guest loopback alias remains after cleanup')
            actions.append(('remove guest loopback alias', remove_alias))
        for label, action in actions:
            try:
                action()
                report['cleanup'].append({'name': label, 'ok': True})
            except Exception:
                errors.append(label)
                report['cleanup'].append({'name': label, 'ok': False})
        if errors:
            failure = AssertionError('Cleanup failed: ' + ', '.join(errors))
            report['cleanupFailure'] = str(failure)
        if failure is None:
            report['outcome'] = 'PASS'
        write_report(args.report, report)
    require(failure is None, report.get('cleanupFailure', report.get('failure', 'Acceptance failed')))
    print(json.dumps({'outcome': report['outcome'], 'checks': len(report['checks']), 'report': str(args.report)}))


def gui_module():
    spec = importlib.util.spec_from_file_location('savings_gui', Path(__file__).with_name('test-linux-gui-vm.py'))
    require(spec is not None and spec.loader is not None, 'Native GUI helper missing')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gui_check(args):
    pid, initial = guest_guard(root=False)
    helper = gui_module()
    helper.check_environment()
    args.report.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    gui = helper.NativeGui(args.report.parent)
    report = {'outcome': 'FAIL', 'systemdPid': pid, 'checks': [], 'untested': ['Desktop shell/window icon visual QA']}
    original = initial['settings']
    changed = False
    failure = None
    try:
        gui.open()
        gui.page('home')
        # Format with the browser's selected locale, matching the real displayed units.
        expected = cli('status')['stats']
        values = [expected[key] for key in ('savedBytes', 'compressionBytesSaved', 'cacheBytesSaved')]
        formatted = gui.js('''const l=document.documentElement.lang.startsWith("cs")?"cs-CZ":"en-US";
            return arguments[0].map(b=>{let v=b,u="B",d=0;
            if(b>=1024**3){v=b/1024**3;u="GB";d=2}else if(b>=1024**2){v=b/1024**2;u="MB";d=1}
            else if(b>=1024){v=b/1024;u="KB";d=1}
            return v.toLocaleString(l,{maximumFractionDigits:d})+" "+u});''', values)
        def rendered():
            actual = gui.js('return ["saved-total","image-saving","cache-saving"].map(id=>'
                            'document.getElementById(id).textContent.trim().replace(/\\s+/g," "))')
            return actual if actual == [value.replace('\u00a0', ' ') for value in formatted] else None
        displayed = helper.wait_for('dashboard savings match canonical daemon counters', rendered)
        require(values[0] == values[1] + values[2], 'Dashboard total source double-counted savings')
        saved_status = gui.js('return document.getElementById("savings-status").textContent.trim()')
        require(saved_status, 'Dashboard saved optimization status is missing')
        gui.shot('savings-dashboard', '#saved-total')
        report['checks'].append({'name': 'native dashboard displays exact formatted service savings',
                                 'displayed': displayed, 'bytes': values, 'savedStatus': saved_status})
        gui.page('settings')
        alternative = 'off' if original['compressionPreset'] != 'off' else 'balanced'
        gui.click(f'[data-setting="compressionPreset"] [data-value="{alternative}"]')
        helper.wait_for('compression draft exposes pending save', lambda: gui.js(
            'return !document.getElementById("settings-savebar").hidden && '
            '!document.getElementById("save-settings").disabled'))
        require(cli('status')['settings'] == original, 'Unsaved compression draft changed daemon settings')
        gui.shot('savings-settings-pending', '#settings-savebar')
        gui.page('home')
        require(gui.js('return document.getElementById("savings-status").textContent.trim()') == saved_status,
                'Dashboard optimization status follows pending draft instead of saved settings')
        gui.shot('savings-dashboard-pending', '#savings-status')
        gui.page('settings')
        changed = True
        gui.click('#save-settings')
        helper.wait_for('GUI compression persisted', lambda:
                        cli('status')['settings']['compressionPreset'] == alternative)
        helper.wait_for('GUI saved state', lambda: gui.js('return document.getElementById("settings-savebar").hidden'))
        gui.shot('savings-settings-saved', '[data-setting="compressionPreset"]')
        gui.page('home')
        helper.wait_for('dashboard optimization status follows persisted compression', lambda:
                        gui.js('return document.getElementById("savings-status").textContent.trim()') != saved_status)
        gui.shot('savings-dashboard-saved', '#savings-status')
        report['checks'].append({'name': 'native pending compression is separate from persisted setting'})
    except BaseException as error:
        failure = error
        report['failure'] = str(error) if isinstance(error, AssertionError) else type(error).__name__
    finally:
        errors = []
        if changed:
            try:
                restore_settings(original, ('compressionPreset',), pid)
            except Exception:
                errors.append('restore compression settings')
        try:
            gui.cleanup()
        except Exception:
            errors.append('close native GUI')
        if errors:
            failure = AssertionError('Cleanup failed: ' + ', '.join(errors))
            report['cleanupFailure'] = str(failure)
        if failure is None:
            report['outcome'] = 'PASS'
        write_report(args.report, report)
    require(failure is None, report.get('cleanupFailure', report.get('failure', 'Native GUI check failed')))
    print(json.dumps({'outcome': report['outcome'], 'checks': len(report['checks']), 'report': str(args.report)}))


class SelfTests(unittest.TestCase):
    def counters(self):
        return {key: 0 for key in COUNTERS}

    def test_transformed_miss_counts_image_only(self):
        before, after = self.counters(), self.counters()
        after.update(originBytes=100, deliveredBytes=40, compressionBytesSaved=60,
                     savedBytes=60, compressedImages=1)
        validate_delta(before, after, 100, 40, 60, 0, images=1)

    def test_compressed_hit_does_not_repeat_image_savings(self):
        before, after = self.counters(), self.counters()
        after.update(deliveredBytes=40, cacheBytesSaved=40, savedBytes=40, cacheHits=1)
        validate_delta(before, after, 0, 40, 0, 40, hits=1)
        after.update(compressionBytesSaved=60, savedBytes=100)
        with self.assertRaisesRegex(AssertionError, 'Incorrect savings'):
            validate_delta(before, after, 0, 40, 0, 40, hits=1)

    def test_cache_savings_require_origin_bytes_zero(self):
        after = self.counters()
        after.update(deliveredBytes=40, originBytes=100, cacheBytesSaved=40, savedBytes=40, cacheHits=1)
        with self.assertRaisesRegex(AssertionError, 'Incorrect savings'):
            validate_delta(self.counters(), after, 0, 40, 0, 40, hits=1)

    def test_setting_scope_rejects_auth_changes_before_cli(self):
        with mock.patch(__name__ + '.cli') as installed:
            with self.assertRaisesRegex(AssertionError, 'outside savings'):
                patch_settings({'lanAuthEnabled': False})
            installed.assert_not_called()

    def test_invalid_jpeg_rejected_before_decode(self):
        with self.assertRaisesRegex(AssertionError, 'JPEG envelope'):
            jpeg_dimensions(b'not-a-jpeg')

    def test_transformed_stale_validator_rejected(self):
        original = b'original-image'
        result = {'status': 200, 'body': b'jpeg', 'headers': {
            'content-type': 'image/jpeg', 'content-length': '4',
            'cache-control': 'public, max-age=3600', 'etag': 'stale'}}
        with mock.patch(__name__ + '.jpeg_dimensions', return_value=(10, 10)):
            with self.assertRaisesRegex(AssertionError, 'stale origin'):
                validate_response(result, original, (10, 10), True, 'public')

    def test_transformed_wire_evidence_does_not_require_internal_cache_marker(self):
        original = b'original-image'
        result = {'status': 200, 'body': b'jpeg', 'headers': {
            'content-type': 'image/jpeg', 'content-length': '4',
            'cache-control': 'public, max-age=3600'}}
        with mock.patch(__name__ + '.jpeg_dimensions', return_value=(10, 10)):
            validate_response(result, original, (10, 10), True, 'public')
            result['headers']['x-homeproxy-transformed'] = '1'
            with self.assertRaisesRegex(AssertionError, 'Internal cache marker'):
                validate_response(result, original, (10, 10), True, 'public')

    def test_restore_changes_only_owned_fields_then_checks_full_equality(self):
        original = {'compressionPreset': 'balanced', 'lanAuthEnabled': True, 'proxyPort': 9999}
        with mock.patch(__name__ + '.patch_settings') as patch, \
                mock.patch(__name__ + '.cli', return_value={'settings': dict(original), 'running': True}), \
                mock.patch(__name__ + '.service_pid', return_value=42):
            restore_settings(original, ('compressionPreset',), 42)
            patch.assert_called_once_with({'compressionPreset': 'balanced'})

    def test_restore_failure_cannot_pass_acceptance(self):
        original = {'compressionPreset': 'balanced', 'lanAuthEnabled': True}
        with mock.patch(__name__ + '.patch_settings'), \
                mock.patch(__name__ + '.cli', return_value={'settings': original, 'running': False}):
            with self.assertRaisesRegex(AssertionError, 'not running'):
                restore_settings(original, ('compressionPreset',), 42)

    def test_traffic_failure_and_interrupt_cleanup_never_report_pass(self):
        initial = {'settings': {'cacheLimitGib': 1, 'cacheMaxObjectMib': 1, 'proxyPort': 9999}}
        args = argparse.Namespace(jpeg=Path('/fixture.jpg'), report=Path('/report.json'),
                                  https_host=None, tls_fixture_dir=None)
        for interruption in (AssertionError('fixture request failed'), KeyboardInterrupt()):
            with self.subTest(interruption=type(interruption).__name__), \
                    mock.patch(__name__ + '.guest_guard', return_value=(42, initial)), \
                    mock.patch.object(Path, 'read_bytes', return_value=b'x' * 32769), \
                    mock.patch(__name__ + '.jpeg_dimensions', return_value=(100, 100)), \
                    mock.patch(__name__ + '.command', return_value=''), \
                    mock.patch(__name__ + '.Origin') as origin, \
                    mock.patch(__name__ + '.threading.Thread'), \
                    mock.patch(__name__ + '.patch_settings'), \
                    mock.patch(__name__ + '.cache_usage', return_value={}), \
                    mock.patch(__name__ + '.cli', return_value={'stats': self.counters()}), \
                    mock.patch(__name__ + '.exchange', side_effect=interruption), \
                    mock.patch(__name__ + '.restore_settings', side_effect=AssertionError('restore failed')), \
                    mock.patch(__name__ + '.write_report') as write:
                with self.assertRaisesRegex(AssertionError, 'Cleanup failed'):
                    traffic(args)
                report = write.call_args.args[1]
                self.assertEqual(report['outcome'], 'FAIL')
                self.assertEqual([check['ok'] for check in report['cleanup']], [False, True, True])
                origin.return_value.shutdown.assert_called_once()
                origin.return_value.server_close.assert_called_once()

    def test_http_request_no_transform_is_actually_sent(self):
        stream = mock.Mock()
        response = mock.Mock(status=200)
        response.getheaders.return_value = []
        response.read.return_value = b'body'
        with mock.patch(__name__ + '.socket.create_connection', return_value=stream), \
                mock.patch(__name__ + '.http.client.HTTPResponse', return_value=response):
            exchange(9999, '/warm.jpg', no_transform=True)
            request = stream.sendall.call_args.args[0]
            self.assertIn(b'Cache-Control: no-transform\r\n', request)
            self.assertIn(b'GET http://1.1.1.123/warm.jpg HTTP/1.1\r\n', request)
            stream.close.assert_called_once()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--ack-disposable-vm', action='store_true')
    parser.add_argument('--jpeg', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--gui-check', action='store_true')
    parser.add_argument('--https-host', help='Controller-prepared Inspect fixture hostname')
    parser.add_argument('--tls-fixture-dir', type=Path, help='Contains controller-supplied origin.crt and origin.key')
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        require(result.wasSuccessful(), 'Savings helper regression checks failed')
        return
    require(args.ack_disposable_vm and args.report is not None, 'Requires --ack-disposable-vm and --report')
    # Invalidate a previous PASS before any fallible host/input/service guard.
    write_report(args.report, {'outcome': 'FAIL', 'checks': [], 'phase': 'starting'})
    if args.gui_check:
        gui_check(args)
    else:
        traffic(args)


if __name__ == '__main__':
    main()
