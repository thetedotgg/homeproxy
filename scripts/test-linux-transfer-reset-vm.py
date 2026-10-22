#!/usr/bin/env python3
"""Transfer reset acceptance on installed HomeProxy in disposable homeproxy-qa.

Run as the graphical qa user on the existing Xorg :0 session. Uses the canonical
system service, NativeGui and authenticated LAN HTTP against a local chunked
origin. Pauses one response across reset, then resumes that same connection.
One separately reported control-socket access refusal checks keyboard recovery.
Owns one temporary public-IP loopback alias so private-destination protections
remain enabled. Never connects the fixture to the real internet. No dependencies,
service restarts, CA access or VM provisioning are performed.
"""

import argparse
import hashlib
import http.client
import http.server
import importlib.util
import inspect
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


spec = importlib.util.spec_from_file_location(
    'gui_fixture', Path(__file__).with_name('test-linux-gui-vm.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
require, wait_for, cli = fixture.require, fixture.wait_for, fixture.cli
CHUNK = b'homeproxy-transfer-reset-fixture\n' * 16384
ORIGIN_IP = '1.1.1.126'
ORIGIN_PORT = 8080


class ResetGui(fixture.NativeGui):
    """Record fixed selectors and W3C error codes, never WebDriver messages."""

    def __init__(self, artifacts, report):
        self.report = report
        super().__init__(artifacts)

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}', data=data, method=method,
            headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                return json.load(response)['value']
        except urllib.error.HTTPError as error:
            allowed = {'element click intercepted', 'element not interactable',
                       'invalid argument', 'invalid session id', 'javascript error',
                       'move target out of bounds', 'no such element', 'no such window',
                       'script timeout', 'session not created', 'stale element reference',
                       'timeout', 'unknown command', 'unknown error', 'unsupported operation'}
            code = 'unclassified'
            try:
                envelope = json.loads(error.read(128 * 1024))
                candidate = envelope.get('value', {}).get('error')
                if candidate in allowed:
                    code = candidate
            except (ValueError, TypeError, AttributeError):
                pass
            finally:
                error.close()
            self.report['webdriverError'] = {'httpStatus': error.code, 'code': code}
            fixture.write_json(self.artifacts / 'report.json', self.report)
            raise AssertionError(f'WebDriver {method} {path} failed: HTTP {error.code}, {code}') from None

    def click(self, selector):
        # All callers use source-owned static selectors, never field values.
        self.report['lastControl'] = selector
        fixture.write_json(self.artifacts / 'report.json', self.report)
        return super().click(selector)


def origin_alias_present():
    addresses = json.loads(fixture.command('ip', '-j', 'address', 'show'))
    return any(address.get('local') == ORIGIN_IP for interface in addresses
               for address in interface.get('addr_info', []))


def require_local_origin_route():
    routes = json.loads(fixture.command('ip', '-j', 'route', 'get', ORIGIN_IP))
    require(bool(routes) and all(route.get('type') == 'local' and route.get('dev') == 'lo'
                               for route in routes),
            'Fixture origin must have an explicitly local loopback route')


def receive_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        data = stream.recv(size - len(result))
        require(bool(data), 'Canonical control response ended early')
        result.extend(data)
    return bytes(result)


def desktop_snapshot():
    """Privileged settings stay in memory, including secrets needed for restore."""
    payload = json.dumps({'version': 1, 'command': {'method': 'desktop_snapshot'}}).encode()
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(35)
        stream.connect(str(fixture.SOCKET))
        stream.sendall(struct.pack('!I', len(payload)) + payload)
        size = struct.unpack('!I', receive_exact(stream, 4))[0]
        require(0 < size <= 32 * 1024 * 1024, 'Invalid canonical control frame size')
        value = json.loads(receive_exact(stream, size))
    require(value.get('version') == 1 and 'Ok' in value.get('result', {}),
            'Canonical desktop snapshot failed')
    return value['result']['Ok']


def apply_patch(patch):
    # Credentials are sent through stdin, never argv, files or logs.
    result = subprocess.run(['/usr/bin/homeproxy', '--json', 'config', 'apply', '--stdin'],
                            input=json.dumps(patch), text=True, capture_output=True, timeout=35)
    require(result.returncode == 0, 'Canonical settings patch failed')
    value = json.loads(result.stdout)
    require(value.get('ok', True), 'Canonical settings patch returned an error')


class ChunkedOrigin:
    def __init__(self):
        self.resume = threading.Event()
        self.sent = threading.Event()
        self.finished = threading.Event()
        self.failures = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def do_GET(self):
                try:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Transfer-Encoding', 'chunked')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(f'{len(CHUNK):x}\r\n'.encode() + CHUNK + b'\r\n')
                    self.wfile.flush()
                    owner.sent.set()
                    if not owner.resume.wait(180):
                        owner.failures.append('origin-pause-timeout')
                        return
                    self.wfile.write(f'{len(CHUNK):x}\r\n'.encode() + CHUNK + b'\r\n0\r\n\r\n')
                    self.wfile.flush()
                except (OSError, ValueError):
                    owner.failures.append('origin-transport-error')
                finally:
                    owner.finished.set()

        require_local_origin_route()
        self.server = http.server.ThreadingHTTPServer((ORIGIN_IP, ORIGIN_PORT), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.resume.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def open_authenticated_transfer(ip, port, username, password, origin_port):
    require_local_origin_route()
    uri = f'http://{ORIGIN_IP}:{origin_port}/transfer-reset.bin'

    def connect(authorization=None):
        require_local_origin_route()
        stream = socket.socket()
        stream.settimeout(35)
        # A non-loopback source makes LAN Digest authentication mandatory.
        stream.bind((ip, 0))
        try:
            stream.connect((ip, port))
            auth = f'Proxy-Authorization: {authorization}\r\n' if authorization else ''
            request = (f'GET {uri} HTTP/1.1\r\nHost: {ORIGIN_IP}:{origin_port}\r\n'
                       f'{auth}Connection: close\r\n\r\n')
            stream.sendall(request.encode())
            response = http.client.HTTPResponse(stream)
            response.begin()
            return stream, response
        except BaseException:
            stream.close()
            raise

    challenge_socket, challenge = connect()
    try:
        require(challenge.status == 407, 'LAN request without credentials was not rejected')
        raw = challenge.getheader('Proxy-Authenticate', '')
        require(raw.startswith('Digest '), 'Canonical proxy did not offer Digest authentication')
        params = urllib.request.parse_keqv_list(urllib.request.parse_http_list(raw[7:]))
        require(params.get('algorithm', 'MD5') == 'MD5' and params.get('qop') == 'auth',
                'Unexpected fixture Digest authentication scheme')
    finally:
        challenge.close()
        challenge_socket.close()
    digest = lambda value: hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()
    nonce, realm, cnonce = params['nonce'], params['realm'], secrets.token_hex(12)
    answer = digest(f'{digest(f"{username}:{realm}:{password}")}:{nonce}:00000001:'
                    f'{cnonce}:auth:{digest(f"GET:{uri}")}')
    auth = (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{answer}", algorithm=MD5, qop=auth, '
            f'nc=00000001, cnonce="{cnonce}"')
    stream, response = connect(auth)
    try:
        require(response.status == 200,
                f'Authenticated fixture request did not succeed (HTTP {response.status})')
        require(response.read(len(CHUNK)) == CHUNK, 'First fixture chunk did not arrive')
    except BaseException:
        response.close()
        stream.close()
        raise
    return stream, response


def stable_stats(stats):
    # Rates and live ages naturally change with wall time; lifetime identity and
    # byte/count fields must remain identical while the origin is paused.
    volatile = {'uploadBytesPerSecond', 'downloadBytesPerSecond', 'ageMs', 'idleMs'}

    def strip(value):
        if isinstance(value, dict):
            return {key: strip(item) for key, item in value.items() if key not in volatile}
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    return strip({key: value for key, value in stats.items()
                  if key not in {'uploadBytes', 'downloadBytes', 'transferStatsResetUnixMs'}})


def assert_invariants(before, after, history, pid):
    require(after['running'] and fixture.service_pid() == pid, 'Reset interrupted canonical daemon')
    for key in ('settings', 'revision', 'quotaStatuses', 'usageHistory'):
        require(before[key] == after[key], f'Reset changed {key}')
    require(cli('history', 'status') == history, 'Reset changed canonical usage history')
    require(stable_stats(before['stats']) == stable_stats(after['stats']),
            'Reset changed lifetime savings, clients, activity or connection state')


def raw_totals():
    metrics = cli('diagnostics', 'export')['current']['metrics']
    require(metrics['trafficAvailable'], 'Raw diagnostic accounting is unavailable')
    return {key: metrics[key] for key in ('uploadBytes', 'downloadBytes')}


def fd_bound_socket_chmod(path, identity, expected_mode, desired_mode, before_chmod=None):
    """Validate an O_PATH socket descriptor and chmod that inode, never its path."""
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        actual = (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
        if not stat.S_ISSOCK(metadata.st_mode) or actual != identity:
            raise ValueError('Socket descriptor identity mismatch')
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ValueError('Socket descriptor mode mismatch')
        if before_chmod is not None:
            before_chmod(fd)
        # fchmod rejects O_PATH descriptors. Linux procfs dereferences this
        # descriptor to the pinned inode even if its original path is replaced.
        os.chmod(f'/proc/self/fd/{fd}', desired_mode)
        if stat.S_IMODE(os.fstat(fd).st_mode) != desired_mode:
            raise ValueError('Socket descriptor chmod verification failed')
    finally:
        os.close(fd)


def socket_chmod_helper_source():
    # Both the elevated helper and isolated self-test use this exact function.
    return ('import os, stat, sys\n' + inspect.getsource(fd_bound_socket_chmod)
            + '\nfd_bound_socket_chmod(sys.argv[1], tuple(map(int, sys.argv[2:6])), '
              'int(sys.argv[6]), int(sys.argv[7]))\n')


def self_test_socket_chmod():
    """Own temporary sockets only; exercise the real fd/procfs race boundary."""
    with tempfile.TemporaryDirectory(prefix='homeproxy-socket-chmod-') as directory:
        root = Path(directory)
        original = root / 'control.sock'
        saved = root / 'original.sock'
        foreign = root / 'foreign.sock'
        link = root / 'link.sock'
        with socket.socket(socket.AF_UNIX) as owned, socket.socket(socket.AF_UNIX) as other:
            owned.bind(str(original))
            other.bind(str(foreign))
            os.chmod(original, 0o660)
            os.chmod(foreign, 0o600)
            identity = ControlSocketModeGuard.identity_of(original.lstat())
            source = socket_chmod_helper_source()
            for expected, desired in ((0o660, 0o600), (0o600, 0o660)):
                result = subprocess.run([sys.executable, '-c', source, str(original),
                                         *(str(item) for item in identity), str(expected), str(desired)],
                                        capture_output=True, timeout=10)
                require(result.returncode == 0 and stat.S_IMODE(original.stat().st_mode) == desired,
                        'FD-bound normal deny/restore helper failed')

            def rejects(path, expected_identity, expected_mode):
                before = stat.S_IMODE(path.stat().st_mode)
                try:
                    fd_bound_socket_chmod(path, expected_identity, expected_mode, 0o640)
                except ValueError:
                    require(stat.S_IMODE(path.stat().st_mode) == before,
                            'Rejected descriptor validation changed socket mode')
                else:
                    raise AssertionError('Wrong inode, symlink or mode was accepted')

            rejects(foreign, identity, 0o600)
            link.symlink_to(original)
            rejects(link, identity, 0o660)
            rejects(original, identity, 0o600)

            with socket.socket(socket.AF_UNIX) as replacement:
                def replace_after_fstat(fd):
                    require(ControlSocketModeGuard.identity_of(os.fstat(fd)) == identity,
                            'Race self-test did not capture the original socket descriptor')
                    original.rename(saved)
                    replacement.bind(str(original))
                    os.chmod(original, 0o600)

                fd_bound_socket_chmod(original, identity, 0o660, 0o640, replace_after_fstat)
                require(stat.S_IMODE(saved.stat().st_mode) == 0o640,
                        'Race chmod did not change the pinned original inode')
                require(stat.S_IMODE(original.stat().st_mode) == 0o600,
                        'Race chmod changed the replacement socket')
    print('PASS fd-bound socket chmod: normal deny/restore; wrong inode/symlink/mode rejected; '
          'path replacement leaves foreign socket unchanged', flush=True)
    return 0


class ControlSocketModeGuard:
    """Own a temporary mode change only on the recorded canonical socket inode."""

    def __init__(self, report):
        self.report = report
        metadata = fixture.SOCKET.lstat()
        require(stat.S_ISSOCK(metadata.st_mode), 'Canonical control endpoint must be a real socket')
        require(metadata.st_uid != os.geteuid(), 'QA must not own the canonical control socket')
        self.mode = stat.S_IMODE(metadata.st_mode)
        require(self.mode == 0o660, 'Canonical control socket must initially have mode 0660')
        self.identity = self.identity_of(metadata)
        self.changed = False

    @staticmethod
    def identity_of(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)

    def guarded_metadata(self):
        metadata = fixture.SOCKET.lstat()
        require(stat.S_ISSOCK(metadata.st_mode) and self.identity_of(metadata) == self.identity,
                'Canonical socket identity changed; refusing to chmod another inode')
        return metadata

    def deny(self):
        require(stat.S_IMODE(self.guarded_metadata().st_mode) == self.mode,
                'Canonical socket mode changed before the owned access-denial test')
        # Record responsibility before chmod: even a failing command must trigger
        # a guarded attempt to restore this exact inode in either finally block.
        self.changed = True
        self.report['restoredSocketMode'] = False
        self.chmod_descriptor(self.mode, 0o600)
        require(stat.S_IMODE(self.guarded_metadata().st_mode) == 0o600,
                'Owned control-socket denial mode was not applied')

    def restore(self):
        metadata = self.guarded_metadata()
        if self.changed and stat.S_IMODE(metadata.st_mode) != self.mode:
            self.chmod_descriptor(0o600, self.mode)
        require(stat.S_IMODE(self.guarded_metadata().st_mode) == self.mode,
                'Canonical control-socket mode was not restored')
        self.changed = False
        self.report['restoredSocketMode'] = True

    def chmod_descriptor(self, expected_mode, desired_mode):
        fixture.command('sudo', '-n', '/usr/bin/python3', '-c', socket_chmod_helper_source(),
                        str(fixture.SOCKET), *(str(item) for item in self.identity),
                        str(expected_mode), str(desired_mode))


def clear_denial_observers(gui):
    gui.js('''
      const q=window.__resetDenialQa;
      if(q) {
        q.observer.disconnect();
        q.button.removeEventListener('click',q.onClick);
        q.button.removeEventListener('focusin',q.onFocus);
        delete window.__resetDenialQa;
      }
    ''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test-socket-chmod', action='store_true',
                        help='Isolated Linux filesystem race test; does not use a VM or service')
    parser.add_argument('--ack-disposable-vm', action='store_true', help='Required for native VM QA')
    parser.add_argument('--artifacts', type=Path, help='Required new artifact directory for native VM QA')
    args = parser.parse_args()
    if args.self_test_socket_chmod:
        return self_test_socket_chmod()
    if not args.ack_disposable_vm or args.artifacts is None:
        parser.error('native VM QA requires --ack-disposable-vm and --artifacts')
    require(socket.gethostname() == 'homeproxy-qa', 'Requires disposable homeproxy-qa VM')
    fixture.check_environment()
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=False, mode=0o700)
    artifacts.chmod(0o700)
    report = {'result': 'running', 'phase': 'setup', 'lastControl': None,
              'display': ':0', 'displayServer': 'Xorg',
              'checks': [], 'controlAccessChecks': [], 'restoredSettings': False,
              'restoredSocketMode': False,
              'localOriginAddress': ORIGIN_IP, 'localOriginPort': ORIGIN_PORT,
              'removedOwnedOriginAlias': False,
              'binarySha256': {name: hashlib.sha256(Path('/usr/bin', name).read_bytes()).hexdigest()
                               for name in ('klidna-sit', 'homeproxyd', 'homeproxy')}}
    fixture.write_json(artifacts / 'report.json', report)
    gui = origin = stream = response = None
    restore = None
    original_locale = original_rect = None
    draft_changed = False
    # Record ownership intent before mutation; only successful atomic add grants
    # cleanup ownership. A pre-existing alias (on any interface) is never touched.
    origin_alias_owned = False
    socket_mode_guard = None
    error = None

    def phase(label):
        report['phase'] = label
        fixture.write_json(artifacts / 'report.json', report)

    def passed(label, control_access=False):
        report['controlAccessChecks' if control_access else 'checks'].append(label)
        fixture.write_json(artifacts / 'report.json', report)
        print('PASS ' + label, flush=True)

    def visible_zero():
        return gui.js('return ["upload","download"].every(k=>'
                      'document.querySelector("#"+k+"-total").textContent==="0 B")')

    def confirmation():
        require(gui.js('''
          const home=document.querySelector('#home-page');
          const reset=document.querySelector('#traffic-reset');
          return !!home && home.classList.contains('is-active') && !!reset
            && reset.getClientRects().length>0;
        '''), 'Reset confirmation requires active Home page and a visible reset control')
        gui.click('#traffic-reset')
        wait_for('reset opens with Cancel focused', lambda: gui.js(
            'return !document.querySelector("#traffic-reset-confirmation").hidden && '
            'document.activeElement.id==="traffic-reset-cancel"'))

    def cancelled():
        wait_for('confirmation closes and reset receives focus', lambda: gui.js(
            'return document.querySelector("#traffic-reset-confirmation").hidden && '
            'document.activeElement.id==="traffic-reset"'))

    try:
        initial = desktop_snapshot()
        original_settings = initial['settings']
        require(initial['running'] and original_settings['enabled'],
                'Disposable test requires an already running, enabled canonical proxy')
        require(original_settings['httpsMode'] == 'tunnel', 'Disposable test requires Tunnel mode')
        require(not origin_alias_present(), 'Fixture public-IP alias is already assigned; refusing reuse')
        fixture.command('sudo', '-n', 'ip', 'address', 'add', f'{ORIGIN_IP}/32', 'dev', 'lo')
        origin_alias_owned = True
        require_local_origin_route()
        ip = next((item['ip'] for item in initial['availableAddresses'] if item['ip']), None)
        require(ip, 'Disposable guest requires a LAN IPv4 address for authenticated traffic')
        with socket.socket() as candidate:
            candidate.bind((ip, 0))
            port = candidate.getsockname()[1]
        fixture.PASSWORD = secrets.token_urlsafe(24)
        patch = {'lanEnabled': True, 'listenIp': ip, 'listenIps': [ip],
                 'proxyPort': port, 'lanAuthEnabled': True, 'proxyUsername': 'qa-transfer-reset',
                 'proxyPassword': fixture.PASSWORD, 'cacheEnabled': False, 'cacheMode': 'online',
                 'upstreamProxies': [], 'blockDomains': [], 'allowDomains': [], 'filterFeeds': [],
                 'deniedClientIps': [], 'deviceLimits': [], 'adblockMode': 'off'}
        restore = {key: original_settings[key] for key in patch}
        apply_patch(patch)
        wait_for('owned fixture settings active', lambda: cli('status')['running'] and
                 cli('status')['settings']['proxyPort'] == port)
        pid = fixture.service_pid()
        require(pid > 0, 'Canonical daemon has no PID')
        report['systemdMainPID'] = pid
        phase('native GUI startup')
        gui = ResetGui(artifacts, report)
        gui.open()
        original_locale = gui.js('return document.documentElement.lang')
        original_rect = gui.wd('GET', '/window/rect')
        gui.page('home')
        phase('authenticated chunked HTTP fixture')
        origin = ChunkedOrigin()
        stream, response = open_authenticated_transfer(
            ip, port, patch['proxyUsername'], fixture.PASSWORD, origin.server.server_port)
        wait_for('first origin chunk sent', origin.sent.is_set)
        before = cli('status')
        require(before['stats']['uploadBytes'] > 0 and before['stats']['downloadBytes'] >= len(CHUNK),
                'Real authenticated traffic did not populate transfer totals')
        require(before['stats']['activeConnections'] > 0, 'Fixture has no active proxy socket')
        wait_for('real traffic rendered', lambda: gui.js(
            'return document.querySelector("#download-total").textContent!=="0 B"'))
        passed('real LAN Digest authentication rejects anonymous and forwards fixture traffic')

        labels = {'cs': ('Vynulovat přenos', 'Od vynulování'),
                  'en': ('Reset traffic totals', 'Since reset')}
        for locale in ('cs', 'en'):
            phase(f'native locale {locale}')
            gui.click(f'[data-locale="{locale}"]')
            wait_for('native locale ' + locale, lambda: gui.js(
                'return document.documentElement.lang') == locale)
            # Locale selection reloads the installed application and can restore
            # its initial Guide route. Navigate using actual native UI again.
            gui.page('home')
            wait_for('localized Home reset is visible and enabled', lambda: gui.js('''
              const home=document.querySelector('#home-page');
              const reset=document.querySelector('#traffic-reset');
              return !!home && home.classList.contains('is-active') && !!reset
                && reset.getClientRects().length>0 && !reset.disabled;
            '''))
            require(gui.js('return document.querySelector("#traffic-reset").getAttribute("aria-label")')
                    == labels[locale][0], 'Reset accessible label is not localized')
            for width in (760, 1180):
                phase(f'confirmation cancellation {locale} viewport {width}')
                gui.wd('POST', '/window/rect', {'width': width, 'height': 860})
                # Set actual content viewport, accounting for window decorations.
                inner = gui.js('return window.innerWidth')
                rect = gui.wd('GET', '/window/rect')
                gui.wd('POST', '/window/rect', {'width': rect['width'] + width - inner, 'height': 860})
                wait_for('viewport width', lambda: gui.js('return window.innerWidth') == width)
                confirmation()
                require(gui.js('''
                  const ids=['traffic-reset','traffic-reset-cancel','traffic-reset-confirm'];
                  return document.documentElement.scrollWidth<=window.innerWidth+1 && ids.every(id=>{
                    const r=document.getElementById(id).getBoundingClientRect();
                    return r.width>0 && r.left>=0 && r.right<=window.innerWidth+1;
                  });'''), 'Reset controls overflow native viewport')
                gui.shot(f'reset-confirmation-{locale}-{width}', '#traffic-reset-confirmation')
                gui.keys(['\ue00c'])
                cancelled()
                confirmation()
                gui.click('#traffic-reset-cancel')
                cancelled()
                require(cli('status')['stats']['transferStatsResetUnixMs'] ==
                        before['stats']['transferStatsResetUnixMs'], 'Cancel changed canonical reset timestamp')
        passed('CS/EN at 760/1180px: localized controls, screenshots, Escape/Cancel and restored focus')

        phase('real control-socket permission refusal keyboard recovery')
        refusal_before = cli('status')['stats']
        socket_mode_guard = ControlSocketModeGuard(report)
        confirmation()
        gui.js('document.querySelector("#traffic-reset-confirm").scrollIntoView({block:"center"})')
        prepared_confirm = gui.element('#traffic-reset-confirm')
        report['lastControl'] = '#traffic-reset-confirm'
        # Capture trusted input/focus and wait for a fresh normal poll render,
        # providing nearly a full poll interval for the bounded denial attempt.
        gui.js('''
          const button=document.querySelector('#traffic-reset-confirm');
          const q={button,trustedClick:false,confirmFocusEvents:0,renderSeen:false};
          q.onClick=event=>{q.trustedClick=event.isTrusted;};
          q.onFocus=()=>{q.confirmFocusEvents++;};
          button.addEventListener('click',q.onClick);
          button.addEventListener('focusin',q.onFocus);
          q.observer=new MutationObserver(()=>{q.renderSeen=true;q.observer.disconnect();});
          q.observer.observe(document.querySelector('#upload-total'),{childList:true});
          window.__resetDenialQa=q;
        ''')
        try:
            wait_for('next normal poll render before access denial', lambda: gui.js(
                'return window.__resetDenialQa.renderSeen'), timeout=3)
            socket_mode_guard.deny()
            # Use the prepared native element directly: no extra selector,
            # scroll, enabled-wait or JavaScript click during the deny interval.
            gui.wd('POST', f'/element/{prepared_confirm}/click', {})
            wait_for('reset action refused with trusted input, action error and Confirm focus', lambda: gui.js('''
              const q=window.__resetDenialQa;
              const notice=document.querySelector('#notice');
              return q.trustedClick && q.confirmFocusEvents>0
                && !notice.hidden && notice.dataset.kind==='error' && notice.dataset.source==='action'
                && document.activeElement.id==='traffic-reset-confirm'
                && !document.querySelector('#traffic-reset-confirmation').hidden
                && !document.querySelector('#traffic-reset-confirm').disabled;
            '''), timeout=1)
        finally:
            # Restore before any further diagnostic call, independently of UI
            # errors. The global finally retries the same guarded restoration.
            socket_mode_guard.restore()
            report['controlAccessAttempt'] = gui.js('''
              const q=window.__resetDenialQa;
              return {trustedClick:q.trustedClick,confirmFocusEvents:q.confirmFocusEvents,
                panelOpen:!document.querySelector('#traffic-reset-confirmation').hidden,
                confirmDisabled:document.querySelector('#traffic-reset-confirm').disabled,
                confirmFocused:document.activeElement.id==='traffic-reset-confirm',
                noticeKind:document.querySelector('#notice').dataset.kind,
                noticeSource:document.querySelector('#notice').dataset.source};
            ''')
            clear_denial_observers(gui)
        refusal_after = cli('status')['stats']
        require(all(refusal_after[key] == refusal_before[key] for key in
                    ('uploadBytes', 'downloadBytes', 'transferStatsResetUnixMs')),
                'Control-socket refusal changed canonical transfer totals or timestamp')
        require(fixture.service_pid() == pid, 'Control-socket refusal changed the canonical daemon PID')
        wait_for('Confirm is usable again after access restoration', lambda: gui.js(
            'return !document.querySelector("#traffic-reset-confirm").disabled'))
        gui.keys(['\ue00c'])
        cancelled()
        passed('real control-socket permission refusal: trusted Confirm, action error, restored focus/mode, Escape and unchanged canonical totals/PID',
               control_access=True)

        phase('unsaved settings draft setup')
        gui.page('settings')
        draft_port = '17894' if gui.field('#proxy-port') != '17894' else '17895'
        draft_changed = True
        gui.type_in('#proxy-port', draft_port)
        wait_for('own unsaved draft is dirty', lambda: gui.js(
            'return !document.querySelector("#settings-savebar").hidden'))
        gui.page('home')
        before = cli('status')
        history = cli('history', 'status')
        raw_before = raw_totals()
        phase('real native transfer reset')
        confirmation()
        # Observe trust only; the actual input is NativeGui's W3C pointer click.
        gui.js('''window.__resetPointerTrusted=false;
          document.querySelector('#traffic-reset-confirm').addEventListener('click',
            event=>{window.__resetPointerTrusted=event.isTrusted;},{once:true});''')
        gui.click('#traffic-reset-confirm')
        wait_for('native UI displays zero after real reset', visible_zero)
        cancelled()
        require(gui.js('return window.__resetPointerTrusted'), 'Reset did not receive trusted pointer input')
        after = cli('status')
        require(after['stats']['uploadBytes'] == after['stats']['downloadBytes'] == 0,
                'Canonical displayed totals did not reset to zero')
        require(isinstance(after['stats']['transferStatsResetUnixMs'], int)
                and after['stats']['transferStatsResetUnixMs'] > 0,
                'Canonical reset timestamp is missing')
        assert_invariants(before, after, history, pid)
        raw_after = raw_totals()
        require(raw_after == raw_before, 'Reset changed raw lifetime diagnostic totals')
        # Regular native polling must keep displaying the canonical zero state.
        deadline = time.monotonic() + 2.2
        while time.monotonic() < deadline:
            require(visible_zero(), 'Polling changed paused post-reset UI totals')
            time.sleep(.1)
        require(gui.js('return document.querySelector("#traffic-period").textContent')
                .startswith(labels['en'][1]), 'Reset period is not localized')
        gui.shot('reset-zero-en', '#traffic-period')
        passed('visible pointer confirmation resets canonical/UI totals without PID/settings/revision/history/quota/client/activity/savings changes')
        phase('unsaved settings draft preservation')
        gui.page('settings')
        require(gui.field('#proxy-port') == draft_port and gui.js(
            'return !document.querySelector("#settings-savebar").hidden'),
            'Reset or subsequent polling discarded the unsaved settings draft')
        require(cli('status')['settings']['proxyPort'] == port,
                'Reset saved the local settings draft')
        gui.page('home')
        passed('reset and fresh native polling preserve own unsaved settings draft without saving it')
        report['displayedAfterReset'] = {key: after['stats'][key] for key in
                                        ('uploadBytes', 'downloadBytes', 'transferStatsResetUnixMs')}
        report['rawLifetimeTotals'] = raw_after

        phase('same socket continuation and new authenticated traffic')
        origin.resume.set()
        require(response.read() == CHUNK, 'Same authenticated socket did not continue after reset')
        require(origin.finished.wait(10) and not origin.failures, 'Origin fixture failed to finish')
        continued = wait_for('post-reset canonical download counter rises', lambda:
                             (state if (state := cli('status'))['stats']['downloadBytes'] >= len(CHUNK)
                              else None))
        passed('same authenticated HTTP response/socket continues after reset')
        response.close()
        stream.close()
        response = stream = None
        stream, response = open_authenticated_transfer(
            ip, port, patch['proxyUsername'], fixture.PASSWORD, origin.server.server_port)
        require(response.read() == CHUNK, 'Fresh authenticated post-reset response did not complete')
        continued = wait_for('both post-reset canonical transfer totals rise', lambda:
                             (state if (state := cli('status'))['stats']['uploadBytes'] > 0
                              and state['stats']['downloadBytes'] >= len(CHUNK) else None))
        wait_for('post-reset traffic rendered', lambda: gui.js(
            'return document.querySelector("#download-total").textContent!=="0 B"'))
        require(fixture.service_pid() == pid and continued['revision'] == before['revision'],
                'Continued traffic changed daemon PID or settings revision')
        raw_continued = raw_totals()
        require(all(raw_continued[key] >= raw_after[key] for key in raw_after)
                and raw_continued['downloadBytes'] > raw_after['downloadBytes'],
                'Raw lifetime totals did not increase monotonically')
        require(all(raw_continued[key] - raw_after[key] == continued['stats'][key]
                    for key in raw_after),
                'Raw lifetime increments differ from canonical post-reset transfer totals')
        gui.shot('reset-continued-en', '#traffic-period')
        passed('fresh authenticated traffic increases both canonical totals; UI download is nonzero and raw increments match canonical totals')
        report['displayedAfterContinuation'] = {key: continued['stats'][key]
                                               for key in ('uploadBytes', 'downloadBytes')}
    except Exception as caught:
        error = caught
        report['result'] = 'fail'
        # Exception strings can contain echoed payloads/credentials from libraries.
        report['errorType'] = type(caught).__name__
        report['failedPhase'] = report['phase']
        report['failedControl'] = report['lastControl']
        if 'webdriverError' in report:
            report['failedWebdriverError'] = dict(report['webdriverError'])
        if isinstance(caught, AssertionError):
            # All assertion messages in this harness and NativeGui are fixed
            # descriptions, never snapshot values or HTTP/control payloads.
            report['failedCheck'] = str(caught)
        if gui and gui.session:
            try:
                gui.shot('failure')
                report['failureScreenshot'] = 'failure.png'
            except Exception:
                report['failureScreenshot'] = 'unavailable'
        print('FAIL transfer reset acceptance (' + type(caught).__name__ + ')', flush=True)
    finally:
        report['phase'] = 'cleanup'
        cleanup_failures = []
        if socket_mode_guard is not None:
            try:
                socket_mode_guard.restore()
            except Exception:
                cleanup_failures.append('control-socket-mode-restore')
        for resource in (response, stream, origin):
            if resource:
                try:
                    resource.close()
                except Exception:
                    cleanup_failures.append('fixture-close')
        if origin_alias_owned:
            try:
                fixture.command('sudo', '-n', 'ip', 'address', 'del', f'{ORIGIN_IP}/32', 'dev', 'lo')
                require(not origin_alias_present(), 'Owned origin alias remains assigned after cleanup')
                report['removedOwnedOriginAlias'] = True
            except Exception:
                cleanup_failures.append('origin-alias-remove')
        if gui:
            try:
                if gui.session:
                    clear_denial_observers(gui)
                    if draft_changed:
                        gui.page('settings')
                        if gui.js('return !document.querySelector("#settings-savebar").hidden'):
                            gui.click('#discard-settings')
                            wait_for('own draft discarded', lambda: gui.js(
                                'return document.querySelector("#settings-savebar").hidden'))
                    if original_locale in ('cs', 'en'):
                        gui.click(f'[data-locale="{original_locale}"]')
                    if original_rect:
                        gui.wd('POST', '/window/rect', {key: original_rect[key]
                               for key in ('x', 'y', 'width', 'height')})
            except Exception:
                cleanup_failures.append('gui-state-restore')
            try:
                gui.cleanup()
            except Exception:
                cleanup_failures.append('gui-close')
        if restore is not None:
            try:
                apply_patch(restore)
                restored = desktop_snapshot()
                require(all(restored['settings'][key] == value for key, value in restore.items()),
                        'Owned settings were not restored')
                require(restored['settings'] == original_settings,
                        'Full canonical settings differ from the initial settings after cleanup')
                report['restoredSettings'] = True
            except Exception:
                cleanup_failures.append('settings-restore')
        report['cleanupFailures'] = cleanup_failures
        report['result'] = 'fail' if error or cleanup_failures else 'pass'
        fixture.write_json(artifacts / 'report.json', report)
    return 0 if report['result'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
