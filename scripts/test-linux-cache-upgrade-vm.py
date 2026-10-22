#!/usr/bin/env python3
"""Installed native offline preparation/pinning acceptance on the disposable homeproxy-qa VM.

Run inside the KVM guest as the graphical qa user on the real Xorg :0 session,
after test-linux-gui-vm.py has prepared Inspect for cache.fixture.test with a
trusted client declaration. Requires test-linux-gui-vm.py beside this file, the
installed /usr/bin binaries, WebKitWebDriver, canonical homeproxy.service and an
active fixture-origin.service whose request ledger is readable by qa.

Every product action is a visible native GUI action; every success is
corroborated by the canonical CLI, the origin ledger and real proxy traffic.
The harness clears the guest cache through the GUI to start from the empty
preparation state. It never starts a daemon, display or origin, and qa cannot
restart the system service: the controller (root on the host, via SSH) restarts
homeproxy.service when cache-restart-ready.json appears, then creates
cache-restart.done. Alternatively --controller-hook PHASE ARTIFACTS must exit
successfully only after that restart.

Cancellation and byte-budget rejection need a controlled slow origin path (default
/slow.bin): public, max-age=3600, declared Content-Length of at least 4 MiB and
paced at no more than 256 KiB/s. Without it pass --no-slow-fixture; the result
is then "incomplete" (exit 2), never "pass".

Example: DISPLAY=:0 python3 test-linux-cache-upgrade-vm.py --ack-disposable-vm \
    --artifacts /home/qa/cache-upgrade
"""

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.request


HOST = 'cache.fixture.test'
PAYLOAD_SIZE = 131072
RANGE = (1024, 3071)
SOCKET = Path('/run/homeproxy/control.sock')
UNIT_PATHS = ('/usr/lib/systemd/system/homeproxy.service', '/lib/systemd/system/homeproxy.service')
ORIGIN_STATE = Path('/var/lib/fixture-origin/counts.json')
RESTART_PHASE = 'cache-restart'
NARROW = (760, 640)
# W3C WebDriver key codes, spelled out so no invisible characters live in this file.
TAB_KEY, ENTER_KEY = chr(0xE004), chr(0xE007)
ACTIVE_STATES = ('queued', 'running')
CACHE_KEY = re.compile(r'[0-9a-f]{64}')
# Long path without a query string: labels are redacted to scheme://authority/path.
LONG_PATH = '/' + 'offline-preparation-wrapping-check-' * 8 + 'end.jpg'
# Exact product copy (src/i18n.ts, src/offline-preparation.ts) for visible-state checks.
EMPTY_TEXT = {'cs': 'Zatím nebyly připraveny žádné soubory.', 'en': 'No files have been prepared yet.'}
REASONS = {
    'invalid-input': 'Enter 1–32 different public HTTP(S) URLs and a 1–1024 MiB budget.',
    'private-target': 'Private and local destinations are not allowed.',
    'pin-quota': 'The budget exceeds free pin space; reduce it or release pins.',
    'byte-budget': 'The file exceeds the remaining transfer budget.',
    'offline-mode': 'Preparation requires saved Online mode.',
    'queued': 'Queued',
    'cancelled': 'Preparation cancelled',
}
READY_TEXT = 'Available offline'
UNAVAILABLE_TEXT = 'Currently unavailable offline'
PINNED_TEXT = 'Pinned'

_native = None


def native():
    """Shared NativeGui, guards and CLI helpers from the installed GUI harness."""
    global _native
    if _native is None:
        spec = importlib.util.spec_from_file_location(
            'gui_vm_harness', Path(__file__).with_name('test-linux-gui-vm.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _native = module
    return _native


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def payload(path):
    # Mirrors fixture-origin.py; any byte difference means the origin changed.
    seed = ('HomeProxy disposable fixture PAYLOAD ' + path + '\n').encode()
    return (seed * (PAYLOAD_SIZE // len(seed) + 1))[:PAYLOAD_SIZE]


def url(path, scheme='https'):
    return f'{scheme}://{HOST}{path}'


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


# Canonical CLI ------------------------------------------------------------

def cli_attempt(*args, stdin=None):
    """Run the installed CLI; return (ok, result) or (False, error code only)."""
    result = subprocess.run(['/usr/bin/homeproxy', '--json', *args], input=stdin,
                            text=True, capture_output=True, timeout=35)
    try:
        value = json.loads(result.stdout)
    except ValueError:
        value = None
    if result.returncode == 0 and isinstance(value, dict) and value.get('ok', True) and 'result' in value:
        return True, value['result']
    return False, error_code(value, result.stderr)


def error_code(value, stderr=''):
    """Extract a stable error code; never return raw output that may echo input."""
    text = json.dumps(value) if value is not None else ''
    match = re.search(r'offline-preparation:([a-z-]+)', text + '\n' + (stderr or ''))
    if match:
        return match[1]
    error = value.get('error') if isinstance(value, dict) else None
    code = error.get('code') if isinstance(error, dict) else None
    return code if isinstance(code, str) and re.fullmatch(r'[a-z_-]{1,64}', code) else 'unknown'


def cli(*args):
    ok, value = cli_attempt(*args)
    require(ok, f'Installed CLI {args[0]} failed ({value})')
    return value


def prepared():
    return cli('cache', 'prepared')


def job_ids(status):
    return [job['id'] for job in status['jobs']]


def new_job(before, status):
    """The one job created since `before`, None while not yet visible (wait_for retries)."""
    created = [job for job in status['jobs'] if job['id'] not in before]
    require(len(created) <= 1, f'Expected one new preparation job, found {len(created)}')
    return created[0] if created else None


def find_job(status, job_id):
    return next((job for job in status['jobs'] if job['id'] == job_id), None)


def job_finished(status, job_id):
    job = find_job(status, job_id)
    return job if job and status.get('activeJob') != job_id and job['state'] not in ACTIVE_STATES else None


def item(job, label):
    matches = [entry for entry in job['items'] if entry['label'] == label]
    require(len(matches) == 1, f'Job does not contain exactly one item {label}')
    return matches[0]


def persistent_view(status):
    """Fields that must survive GUI close/reopen and a canonical service restart."""
    return {'jobs': [{'id': job['id'], 'state': job['state'], 'items': [
        {key: entry[key] for key in ('label', 'state', 'storedBytes', 'cacheKey', 'pinned', 'errorCode')}
        for entry in job['items']]} for job in status['jobs']],
        'pins': sorted((pin['key'], pin['bytes']) for pin in status['pins']),
        'pinUsage': {key: status['pinUsage'][key] for key in ('usedBytes', 'entryCount', 'limitBytes')}}


def check_ready_item(status, job, label):
    entry = item(job, label)
    require(entry['state'] == 'stored' and entry['errorCode'] is None, f'{label} was not stored: {entry["errorCode"]}')
    require(entry['storedBytes'] == PAYLOAD_SIZE and entry['receivedBytes'] == PAYLOAD_SIZE,
            f'{label} stored/received bytes differ from the fixture size')
    require(isinstance(entry['cacheKey'], str) and CACHE_KEY.fullmatch(entry['cacheKey']),
            f'{label} has no valid cache key')
    require(entry['pinned'] and entry['offlineReady'], f'{label} is not pinned and Offline Ready')
    pins = [pin for pin in status['pins'] if pin['key'] == entry['cacheKey']]
    require(len(pins) == 1 and pins[0]['offlineReady'] and pins[0]['bytes'] == PAYLOAD_SIZE,
            f'{label} is missing from canonical pins')
    return {'label': label, 'cacheKey': entry['cacheKey'], 'storedBytes': entry['storedBytes']}


def check_unready_item(status, job, label, may_store=False):
    """Private/Set-Cookie cannot store; zero-TTL can store and pin but never be Offline Ready."""
    entry = item(job, label)
    require(not entry['offlineReady'], f'{label} was reported Offline Ready')
    if may_store:
        require(entry['state'] == 'stored' and entry['errorCode'] is None,
                f'{label} was not stored for online validation')
        require(entry['storedBytes'] == PAYLOAD_SIZE and entry['receivedBytes'] == PAYLOAD_SIZE,
                f'{label} stored/received bytes differ from the fixture size')
        require(isinstance(entry['cacheKey'], str) and CACHE_KEY.fullmatch(entry['cacheKey']),
                f'{label} has no valid cache key')
        pins = [pin for pin in status['pins'] if pin['key'] == entry['cacheKey']]
        require(entry['pinned'] and len(pins) == 1 and not pins[0]['offlineReady']
                and pins[0]['bytes'] == PAYLOAD_SIZE, f'{label} has inconsistent canonical pins')
        return {'label': label, 'state': 'stored', 'pinned': True, 'offlineReady': False}
    require(not entry['pinned'], f'{label} was pinned')
    require(not any(pin['key'] == entry['cacheKey'] for pin in status['pins'] if entry['cacheKey']),
            f'{label} appears in canonical pins')
    require(entry['state'] == 'failed' and entry['errorCode'], f'{label} did not record a preparation failure')
    require(entry['storedBytes'] == 0 and entry['cacheKey'] is None, f'{label} failure retained a cache entry')
    return {'label': label, 'state': entry['state'], 'errorCode': entry['errorCode']}


def check_released_pin(status, before, key, payload_bytes):
    """Canonical quota includes the body, metadata and pin-manifest overhead."""
    after = status['pinUsage']
    freed = before['usedBytes'] - after['usedBytes']
    require(not after['degraded'] and all(pin['key'] != key for pin in status['pins']),
            'Released pin remains in canonical pins or quota is degraded')
    require(after['entryCount'] == before['entryCount'] - 1
            and after['entryCount'] == len(status['pins'])
            and freed >= payload_bytes
            and after['usedBytes'] >= sum(pin['bytes'] for pin in status['pins']),
            'Pin usage did not release the complete file and preserve remaining pins')
    return {'before': before['usedBytes'], 'after': after['usedBytes'], 'freedBytes': freed}


def check_pin_usage(status, minimum_entries, minimum_bytes):
    usage = status['pinUsage']
    require(not usage['degraded'] and usage['limitBytes'] > 0, 'Pin usage is degraded or has no limit')
    require(usage['entryCount'] >= minimum_entries and usage['usedBytes'] >= minimum_bytes,
            'Pin usage does not account for pinned prepared files')
    require(usage['usedBytes'] <= usage['limitBytes'], 'Pin usage exceeds its quota')
    return {key: usage[key] for key in ('usedBytes', 'limitBytes', 'entryCount')}


# Origin ledger ------------------------------------------------------------

class Ledger:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        value = json.loads(self.path.read_text())
        require(isinstance(value.get('paths'), dict) and isinstance(value.get('requests'), list),
                'Origin ledger has an unexpected format')
        return value


def path_deltas(before, after):
    paths = set(before['paths']) | set(after['paths'])
    return {path: after['paths'].get(path, 0) - before['paths'].get(path, 0)
            for path in sorted(paths) if after['paths'].get(path, 0) != before['paths'].get(path, 0)}


def require_no_egress(before, after, label):
    require(after.get('total') == before.get('total') and after['requests'] == before['requests'],
            f'{label}: origin received {after.get("total", 0) - before.get("total", 0)} new requests')
    return {'newOriginRequests': 0}


# Real proxy traffic -------------------------------------------------------

def digest_authorization(challenge, username, password, method, uri, cnonce=None):
    """HomeProxy HTTP Digest (MD5, qop=auth); there is no Basic fallback."""
    scheme, separator, parameters = challenge.partition(' ')
    require(separator and scheme.lower() == 'digest', 'Proxy must offer Digest authentication')
    fields = {key.lower(): value for key, value in
              urllib.request.parse_keqv_list(urllib.request.parse_http_list(parameters)).items()}
    require(fields.get('algorithm', 'MD5').upper() == 'MD5', 'Unexpected Digest algorithm')
    require('auth' in [token.strip().lower() for token in fields.get('qop', '').split(',')],
            'Digest qop=auth is required')
    cnonce = cnonce or os.urandom(16).hex()

    def md5(value):
        return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()

    response = md5(':'.join((md5(f'{username}:{fields["realm"]}:{password}'), fields['nonce'],
                             '00000001', cnonce, 'auth', md5(f'{method}:{uri}'))))

    def quoted(value):
        require('\r' not in value and '\n' not in value, 'Digest values must not contain newlines')
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    values = [('username', username), ('realm', fields['realm']), ('nonce', fields['nonce']),
              ('uri', uri), ('response', response)]
    if 'opaque' in fields:
        values.append(('opaque', fields['opaque']))
    return ('Digest ' + ', '.join(f'{key}={quoted(value)}' for key, value in values)
            + f', algorithm=MD5, qop=auth, nc=00000001, cnonce={quoted(cnonce)}')


def read_head(stream, limit=65536):
    raw = bytearray()
    while not raw.endswith(b'\r\n\r\n'):
        byte = stream.recv(1)
        require(byte, 'Proxy closed before complete response headers')
        raw.extend(byte)
        require(len(raw) <= limit, 'Proxy response headers exceeded 64 KiB')
    lines = bytes(raw).decode('iso-8859-1').split('\r\n')
    headers = {key.strip().lower(): value.strip() for line in lines[1:] if ':' in line
               for key, value in [line.split(':', 1)]}
    return int(lines[0].split()[1]), headers


def exchange(stream, method, target, extra=None, authorization=None, issuer=None):
    """Send one request and parse one response; HEAD responses never read a body."""
    custom = ''.join(f'{name}: {value}\r\n' for name, value in (extra or {}).items())
    auth = f'Proxy-Authorization: {authorization}\r\n' if authorization else ''
    try:
        stream.sendall((f'{method} {target} HTTP/1.1\r\nHost: {HOST}\r\nAccept: */*\r\n'
                        f'Accept-Encoding: identity\r\n{auth}{custom}Connection: close\r\n\r\n').encode())
        response = http.client.HTTPResponse(stream, method=method)
        response.begin()
        result = {'status': response.status, 'body': response.read(), 'issuer': issuer,
                  'headers': {key.lower(): value for key, value in response.getheaders()}}
        response.close()
        return result
    finally:
        stream.close()


class ProxyClient:
    """Loopback client of the canonical listener; Digest credentials only on 407."""

    def __init__(self, port, ca, address='127.0.0.1'):
        self.port, self.ca, self.address = port, ca, address
        self._credentials = None

    def credentials(self):
        if self._credentials is None:
            value = cli('credentials', 'show')
            self._credentials = (value['username'], value['password'])
        return self._credentials

    def stream(self):
        return socket.create_connection((self.address, self.port), timeout=20)

    def authorization(self, headers, method, uri):
        username, password = self.credentials()
        return digest_authorization(headers['proxy-authenticate'], username, password, method, uri)

    def http(self, method, path, extra=None):
        target = url(path, 'http')
        result = exchange(self.stream(), method, target, extra)
        if result['status'] == 407:
            result = exchange(self.stream(), method, target, extra,
                              self.authorization(result['headers'], method, target))
        return result

    def connect(self, authorization=None):
        stream = self.stream()
        auth = f'Proxy-Authorization: {authorization}\r\n' if authorization else ''
        try:
            stream.sendall(f'CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n{auth}\r\n'.encode())
            status, headers = read_head(stream)
        except Exception:
            stream.close()
            raise
        if status != 200:
            stream.close()
        return status, headers, stream

    def https(self, method, path, extra=None):
        status, headers, stream = self.connect()
        if status == 407:
            status, headers, stream = self.connect(self.authorization(headers, 'CONNECT', f'{HOST}:443'))
        if status != 200:
            return {'status': status, 'headers': headers, 'body': b'', 'issuer': None}
        try:
            # Strict verification against the exported public HomeProxy CA only.
            stream = ssl.create_default_context(cafile=str(self.ca)).wrap_socket(stream, server_hostname=HOST)
            issuer = [value for group in stream.getpeercert()['issuer'] for key, value in group if key == 'commonName']
        except Exception:
            stream.close()
            raise
        return exchange(stream, method, path, extra, issuer=issuer)


def check_response(result, path, method='GET', status=200, hit=None, ranged=False, tls=True):
    label = f'{"https" if tls else "http"} {method} {path}'
    require(result['status'] == status, f'{label}: expected {status}, received {result["status"]}')
    cache = result['headers'].get('cache-status', '').lower()
    if hit:
        require('homeproxy' in cache and '; hit' in cache, f'{label}: expected HomeProxy cache hit')
    else:
        require('; hit' not in cache, f'{label}: unexpected cache hit')
    if status in (200, 206):
        start, end = RANGE
        expected = payload(path)[start:end + 1] if ranged else payload(path)
        if method == 'HEAD':
            require(result['body'] == b'', f'{label}: HEAD returned a body')
            require(result['headers'].get('content-length') == str(len(expected)),
                    f'{label}: HEAD Content-Length differs from the stored representation')
        else:
            require(result['body'] == expected, f'{label}: body differs from the fixture origin')
        if ranged:
            require(result['headers'].get('content-range') == f'bytes {start}-{end}/{PAYLOAD_SIZE}',
                    f'{label}: wrong Content-Range')
        if tls:
            require(any('HomeProxy' in name for name in result['issuer'] or []),
                    f'{label}: TLS issuer must be the HomeProxy authority')
    return {'request': label, 'status': result['status'], 'cacheStatus': cache,
            'bytes': len(result['body']), 'sha256': hashlib.sha256(result['body']).hexdigest()}


def offline_traffic(client, https_ready, http_ready, misses):
    """Cached GET/HEAD/Range for prepared files and 504 misses; caller checks ledger."""
    ranged = {'Range': f'bytes={RANGE[0]}-{RANGE[1]}'}
    evidence = []
    for path in https_ready:
        evidence.append(check_response(client.https('GET', path), path, hit=True))
        evidence.append(check_response(client.https('HEAD', path), path, 'HEAD', hit=True))
        evidence.append(check_response(client.https('GET', path, ranged), path, status=206, hit=True, ranged=True))
    for path in http_ready:
        evidence.append(check_response(client.http('GET', path), path, hit=True, tls=False))
        evidence.append(check_response(client.http('HEAD', path), path, 'HEAD', hit=True, tls=False))
        evidence.append(check_response(client.http('GET', path, ranged), path, status=206, hit=True,
                                       ranged=True, tls=False))
    for path in misses:
        evidence.append(check_response(client.https('GET', path), path, status=504, hit=False))
    return evidence


# Guards and result --------------------------------------------------------

def unit_overrides(drop_in_paths):
    return [path for path in drop_in_paths.split() if '/homeproxy.service.d/' in path
            or '/homeproxy-.service.d/' in path]


def check_vm_guards(gui_harness):
    """Guest-only guards in addition to the GUI harness's Xorg/qa/canonical-service checks."""
    gui_harness.check_environment()
    require(not any(key.startswith('HOMEPROXY_') for key in os.environ),
            'HOMEPROXY_* overrides (custom socket/config) are forbidden')
    require(gui_harness.command('systemd-detect-virt').strip() == 'kvm', 'Requires the KVM homeproxy-qa guest')
    require(stat.S_ISSOCK(os.lstat(SOCKET).st_mode), 'Control socket must be the canonical socket, not a link')
    show = lambda prop: gui_harness.command(
        'systemctl', 'show', 'homeproxy.service', f'--property={prop}', '--value').strip()
    require(show('FragmentPath') in UNIT_PATHS, 'homeproxy.service must be the packaged unit')
    # Distribution-wide service.d drop-ins are allowed; unit-specific overrides are not.
    require(not unit_overrides(show('DropInPaths')), 'homeproxy.service drop-in overrides are forbidden')
    require('HOMEPROXY_' not in show('Environment'), 'Service environment overrides are forbidden')
    require(gui_harness.command('systemctl', 'is-active', 'fixture-origin.service').strip() == 'active',
            'fixture-origin.service must stay active so missing egress is meaningful')


def check_product_preconditions(settings, tls):
    require(settings['httpsMode'] == 'inspect' and settings['httpsClientTrustAcknowledged'],
            'Run test-linux-gui-vm.py first: Inspect with client trust declaration is required')
    require(HOST in settings['httpsInspectHosts'], f'{HOST} must be in the Inspect allowlist')
    require(not any(HOST == rule or HOST.endswith('.' + rule.lstrip('*.')) for rule in settings.get('httpsBypassHosts', [])),
            f'{HOST} must not be bypassed')
    require(settings['cacheEnabled'], 'Public cache must be enabled')
    require(tls['prepared'], 'The existing HomeProxy CA must be prepared')


def final_result(not_covered):
    return 'incomplete' if not_covered else 'pass'


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--ack-disposable-vm', action='store_true', required=True)
    parser.add_argument('--origin-state', type=Path, default=ORIGIN_STATE)
    parser.add_argument('--slow-path', default='/slow.bin', help='Controlled slow public origin path')
    parser.add_argument('--no-slow-fixture', action='store_true',
                        help='Slow path unavailable: cancellation/byte budget are reported not covered')
    parser.add_argument('--phase-timeout', type=int, default=300)
    parser.add_argument('--egress-quiet-seconds', type=float, default=10)
    parser.add_argument('--controller-hook', type=Path, help='Executable: PHASE ARTIFACTS; restarts the service')
    args = parser.parse_args(argv)
    require(re.fullmatch(r'/[A-Za-z0-9._/-]{1,200}', args.slow_path) and '..' not in args.slow_path,
            'Slow path must be a plain absolute fixture path')
    require(args.slow_path not in ('/public.jpg', '/http.jpg', '/uncached.jpg'),
            'Slow path must be separate from prepared and miss fixtures')
    require(args.egress_quiet_seconds >= 1, 'Egress observation needs at least one second')
    return args


# Native GUI actions -------------------------------------------------------

ITEM_SCRIPT = (
    'const jobs=[...document.querySelectorAll("#preparation-jobs details.preparation-job")];'
    'for(const [jobIndex,d] of jobs.entries()) {'
    'const li=[...d.querySelectorAll("li")].find(e=>e.querySelector(".preparation-label")?.textContent===arguments[0]);'
    'if(!li) continue; const s=li.querySelector(".preparation-state"); if(!s) return null;'
    'const r=li.getBoundingClientRect(), style=getComputedStyle(li);'
    'return {jobIndex,open:d.open,visible:d.open&&r.width>0&&r.height>0'
    '&&style.display!=="none"&&style.visibility!=="hidden"&&style.visibility!=="collapse",'
    'state:s.textContent, ready:s.classList.contains("is-ready"),'
    'error:li.querySelector(".field-error")?.textContent||null};} return null;')


class PreparationGui:
    def __init__(self, gui, gui_harness):
        self.gui, self.h = gui, gui_harness

    def text(self, selector):
        return self.gui.js('return document.querySelector(arguments[0]).innerText.trim()', selector)

    def disabled(self, selector):
        return self.gui.js('return document.querySelector(arguments[0]).disabled', selector)

    def gui_item(self, label):
        return self.gui.js(ITEM_SCRIPT, label)

    def reveal_item(self, label):
        item = self.h.wait_for(f'native job contains {label}', lambda: self.gui_item(label))
        if not item['open']:
            self.gui.click(f'#preparation-jobs details.preparation-job:nth-of-type({item["jobIndex"] + 1}) > summary')

        def visible_item():
            item = self.gui_item(label)
            return item if item and item['open'] and item['visible'] else False
        self.h.wait_for(f'native item is expanded and visible: {label}', visible_item)
        # The GUI refreshes every 1.5 seconds. A manual expansion must survive
        # at least two snapshot polls instead of being silently replaced.
        deadline = time.monotonic() + 3.2
        while time.monotonic() < deadline:
            require(visible_item(), f'Native item collapsed or became hidden during polling: {label}')
            time.sleep(.2)

    def pin_keys(self):
        return sorted(self.gui.js('return [...document.querySelectorAll("#preparation-pins button[data-pin-key]")]'
                                  '.map(b=>b.dataset.pinKey)'))

    def settings(self):
        self.gui.page('settings')
        self.h.wait_for('native preparation controls loaded', lambda: self.gui.js(
            'return !!document.querySelector("#preparation-jobs").innerHTML.trim()'))

    def locale(self, value):
        self.gui.click(f'[data-locale="{value}"]')
        self.h.wait_for(f'native {value} locale', lambda: self.gui.js('return document.documentElement.lang') == value)
        self.settings()

    def pin(self, desired):
        if self.gui.js('return document.querySelector("#preparation-pin").checked') != desired:
            self.gui.click('#preparation-pin')
        self.h.wait_for('native pin option', lambda: self.gui.js(
            'return document.querySelector("#preparation-pin").checked') == desired)

    def fill(self, urls, budget='64', pin=True):
        self.gui.type_in('#preparation-urls', '\n'.join(urls))
        self.gui.type_in('#preparation-budget', budget)
        self.pin(pin)

    def error(self, code):
        expected = REASONS[code]
        self.h.wait_for(f'visible preparation reason {code}', lambda: self.text('#preparation-error') == expected)
        return expected

    def cache_mode(self, mode):
        if self.gui.field('#cache-mode') != mode:
            self.gui.select('#cache-mode', mode)
            self.gui.click('#save-settings')
        self.h.wait_for(f'canonical cacheMode {mode}', lambda: cli('status')['settings']['cacheMode'] == mode)
        self.h.wait_for('saved settings draft is clean', lambda: self.gui.js(
            'return document.querySelector("#settings-savebar").hidden'))

    def start_by_keyboard(self):
        # Real keyboard activation: focus the last option, Tab to the button and press Enter.
        # A disabled button is skipped by Tab, so wait for the valid form first.
        self.h.wait_for('enabled keyboard start', lambda: not self.disabled('#prepare-offline'))
        self.gui.js('document.querySelector("#preparation-pin").focus()')
        self.gui.keys([TAB_KEY])
        focused = self.gui.js('return document.activeElement.id')
        require(focused == 'prepare-offline', f'Tab from pin option focused {focused!r}, not the start button')
        self.gui.keys([ENTER_KEY])


def main(argv=None):
    args = parse_args(argv)
    # Reject other hosts before any artifact mutation, GUI or service operation.
    require(socket.gethostname() == 'homeproxy-qa', 'Requires the disposable homeproxy-qa VM')
    h = native()
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifacts.chmod(0o700)
    checks, not_covered = [], []
    report = {'result': 'running', 'display': ':0', 'socket': str(SOCKET), 'host': HOST,
              'checks': checks, 'notCovered': not_covered, 'binarySha256': {}}
    # Invalidate a previous PASS before fallible guest checks.
    write_json(artifacts / 'report.json', report)
    gui = None

    def passed(label, evidence=None):
        checks.append({'check': label, 'evidence': evidence} if evidence is not None else {'check': label})
        print('PASS ' + label, flush=True)
        write_json(artifacts / 'report.json', report)

    def skipped(label, reason):
        not_covered.append({'check': label, 'reason': reason})
        print(f'NOT COVERED {label}: {reason}', flush=True)
        write_json(artifacts / 'report.json', report)

    def wait_job(job_id, timeout=150):
        return h.wait_for(f'preparation job {job_id} finished', lambda: job_finished(prepared(), job_id), timeout)

    def submit(urls, budget, pin, keyboard=False):
        before = job_ids(prepared())
        ui.fill(urls, budget, pin)
        if keyboard:
            ui.start_by_keyboard()
        else:
            gui.click('#prepare-offline')
        return h.wait_for('canonical job created by native GUI', lambda: new_job(before, prepared()))

    try:
        for marker in (f'{RESTART_PHASE}-ready.json', f'{RESTART_PHASE}.done'):
            (artifacts / marker).unlink(missing_ok=True)
        check_vm_guards(h)
        report['sourceSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['helperSha256'] = hashlib.sha256(Path(h.__file__).read_bytes()).hexdigest()
        report['binarySha256'] = {name: hashlib.sha256(Path('/usr/bin', name).read_bytes()).hexdigest()
                                  for name in ('klidna-sit', 'homeproxyd', 'homeproxy')}
        ledger = Ledger(args.origin_state)
        ledger.read()
        state = cli('status')
        require(state['running'], 'Canonical proxy must be running')
        check_product_preconditions(state['settings'], cli('tls', 'status'))
        initial_pid = h.service_pid()
        require(initial_pid > 0, 'Canonical service has no MainPID')
        report['initialSystemdMainPID'] = initial_pid
        ca = artifacts / 'public-ca.pem'
        ca.unlink(missing_ok=True)
        cli('tls', 'export', '--format', 'pem', '--output', str(ca))
        client = ProxyClient(state['settings']['proxyPort'], ca)
        passed('Guest guards: KVM homeproxy-qa, real Xorg :0, qa, canonical unit/socket, Inspect for fixture host')

        gui = h.NativeGui(artifacts)
        gui.open()
        ui = PreparationGui(gui, h)
        ui.locale('en')
        ui.cache_mode('online')
        # The default 8 GiB cache has a 2 GiB pin quota, above the maximum
        # preparation budget. Set a real 1 GiB cache through the visible form
        # so the quota rejection below is exercised rather than skipped.
        gui.type_in('#cache-limit-gib', '1')
        gui.click('#save-settings')
        h.wait_for('canonical 1 GiB cache saved for pin quota acceptance', lambda:
                   cli('status')['settings']['cacheLimitGib'] == 1)
        h.wait_for('cache limit settings draft saved', lambda: gui.js(
            'return document.querySelector("#settings-savebar").hidden'))
        gui.click('#clear-cache')
        h.wait_for('native clear removed preparation jobs and pins', lambda: (
            lambda s: not s['jobs'] and not s['pins'] and s['activeJob'] is None and s['pinUsage']['usedBytes'] == 0
        )(prepared()))
        empty = {}
        for locale in ('cs', 'en'):
            ui.locale(locale)
            h.wait_for(f'{locale} empty preparation state', lambda: ui.text('#preparation-jobs') == EMPTY_TEXT[locale])
            require(gui.field('#preparation-budget') == '64', 'Default budget must be 64 MiB')
            require(gui.js('return document.querySelector("#preparation-pin").checked'), 'Pinning must default on')
            require(ui.disabled('#prepare-offline') and gui.js(
                'return document.querySelector("#cancel-preparation").hidden'),
                'Empty form must not start or offer cancellation')
            require(not ui.text('#preparation-pins'), 'Empty state must not list pins')
            empty[locale] = ui.text('#preparation-quota')
            gui.shot(f'01-empty-{locale}', '#preparation-jobs')
        passed('New preparation empty state in Czech and English with 64 MiB/pin defaults (GUI clear corroborated by CLI)', empty)

        baseline = job_ids(prepared())
        invalid_forms = [
            (['ftp://cache.fixture.test/public.jpg'], '64'),
            (['https://cache.fixture.test:8443/public.jpg'], '64'),
            (['https://qa@cache.fixture.test/public.jpg'], '64'),
            ([url('/public.jpg'), url('/public.jpg')], '64'),
            ([url('/public.jpg')], '0'),
            ([url('/public.jpg')], '1025'),
            ([url('/public.jpg')], 'abc'),
            ([url(f'/public.jpg?n={index}') for index in range(33)], '64'),
        ]
        for urls, budget in invalid_forms:
            ui.fill(urls, budget, True)
            ui.error('invalid-input')
            require(ui.disabled('#prepare-offline'), 'Invalid preparation form can be submitted')
        require(job_ids(prepared()) == baseline, 'Invalid native form reached the service')
        server_cases = [
            ({'urls': [url('/public.jpg')], 'budgetMib': 0, 'pin': False}, 'invalid-input'),
            ({'urls': [url('/public.jpg')], 'budgetMib': 1025, 'pin': False}, 'invalid-input'),
            ({'urls': [url('/public.jpg')] * 2, 'budgetMib': 64, 'pin': False}, 'duplicate-url'),
            ({'urls': ['ftp://cache.fixture.test/public.jpg'], 'budgetMib': 64, 'pin': False}, 'invalid-url'),
            ({'urls': ['http://127.0.0.1/private'], 'budgetMib': 64, 'pin': False}, 'private-target'),
            ({'urls': [url('/public.jpg')], 'budgetMib': 64, 'pin': False, 'headers': {}}, None),
        ]
        server_codes = []
        for request, expected in server_cases:
            ok, code = cli_attempt('cache', 'prepare', '--file', '-', stdin=json.dumps(request))
            require(not ok, f'Service accepted invalid preparation ({expected or "unknown field"})')
            require(expected is None or code in (expected, 'unknown'), f'Service rejected with {code}, expected {expected}')
            server_codes.append(code)
        ok, code = cli_attempt('cache', 'cancel', 'offline-0-0')
        require(not ok, 'Cancelling a nonexistent job succeeded')
        server_codes.append(code)
        require(job_ids(prepared()) == baseline, 'Rejected requests created preparation jobs')
        gui.shot('02-invalid-input', '#preparation-error')
        passed('Invalid scheme/port/userinfo/duplicate/budget/over-32 URLs rejected in GUI and by canonical service',
               {'serviceCodes': server_codes})

        for target in ('http://127.0.0.1/offline-check', 'https://10.0.2.2/offline-check'):
            ui.fill([target], '64', False)
            gui.click('#prepare-offline')
            ui.error('private-target')
        require(job_ids(prepared()) == baseline, 'Private target created a preparation job')
        gui.shot('03-private-target', '#preparation-error')
        passed('Private and local destinations are refused visibly without a job')

        usage = prepared()['pinUsage']
        free_mib = (usage['limitBytes'] - usage['usedBytes']) // (1024 * 1024)
        if free_mib < 1024:
            ui.fill([url('/public.jpg')], '1024', True)
            gui.click('#prepare-offline')
            ui.error('pin-quota')
            require(job_ids(prepared()) == baseline, 'Over-quota pinned preparation created a job')
            gui.shot('04-pin-quota', '#preparation-error')
            passed('Pinned budget above free pin quota (25% of cache) is rejected', {'freePinMiB': free_mib})
        else:
            skipped('pin-quota rejection', f'free pin space {free_mib} MiB allows the 1024 MiB maximum budget')

        prepared_https = ['/public.jpg']
        prepared_http = ['/http.jpg']
        unready = ['/private.jpg', '/cookie.jpg', '/zero-age.jpg']
        urls = [url(prepared_https[0]), url(prepared_http[0], 'http')] + [url(path) for path in unready]
        before = ledger.read()
        observed = []
        job = submit(urls, '64', True, keyboard=True)
        main_id = job['id']

        def observe():
            status = prepared()
            current = find_job(status, main_id)
            snapshot = (current['state'], tuple(entry['state'] for entry in current['items']))
            if not observed or observed[-1] != snapshot:
                observed.append(snapshot)
            return job_finished(status, main_id)
        h.wait_for('main preparation finished', observe, 150)
        # Loopback fixture files finish quickly; the deterministic queued proof is the slow-fixture job.
        report['mainJobObservedStates'] = observed
        status = prepared()
        job = find_job(status, main_id)
        ready_evidence = [check_ready_item(status, job, url(prepared_https[0])),
                          check_ready_item(status, job, url(prepared_http[0], 'http'))]
        unready_evidence = [check_unready_item(status, job, url('/private.jpg')),
                            check_unready_item(status, job, url('/cookie.jpg')),
                            check_unready_item(status, job, url('/zero-age.jpg'), may_store=True)]
        require(job['state'] == 'failed', f'Mixed job state is {job["state"]}, expected failed')
        pin_evidence = check_pin_usage(status, 2, 2 * PAYLOAD_SIZE)
        deltas = path_deltas(before, ledger.read())
        require(deltas == {path: 1 for path in prepared_https + prepared_http + unready},
                f'Unexpected preparation origin requests: {deltas}')
        h.wait_for('native job list shows canonical results', lambda: all(
            (ui.gui_item(entry['label']) or {}).get('ready') == entry['offlineReady'] for entry in job['items']))
        for entry in job['items']:
            visible = ui.gui_item(entry['label'])
            require((READY_TEXT in visible['state']) == entry['offlineReady']
                    and (UNAVAILABLE_TEXT in visible['state']) == (not entry['offlineReady']),
                    f'GUI readiness for {entry["label"]} differs from the service')
            require((PINNED_TEXT in visible['state']) == entry['pinned'], f'GUI pin state differs for {entry["label"]}')
            require(bool(visible['error']) == bool(entry['errorCode']), f'GUI error differs for {entry["label"]}')
        require(ui.pin_keys() == sorted(pin['key'] for pin in status['pins']), 'GUI pins differ from canonical pins')
        gui.shot('05-prepared-mixed', '#preparation-jobs')
        passed('Keyboard-started multi-URL HTTPS+HTTP preparation stores and pins public files; private/Set-Cookie/'
               'zero-age are never Offline Ready; one origin fetch each',
               {'ready': ready_evidence, 'unready': unready_evidence, 'pinUsage': pin_evidence, 'originDeltas': deltas})

        slow = args.slow_path
        if args.no_slow_fixture:
            for label in ('byte-budget rejection', 'cancellation', 'deterministic visible queued state'):
                skipped(label, 'controlled slow fixture unavailable')
        else:
            before = ledger.read()
            job = submit([url(slow)], '1', False)
            job = wait_job(job['id'])
            entry = item(job, url(slow))
            require(job['state'] == 'failed' and entry['errorCode'] == 'byte-budget', 'Over-budget file was not rejected')
            require(entry['storedBytes'] == 0 and entry['cacheKey'] is None and not entry['offlineReady'],
                    'Over-budget file left a cache entry')
            h.wait_for('native byte-budget reason', lambda: (ui.gui_item(url(slow)) or {}).get('error') == REASONS['byte-budget'])
            gui.shot('06-byte-budget', '#preparation-jobs')
            passed('Declared length above the 1 MiB budget is rejected before storage',
                   {'receivedBytes': entry['receivedBytes'], 'originDeltas': path_deltas(before, ledger.read())})

            before = ledger.read()
            job = submit([url(slow), url('/uncached.jpg')], '64', False)
            cancel_id = job['id']
            h.wait_for('slow item running while second item is queued', lambda: (
                lambda current: current and current['items'][0]['state'] == 'running'
                and current['items'][1]['state'] == 'queued')(find_job(prepared(), cancel_id)), 60)
            h.wait_for('native cancel offered with visible queued item', lambda: gui.js(
                'return !document.querySelector("#cancel-preparation").hidden')
                and REASONS['queued'] in (ui.gui_item(url('/uncached.jpg')) or {}).get('state', ''))
            gui.shot('07-running-queued', '#preparation-jobs')
            gui.click('#cancel-preparation')
            job = wait_job(cancel_id, 60)
            require(job['state'] == 'cancelled', f'Cancelled job state is {job["state"]}')
            for entry in job['items']:
                require(entry['state'] == 'cancelled' and entry['errorCode'] == 'cancelled'
                        and entry['cacheKey'] is None and not entry['pinned'], f'{entry["label"]} was not cancelled cleanly')
            time.sleep(args.egress_quiet_seconds)
            deltas = path_deltas(before, ledger.read())
            require(deltas.get('/uncached.jpg', 0) == 0, 'Queued item was fetched after cancellation')
            require(deltas.get(slow, 0) <= 1, 'Cancelled slow item was retried')
            h.wait_for('native cancelled state', lambda: gui.js(
                'return document.querySelector("#cancel-preparation").hidden')
                and REASONS['cancelled'] in ui.text('#preparation-jobs details.preparation-job summary'))
            gui.shot('08-cancelled', '#preparation-jobs')
            passed('Visible cancel stops the running slow download; the queued item never reaches the origin',
                   {'originDeltas': deltas})

        before = ledger.read()
        job = wait_job(submit([url(LONG_PATH)], '1', False)['id'])
        require(not item(job, url(LONG_PATH))['offlineReady'], 'Unknown long path became Offline Ready')
        original_rect = gui.wd('GET', '/window/rect')
        # The packaged window minimum is 760x620; request it and verify the real viewport.
        gui.wd('POST', '/window/rect', {'width': NARROW[0], 'height': NARROW[1]})
        h.wait_for('native narrow viewport applied', lambda: gui.js('return innerWidth') <= NARROW[0] + 40)
        gui.js('document.querySelector("#preparation-jobs").scrollIntoView({block:"center"})')
        layout = gui.js(
            'const l=[...document.querySelectorAll("#preparation-jobs .preparation-label")]'
            '.find(e=>e.textContent===arguments[0]); const r=l.getBoundingClientRect();'
            'const line=parseFloat(getComputedStyle(l).lineHeight)||16;'
            'return {width:innerWidth,documentWidth:document.documentElement.scrollWidth,'
            'labelRight:r.right,labelHeight:r.height,lineHeight:line};', url(LONG_PATH))
        report['narrowViewport'] = layout
        gui.shot('09-narrow-long-url', '#preparation-jobs')
        require(layout['documentWidth'] <= layout['width'] and layout['labelRight'] <= layout['width'] + 1,
                'Long preparation label overflows the narrow native window')
        require(layout['labelHeight'] > 1.5 * layout['lineHeight'], 'Long preparation label did not wrap')
        gui.wd('POST', '/window/rect', {key: original_rect[key] for key in ('x', 'y', 'width', 'height')})
        passed('Narrow native window wraps a long redacted URL without horizontal overflow',
               {'layout': layout, 'originDeltas': path_deltas(before, ledger.read())})

        status = prepared()
        http_key = next(pin['key'] for pin in status['pins'] if pin['label'] == url('/http.jpg', 'http'))
        usage_before = status['pinUsage']
        gui.click(f'#preparation-pins button[data-pin-key="{http_key}"]')
        status = h.wait_for('canonical pin released', lambda: (
            lambda s: s if all(pin['key'] != http_key for pin in s['pins']) else None)(prepared()))
        released_usage = check_released_pin(status, usage_before, http_key, PAYLOAD_SIZE)
        released = item(find_job(status, main_id), url('/http.jpg', 'http'))
        require(not released['pinned'] and released['cacheKey'] == http_key, 'Released item lost its cache entry')
        h.wait_for('native pin list updated', lambda: http_key not in ui.pin_keys())
        gui.shot('10-unpinned', '#preparation-pins')
        passed('Visible Release pin frees canonical pin quota while keeping the cached file',
               released_usage)

        ui.cache_mode('offline')
        ui.error('offline-mode')
        require(ui.disabled('#prepare-offline'), 'Preparation is startable in offline mode')
        status = prepared()
        require(item(find_job(status, main_id), url('/public.jpg'))['offlineReady'], 'Prepared file lost Offline Ready')
        gui.shot('11-offline-mode', '#preparation-error')
        before = ledger.read()
        misses = ['/uncached.jpg', '/private.jpg', '/cookie.jpg'] + ([] if args.no_slow_fixture else [slow])
        evidence = offline_traffic(client, prepared_https, prepared_http, misses)
        time.sleep(1)
        require_no_egress(before, ledger.read(), 'offline traffic')
        passed('Offline cached TLS+HTTP GET/HEAD/Range hits and 504 misses with an active origin and zero egress', evidence)

        expected_view = persistent_view(prepared())
        before = ledger.read()
        gui.close_window()
        require(h.service_pid() == initial_pid, 'Closing native GUI replaced the daemon')
        require(persistent_view(prepared()) == expected_view, 'Closing native GUI changed preparation state')
        gui.open()
        ui.locale('en')
        h.wait_for('reopened GUI shows persisted pins', lambda: ui.pin_keys() == sorted(
            key for key, _ in expected_view['pins']))
        ui.reveal_item(url('/public.jpg'))
        h.wait_for('reopened older job is visibly Offline Ready', lambda: (
            lambda item: item and item['open'] and item['visible'] and item['ready'])(ui.gui_item(url('/public.jpg'))))
        gui.shot('12-reopened-job', '#preparation-jobs')
        gui.shot('12-reopened', '#preparation-pins')
        gui.close_window()
        require_no_egress(before, ledger.read(), 'GUI close/reopen')
        passed('Native close/reopen preserves jobs, pins and readiness without egress')

        done = artifacts / f'{RESTART_PHASE}.done'
        write_json(artifacts / f'{RESTART_PHASE}-ready.json', {
            'phase': RESTART_PHASE, 'systemdMainPID': initial_pid, 'action': 'systemctl restart homeproxy.service'})
        print(f'WAIT controller {RESTART_PHASE}: restart canonical homeproxy.service', flush=True)
        if args.controller_hook:
            h.command(str(args.controller_hook.resolve()), RESTART_PHASE, str(artifacts), timeout=args.phase_timeout)
        else:
            h.wait_for(f'controller completion {done.name}', done.is_file, args.phase_timeout)
        h.wait_for('canonical service restarted', lambda: SOCKET.is_socket()
                   and h.service_pid() > 0 and h.service_pid() != initial_pid, 60)
        # The new daemon may accept connections before it answers; retry CLI failures here only.
        h.wait_for('restarted proxy running', lambda: (lambda ok, value: ok and value['running'])(
            *cli_attempt('status')), 60)
        report['restartedSystemdMainPID'] = h.service_pid()
        require(cli('status')['settings']['cacheMode'] == 'offline', 'Restart lost offline mode')
        require(persistent_view(prepared()) == expected_view, 'Service restart changed preparation jobs or pins')
        time.sleep(args.egress_quiet_seconds)
        require_no_egress(before, ledger.read(), 'service restart')
        evidence = offline_traffic(client, prepared_https, prepared_http, misses)
        time.sleep(1)
        require_no_egress(before, ledger.read(), 'post-restart offline traffic')
        gui.open()
        ui.locale('en')
        h.wait_for('GUI after restart shows persisted pins', lambda: ui.pin_keys() == sorted(
            key for key, _ in expected_view['pins']))
        ui.reveal_item(url('/public.jpg'))
        h.wait_for('older job after restart is visibly Offline Ready', lambda: (
            lambda item: item and item['open'] and item['visible'] and item['ready'])(ui.gui_item(url('/public.jpg'))))
        gui.shot('13-after-service-restart-job', '#preparation-jobs')
        gui.shot('13-after-service-restart', '#preparation-pins')
        gui.close_window()
        require(cli('status')['running'], 'Closing GUI after restart stopped the proxy')
        require_no_egress(before, ledger.read(), 'GUI after service restart')
        passed('Canonical service restart preserves pins and prepared cache; no automatic egress; offline hits persist',
               evidence)
        report['result'] = final_result(not_covered)
    except Exception as error:
        report['result'] = 'fail'
        report['failure'] = {'type': type(error).__name__,
                             'message': str(error).replace(native().PASSWORD, '[redacted]') if _native else str(error)}
        if gui and gui.session:
            try:
                gui.shot('failure-state')
            except Exception as screenshot_error:
                report['failureScreenshotError'] = type(screenshot_error).__name__
        print('FAIL ' + report['failure']['message'], flush=True)
        raise
    finally:
        try:
            if gui:
                gui.cleanup()
        except Exception as cleanup_error:
            report['result'] = 'fail'
            report['cleanupFailure'] = {'type': type(cleanup_error).__name__}
            raise
        finally:
            write_json(artifacts / 'report.json', report)
    print(f'RESULT {report["result"]}', flush=True)
    return 0 if report['result'] == 'pass' else 2


if __name__ == '__main__':
    sys.exit(main())
