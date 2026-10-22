#!/usr/bin/env python3
"""Installed HomeProxy acceptance on the disposable homeproxy-qa VM's real Xorg :0.

Run as the graphical qa user with DISPLAY, XAUTHORITY and DBUS_SESSION_BUS_ADDRESS
from that session. Requires the installed /usr/bin binaries, WebKitWebDriver and
canonical homeproxy.service. Never starts a daemon or a virtual display.

The controller performs real fixture traffic when <phase>-ready.json appears,
then creates <phase>.done: guide (successful authenticated LAN HTTP), online
(warm HTTPS cache), offline (origin unavailable/cache hits/misses), restart
(restart canonical service and check offline traffic again). Markers are removed
before each phase to reject stale completion. Optional --traffic-hook receives
the phase and artifacts directory instead; it must exit successfully only after
those checks. Credentials stay in the service, not in marker/report files.

Example: DISPLAY=:0 python3 test-linux-gui-vm.py --ack-disposable-vm \
    --artifacts /home/qa/acceptance
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request


ELEMENT_KEY = 'element-6066-11e4-a52e-4f735466cecf'
SOCKET = Path('/run/homeproxy/control.sock')
# Disposable fixture credentials, never written to reports or driver logs.
USERNAME = 'qa-proxy'
PASSWORD = 'VmOnlyCache42_2026'
TEST_PROXY_PORT = 17893
INSPECT_HOSTS = ['cache.fixture.test', 'strict-untrusted.fixture.test']
INSPECT_TEXT = '\n'.join(INSPECT_HOSTS)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_for(label, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, urllib.error.URLError) as error:
            last_error = type(error).__name__
        time.sleep(.2)
    detail = f' (last transient error: {last_error})' if last_error else ''
    raise AssertionError(f'Timed out: {label}{detail}')


def command(*args, timeout=35):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    # Do not echo stdout/stderr: credentials or command payloads may be present.
    require(result.returncode == 0, f'Command {Path(args[0]).name} failed ({result.returncode})')
    return result.stdout


def cli(*args):
    value = json.loads(command('/usr/bin/homeproxy', '--json', *args))
    require(value.get('ok', True), 'Installed CLI returned an error')
    return value['result']


def service_pid():
    return int(command('systemctl', 'show', 'homeproxy.service', '--property=MainPID', '--value'))


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


class NativeGui:
    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.session = None
        with socket.socket() as stream:
            stream.bind(('127.0.0.1', 0))
            self.port = stream.getsockname()[1]
        self.log_path = artifacts / 'webdriver.log'
        self.log = self.log_path.open('w')
        env = dict(os.environ, TAURI_WEBVIEW_AUTOMATION='true')
        # Use qa's real installed desktop profile, including persisted guide state.
        self.driver = subprocess.Popen(
            ['/usr/bin/WebKitWebDriver', f'--port={self.port}'], env=env,
            stdout=self.log, stderr=self.log, start_new_session=True)

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}', data=data, method=method,
            headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                value = json.load(response)['value']
        except urllib.error.HTTPError as error:
            # WebDriver errors may echo input values. Preserve code/path only.
            raise AssertionError(f'WebDriver {method} {path} failed: HTTP {error.code}') from None
        # HTTP success unwraps a W3C value, not an application error envelope.
        # JavaScript may legitimately return any JSON value, including {error: ...}.
        return value

    def wd(self, method, path, body=None):
        require(self.session is not None, 'Native GUI session is not open')
        return self.request(method, f'/session/{self.session}{path}', body)

    def js(self, script, *args):
        return self.wd('POST', '/execute/sync', {'script': script, 'args': list(args)})

    def open(self):
        wait_for('native WebKitWebDriver ready', lambda: self.driver.poll() is None
                 and self.request('GET', '/status') is not None)
        result = self.request('POST', '/session', {'capabilities': {'alwaysMatch': {
            'webkitgtk:browserOptions': {'binary': '/usr/bin/klidna-sit', 'args': []}}}})
        self.session = result['sessionId']
        wait_for('installed GUI has loaded canonical daemon settings', lambda:
                 self.js('return !!document.querySelector("#guide-proxy-user-input")'
                         ' && !document.querySelector("#guide-proxy-user-input").disabled'
                         ' && !!document.querySelector("#guide-address-options input")'))

    def element(self, selector):
        return self.wd('POST', '/element', {'using': 'css selector', 'value': selector})[ELEMENT_KEY]

    def click(self, selector):
        wait_for(f'enabled native control {selector}', lambda: self.js(
            'const e=document.querySelector(arguments[0]); return !!e && !e.disabled;', selector))
        self.js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', selector)
        self.wd('POST', f'/element/{self.element(selector)}/click', {})

    def keys(self, characters):
        actions = []
        for char in characters:
            actions.extend([{'type': 'keyDown', 'value': char}, {'type': 'keyUp', 'value': char}])
        self.wd('POST', '/actions', {'actions': [{'type': 'key', 'id': 'native-edit', 'actions': actions}]})

    def field(self, selector):
        return self.js('return document.querySelector(arguments[0]).value', selector)

    def type_in(self, selector, value):
        self.click(selector)
        # WebKitGTK retains Control with sendKeys/NULL; release each modifier explicitly.
        actions = [('keyDown', '\ue009'), ('keyDown', 'a'), ('keyUp', 'a'),
                   ('keyUp', '\ue009'), ('keyDown', '\ue003'), ('keyUp', '\ue003')]
        for char in str(value):
            # Native WebKit ignores literal line feeds in W3C key actions.
            key = '\ue007' if char == '\n' else char
            actions.extend([('keyDown', key), ('keyUp', key)])
        self.wd('POST', '/actions', {'actions': [{'type': 'key', 'id': 'native-edit',
            'actions': [{'type': kind, 'value': char} for kind, char in actions]}]})
        wait_for(f'edited native field {selector}', lambda: self.field(selector) == str(value))

    def select(self, selector, value):
        options = self.js('return [...document.querySelector(arguments[0]).options]'
                          '.map(o=>({value:o.value,disabled:o.disabled}));', selector)
        index = next(i for i, option in enumerate(options) if option['value'] == value)
        require(not options[index]['disabled'], f'Native option {selector}/{value} is disabled')
        self.click(selector)
        self.keys(['\ue011'] + ['\ue015'] * index + ['\ue007'])
        wait_for(f'native selection {selector}/{value}', lambda: self.field(selector) == value)

    def checked(self, selector, desired):
        if self.js('return document.querySelector(arguments[0]).checked', selector) != desired:
            self.click(f'label[for="{selector[1:]}"]')
        wait_for(f'native checkbox {selector}', lambda: self.js(
            'return document.querySelector(arguments[0]).checked', selector) == desired)

    def page(self, page):
        self.click(f'[data-page="{page}"]')
        wait_for(f'native page {page}', lambda: self.js(
            'return document.querySelector(arguments[0]).classList.contains("is-active")', f'#{page}-page'))

    def shot(self, name, focus=None):
        if focus:
            self.js('document.querySelector(arguments[0]).scrollIntoView({block:"center"})', focus)
        require(self.js('return !document.body.innerText.includes(arguments[0]) && '
                       '[...document.querySelectorAll("input")].every(e=>'
                       'e.value!==arguments[0] || e.type==="password")', PASSWORD),
                'Refusing screenshot with visible fixture password')
        path = self.artifacts / f'{name}.png'
        path.write_bytes(base64.b64decode(self.wd('GET', '/screenshot')))
        path.chmod(0o600)

    def close_window(self):
        self.wd('DELETE', '/window')
        old_session = self.session
        self.session = None
        try:
            self.request('DELETE', f'/session/{old_session}')
        except AssertionError:
            # Closing the last native window can also remove the WebDriver session.
            pass

    def cleanup(self):
        if self.session:
            try:
                self.wd('DELETE', '')
            except (AssertionError, OSError, urllib.error.URLError):
                pass
            self.session = None
        if self.driver.poll() is None:
            os.killpg(self.driver.pid, signal.SIGTERM)
            try:
                self.driver.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.driver.pid, signal.SIGKILL)
                self.driver.wait(timeout=5)
        self.log.close()
        # Preserve diagnostics while ensuring WebKit cannot accidentally echo this key.
        self.log_path.write_text(self.log_path.read_text(errors='replace').replace(PASSWORD, '[redacted]'))
        self.log_path.chmod(0o600)


def check_environment():
    require(os.getuid() != 0, 'Run as graphical qa user, not root')
    require(os.environ.get('USER') == 'qa' or command('id', '-un').strip() == 'qa', 'Run as qa')
    require(os.environ.get('DISPLAY') == ':0', 'Requires the actual graphical display :0')
    require(not os.environ.get('HOMEPROXY_SOCKET'), 'Custom control sockets are forbidden')
    require(os.environ.get('DBUS_SESSION_BUS_ADDRESS'), 'Graphical D-Bus session environment is required')
    require('homeproxy-admin' in command('id', '-nG').split(), 'qa must be in homeproxy-admin')
    require(SOCKET.is_socket(), 'Canonical system service socket is unavailable')
    processes = command('ps', '-eo', 'comm,args')
    require(any(line.split()[0] == 'Xorg' and ':0' in line.split() for line in processes.splitlines()),
            'Actual Xorg :0 server is required')
    require(not any(line.split()[0] == 'Xvfb' for line in processes.splitlines()), 'Xvfb is forbidden')
    for name in ('homeproxy', 'homeproxyd', 'klidna-sit', 'WebKitWebDriver'):
        require(Path('/usr/bin', name).is_file(), f'Installed /usr/bin/{name} is required')
    require(command('systemctl', 'is-active', 'homeproxy.service').strip() == 'active',
            'Canonical service must be active')
    require('/usr/bin/homeproxyd --shared-socket' in command(
        'systemctl', 'show', 'homeproxy.service', '--property=ExecStart', '--value'),
        'Canonical installed daemon ExecStart is required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--ack-disposable-vm', action='store_true', required=True)
    parser.add_argument('--interface', default='eth0')
    parser.add_argument('--phase-timeout', type=int, default=240)
    parser.add_argument('--traffic-hook', type=Path, help='Executable controller hook: PHASE ARTIFACTS')
    args = parser.parse_args()
    # Reject other hosts before any artifact mutation or service/GUI operation.
    require(socket.gethostname() == 'homeproxy-qa', 'Requires the disposable homeproxy-qa VM')
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifacts.chmod(0o700)
    checks = []
    report = {'result': 'running', 'display': ':0', 'displayServer': 'Xorg',
              'socket': str(SOCKET), 'checks': checks, 'binarySha256': {}}
    # Invalidate a previous PASS before fallible VM environment checks.
    write_json(artifacts / 'report.json', report)
    gui = None

    def passed(label):
        checks.append(label)
        print('PASS ' + label, flush=True)
        write_json(artifacts / 'report.json', report)

    def phase(name):
        done = artifacts / f'{name}.done'
        done.unlink(missing_ok=True)
        state = cli('status')
        write_json(artifacts / f'{name}-ready.json', {
            'phase': name, 'proxyIp': state['settings']['listenIp'],
            'proxyPort': state['settings']['proxyPort'], 'username': USERNAME,
            'httpsMode': state['settings']['httpsMode'], 'cacheMode': state['settings']['cacheMode'],
            'publicCa': str(artifacts / 'public-ca.pem'), 'systemdMainPID': service_pid()})
        print(f'WAIT controller {name} traffic/restart checks', flush=True)
        if args.traffic_hook:
            command(str(args.traffic_hook.resolve()), name, str(artifacts), timeout=args.phase_timeout)
        else:
            wait_for(f'controller completion {name}.done', done.is_file, args.phase_timeout)

    def save(expected):
        gui.click('#save-settings')
        wait_for('GUI settings reached canonical daemon', lambda:
                 all(cli('status')['settings'].get(key) == value for key, value in expected.items()))
        wait_for('GUI saved draft is clean', lambda: gui.js(
            'return document.querySelector("#settings-savebar").hidden'))

    def persisted(expected):
        state = cli('status')
        require(state['running'] and state['settings'] == expected,
                'Canonical service did not preserve running state and saved settings')

    try:
        for phase_name in ('guide', 'online', 'offline', 'restart'):
            for marker in (f'{phase_name}-ready.json', f'{phase_name}.done'):
                (artifacts / marker).unlink(missing_ok=True)
        check_environment()
        report['binarySha256'] = {
            name: hashlib.sha256(Path('/usr/bin', name).read_bytes()).hexdigest()
            for name in ('klidna-sit', 'homeproxyd', 'homeproxy')}
        initial = cli('status')
        require(initial['settings']['httpsMode'] == 'tunnel', 'First-install default must be Tunnel')
        require(initial['settings']['cacheMode'] == 'online', 'First-install default must be online')
        require(not initial['settings']['lanEnabled'], 'First-install LAN must start disabled')
        require(initial['settings']['proxyPort'] != TEST_PROXY_PORT,
                'Guide test requires a nondefault proxy port')
        initial_pid = service_pid()
        require(initial_pid > 0, 'Canonical service has no MainPID')
        report['initialSystemdMainPID'] = initial_pid
        gui = NativeGui(artifacts)
        gui.open()
        require(gui.js('return document.querySelector("#guide-page").classList.contains("is-active")'),
                'First installed native launch did not open the setup guide')
        gui.click('[data-locale="en"]')
        wait_for('English native locale', lambda: gui.js('return document.documentElement.lang') == 'en')
        gui.shot('01-first-launch-guide', '#guide-step-connection')
        passed('First installed native GUI opens real setup guide with safe Tunnel/online/LAN-disabled defaults')

        gui.click('input[name="guide-connection"][value="sameWifi"]')
        selector = wait_for('guest LAN adapter in native guide', lambda: gui.js(
            'const c=[...document.querySelectorAll("#guide-address-options .address-choice")]'
            '.find(c=>c.querySelector("small")?.textContent===arguments[0]);'
            'return c?.querySelector("input")?.id ? "#"+c.querySelector("input").id : null;', args.interface))
        gui.click(selector)
        selected_ip = gui.field(selector)
        gui.type_in('#guide-proxy-port', TEST_PROXY_PORT)
        gui.checked('#guide-lan-auth-enabled', True)
        gui.checked('#guide-cache-enabled', True)
        gui.type_in('#guide-proxy-user-input', USERNAME)
        gui.type_in('#guide-proxy-password-input', PASSWORD)
        gui.select('#guide-https-mode', 'tunnel')
        gui.shot('02-guide-auth-masked', '#guide-access-controls')
        gui.click('#guide-prepare')
        def guide_started():
            state = cli('status')
            settings = state['settings']
            return (state['running'] and settings['lanEnabled']
                    and settings['listenIp'] == selected_ip
                    and settings['proxyPort'] == TEST_PROXY_PORT
                    and settings['lanAuthEnabled'] and settings['cacheEnabled'])
        wait_for('guide saves nondefault port, authentication, cache and selected LAN', guide_started)
        credentials = cli('credentials', 'show')
        require(credentials['username'] == USERNAME and credentials['password'] == PASSWORD,
                'Native setup fields did not configure real proxy authentication')
        require(service_pid() == initial_pid, 'GUI started a different daemon')
        wait_for('guide shows prepared instructions', lambda: gui.js(
            'return !document.querySelector("#guide-prepared-instructions").hidden'))
        gui.click('#guide-verify')
        wait_for('guide verification baseline captured', lambda: gui.js(
            'return document.querySelector("#guide-verification").dataset.state') == 'waiting')
        phase('guide')
        wait_for('guide observes successful real LAN request', lambda: gui.js(
            'return document.querySelector("#guide-verification").dataset.state') == 'ready')
        gui.shot('03-guide-verified', '#guide-verification')
        gui.click('#guide-finish')
        wait_for('completed guide returns home', lambda: gui.js(
            'return document.querySelector("#home-page").classList.contains("is-active")'))
        passed('Real native setup saves authenticated guest LAN settings and completes after successful LAN traffic')

        gui.page('settings')
        old_port = cli('status')['settings']['proxyPort']
        gui.type_in('#proxy-port', 0)
        wait_for('invalid port rejected in native settings', lambda: gui.js(
            'return document.querySelector("#save-settings").disabled && '
            '!!document.querySelector("#service-port-error").textContent.trim()'))
        require(cli('status')['settings']['proxyPort'] == old_port, 'Invalid UI draft reached daemon')
        gui.shot('04-invalid-port', '#service-port-error')
        gui.click('#discard-settings')
        wait_for('invalid draft discarded', lambda: gui.field('#proxy-port') == str(old_port))
        passed('Invalid native proxy port is rejected without changing daemon configuration')

        require(not cli('tls', 'status')['prepared'], 'Fresh installation unexpectedly has a prepared CA')
        gui.click('#prepare-tls')
        wait_for('native CA preparation persisted in service', lambda: cli('tls', 'status')['prepared'])
        require(cli('status')['settings']['httpsMode'] == 'tunnel', 'CA preparation enabled Inspect')
        require(not cli('status')['settings']['httpsClientTrustAcknowledged'], 'CA preparation declared client trust')
        # Observe the public Blob created by the real export handler. Keep the
        # browser download and actual native IPC intact; no fake invoke or daemon.
        gui.js('window.__qaPublicExport=null; window.__qaPublicExportError=false;'
               'const original=URL.createObjectURL.bind(URL); URL.createObjectURL=(blob)=>{'
               'if(blob.type==="application/x-pem-file") blob.text().then(text=>'
               'window.__qaPublicExport=text).catch(()=>window.__qaPublicExportError=true);'
               'return original(blob);};')
        gui.click('#export-tls')
        exported = wait_for('native public CA export Blob', lambda: gui.js('return window.__qaPublicExport'))
        require(exported.startswith('-----BEGIN CERTIFICATE-----') and 'PRIVATE KEY' not in exported,
                'Native export did not contain only a public certificate')
        public_ca = artifacts / 'public-ca.pem'
        public_ca.write_text(exported)
        public_ca.chmod(0o600)
        cli_ca = artifacts / 'cli-public-ca.pem'
        cli_ca.unlink(missing_ok=True)
        cli('tls', 'export', '--format', 'pem', '--output', str(cli_ca))
        require(cli_ca.read_text() == exported, 'Native GUI and canonical CLI export different public CAs')
        report['tlsFingerprint'] = cli('tls', 'status')['sha256Fingerprint']
        gui.shot('05-public-ca-prepared', '#tls-authority-state')
        passed('Native CA preparation preserves Tunnel/trust defaults; actual GUI public export matches canonical CLI')

        gui.type_in('#https-inspect-hosts', INSPECT_TEXT)
        gui.select('#https-mode', 'inspect')
        wait_for('Inspect cannot save without trust declaration', lambda: gui.js(
            'return document.querySelector("#save-settings").disabled && '
            '!!document.querySelector("#offline-settings-error").textContent.trim()'))
        require(cli('status')['settings']['httpsMode'] == 'tunnel', 'Unsafe Inspect draft reached service')
        gui.checked('#https-trust-ack', True)
        gui.type_in('#offline-stale-hours', '24')
        save({'httpsMode': 'inspect', 'httpsInspectHosts': INSPECT_HOSTS,
              'httpsClientTrustAcknowledged': True, 'offlineMaxStaleHours': 24})
        gui.shot('06-inspect-allowlist', '#https-inspect-hosts')
        phase('online')
        passed('Native Inspect requires explicit trust and persists only the fixture allowlist; controller online traffic completed')

        gui.select('#cache-mode', 'offline')
        save({'cacheMode': 'offline'})
        gui.shot('07-offline-settings', '#cache-mode')
        phase('offline')
        saved = cli('status')['settings']
        passed('Native offline mode persisted to canonical daemon; controller unavailable-origin traffic completed')

        gui.page('home')
        gui.click('#service-toggle')
        wait_for('native stop reaches canonical daemon', lambda: not cli('status')['running'])
        require(service_pid() == initial_pid, 'Native stop terminated system daemon')
        gui.shot('08-service-stopped')
        gui.click('#service-toggle')
        wait_for('native start reaches canonical daemon', lambda: cli('status')['running'])
        require(service_pid() == initial_pid, 'Native start replaced system daemon')
        gui.shot('09-service-resumed')
        passed('Native Stop/Start controls the proxy inside the same canonical system daemon')

        gui.close_window()
        persisted(saved)
        require(service_pid() == initial_pid, 'Closing native window terminated or replaced daemon')
        passed('Closing the actual native GUI preserves running daemon and all saved settings')
        gui.open()
        require(gui.js('return document.querySelector("#home-page").classList.contains("is-active")'),
                'Completed guide state did not persist across native reopen')
        gui.page('settings')
        wait_for('native persisted Inspect/offline controls', lambda:
                 gui.field('#https-mode') == 'inspect' and gui.field('#cache-mode') == 'offline'
                 and gui.field('#https-inspect-hosts') == INSPECT_TEXT
                 and gui.field('#offline-stale-hours') == '24')
        require(gui.js('return document.querySelector("#https-trust-ack").checked'), 'Trust declaration did not persist')
        require(gui.field('#proxy-password') == PASSWORD, 'Masked authentication did not persist on reopen')
        gui.shot('10-native-reopen-persisted', '#cache-mode')
        # Resize the real native window; record its actual viewport, not an emulated browser.
        original_rect = gui.wd('GET', '/window/rect')
        gui.wd('POST', '/window/rect', {'width': 800, 'height': 740})
        report['narrowViewport'] = gui.js('return {width:innerWidth,height:innerHeight,'
                                         'documentWidth:document.documentElement.scrollWidth}')
        gui.shot('11-native-narrow-settings', '#cache-mode')
        gui.wd('POST', '/window/rect', {key: original_rect[key] for key in ('x', 'y', 'width', 'height')})
        persisted(saved)
        passed('Native reopen preserves completed guide, masked authentication, Inspect allowlist and offline controls')
        gui.close_window()
        phase('restart')
        wait_for('canonical service available after controller restart', lambda: SOCKET.is_socket()
                 and service_pid() > 0 and service_pid() != initial_pid)
        persisted(saved)
        report['restartedSystemdMainPID'] = service_pid()
        gui.open()
        gui.page('settings')
        wait_for('native controls after actual service restart', lambda: gui.field('#cache-mode') == 'offline'
                 and gui.field('#https-mode') == 'inspect' and gui.field('#https-inspect-hosts') == INSPECT_TEXT)
        gui.shot('12-service-restart-persisted', '#cache-mode')
        gui.close_window()
        persisted(saved)
        passed('Actual canonical system service restart preserves configuration and native offline/Inspect controls')
        report['result'] = 'pass'
    except Exception as error:
        report['result'] = 'fail'
        report['failure'] = {'type': type(error).__name__, 'message': str(error).replace(PASSWORD, '[redacted]')}
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
            report['cleanupFailure'] = {
                'type': type(cleanup_error).__name__,
                'message': str(cleanup_error).replace(PASSWORD, '[redacted]')}
            raise
        finally:
            write_json(artifacts / 'report.json', report)


if __name__ == '__main__':
    main()
