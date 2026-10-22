#!/usr/bin/env python3
"""Exercise the real Tauri/WebKitGTK app with an isolated daemon via W3C WebDriver.

Use matching daemon, CLI and desktop binaries from the Linux build scripts.
Requires matching WebKitWebDriver, xvfb-run, and a D-Bus user session. No mocks.
The optional LAN setup scenario is restricted to the disposable homeproxy-qa VM.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--webdriver', type=Path, required=True)
    parser.add_argument('--binaries-dir', type=Path, default=Path('target/debug'))
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--test-lan-guide', action='store_true',
                        help='Exercise real LAN listener in disposable homeproxy-qa VM only')
    args = parser.parse_args()
    if args.test_lan_guide and socket.gethostname() != 'homeproxy-qa':
        parser.error('--test-lan-guide requires the disposable homeproxy-qa VM')
    source_binaries = args.binaries_dir.resolve()
    args.artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    visual_findings = []
    def check(label):
        checks.append(label)
        print('PASS ' + label, flush=True)
    def free_port():
        with socket.socket() as stream:
            stream.bind(('127.0.0.1', 0))
            return stream.getsockname()[1]
    def wait_for(predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, ValueError, AssertionError):
                pass
            time.sleep(.1)
        raise AssertionError('Timed out waiting for native desktop state')

    with tempfile.TemporaryDirectory(prefix='homeproxy-desktop-') as temporary:
        root = Path(temporary)
        # A package rebuild must not swap the executables halfway through a scenario.
        binaries = root / 'binaries'
        binaries.mkdir(mode=0o700)
        binary_hashes = {}
        for name in ('homeproxyd', 'homeproxy', 'klidna-sit'):
            source = source_binaries / name
            destination = binaries / name
            with source.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            shutil.copy2(source, destination)
            with destination.open('rb') as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == digest
            binary_hashes[name] = {'source':str(source), 'sha256':digest}
        endpoint = root / 'run/control.sock'
        env = dict(os.environ, TAURI_WEBVIEW_AUTOMATION='true', HOMEPROXY_SOCKET=str(endpoint),
                   XDG_CONFIG_HOME=str(root/'config'), XDG_DATA_HOME=str(root/'data'),
                   XDG_CACHE_HOME=str(root/'ui-cache'), LIBGL_ALWAYS_SOFTWARE='1')
        port = free_port()
        log = (args.artifacts/'native-desktop.log').open('w')
        driver = subprocess.Popen(['xvfb-run', '-a', str(args.webdriver.resolve()), f'--port={port}'],
                                  env=env, stdout=log, stderr=log, start_new_session=True)
        daemon = None
        session = None
        def request(method, path, body=None):
            data = json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request(f'http://127.0.0.1:{port}'+path, data=data,
                                              method=method, headers={'Content-Type':'application/json'})
            try:
                value = json.load(urllib.request.urlopen(request, timeout=30))['value']
            except urllib.error.HTTPError as error:
                raise AssertionError(error.read().decode()) from error
            return value
        def wd(method, path, body=None):
            return request(method, f'/session/{session}'+path, body)
        def js(script, *arguments):
            return wd('POST', '/execute/sync', {'script':script, 'args':list(arguments)})
        def element(selector):
            result = wd('POST', '/element', {'using':'css selector', 'value':selector})
            return result['element-6066-11e4-a52e-4f735466cecf']
        def click(selector):
            wd('POST', f'/element/{element(selector)}/click', {})
        def type_in(selector, value):
            target = element(selector)
            # Keep focus while replacing the value, as a user does. WebDriver
            # Avoid a separate clear()/blur before typing on a live-updated form.
            wd('POST', f'/element/{target}/click', {})
            # Explicit keyUp is needed: WebKitGTK 2.52.6 sendKeys does not
            # interpret the NULL key as releasing its sticky Control modifier.
            keys = [('keyDown', '\ue009'), ('keyDown', 'a'), ('keyUp', 'a'),
                    ('keyUp', '\ue009'), ('keyDown', '\ue003'), ('keyUp', '\ue003')]
            for char in str(value):
                keys.extend([('keyDown', char), ('keyUp', char)])
            wd('POST', '/actions', {'actions':[{'type':'key', 'id':'edit-input',
                'actions':[{'type':kind, 'value':key} for kind, key in keys]}]})
            wait_for(lambda: field(selector) == str(value))
        def shot(name):
            (args.artifacts/f'{name}.png').write_bytes(base64.b64decode(wd('GET', '/screenshot')))
        def field(selector):
            return js('return document.querySelector(arguments[0]).value', selector)
        def clipped_guide_states():
            return js('''return ["#guide-service-state", "#guide-lan-state", "#guide-address-state"]
                .flatMap(selector => {
                    const strong = document.querySelector(selector);
                    const cell = strong.parentElement.getBoundingClientRect();
                    const text = document.createRange();
                    text.selectNodeContents(strong);
                    const rendered = [...text.getClientRects()];
                    const style = getComputedStyle(strong);
                    const clipped = !strong.textContent.trim() || !rendered.length
                        || style.textOverflow === "ellipsis"
                        || strong.scrollWidth > strong.clientWidth + 1
                        || rendered.some(rect => rect.left < cell.left - 1
                            || rect.right > cell.right + 1
                            || rect.left < -1 || rect.right > innerWidth + 1);
                    return clipped ? [{selector, text:strong.textContent.trim(),
                        cellLeft:cell.left, cellRight:cell.right,
                        textRects:rendered.map(rect => [rect.left, rect.right])}] : [];
                })''')
        def cli(*parts):
            result = subprocess.run([str(binaries/'homeproxy'), '--socket', str(endpoint), '--json', *parts],
                                    text=True, capture_output=True, timeout=35, check=True)
            return json.loads(result.stdout)['result']
        def boot():
            process = subprocess.Popen([str(binaries/'homeproxyd'), '--state-dir', str(root/'state'),
                                        '--cache-dir', str(root/'cache'), '--socket', str(endpoint)],
                                       stdout=log, stderr=log)
            wait_for(lambda: process.poll() is None and endpoint.exists())
            return process
        try:
            wait_for(lambda: request('GET', '/status') is not None)
            created = request('POST', '/session', {'capabilities':{'alwaysMatch':{
                'webkitgtk:browserOptions':{'binary':str(binaries/'klidna-sit'), 'args':[]}}}})
            session = created['sessionId']
            user_agent = js('return navigator.userAgent')
            wait_for(lambda: js('return !!document.querySelector("#notice") && !document.querySelector("#notice").hidden'))
            assert 'systemctl' in js('return document.querySelector("#notice").innerText')
            shot('01-service-unavailable-en')
            check('real WebKitGTK window explains missing service without starting a private engine')
            daemon = boot()
            wait_for(lambda: js('return document.querySelector("#notice").hidden'))
            click('[data-locale="cs"]')
            wait_for(lambda: js('return document.documentElement.lang === "cs"'))
            wait_for(lambda: js('return !!document.querySelector("#guide-address-options .address-choice")'))
            adapter = js('''return [...document.querySelectorAll("#guide-address-options .address-choice")]
                .find(choice => /^(eth|en|wl)[a-z0-9]+$/i.test(choice.querySelector("small")?.textContent || ""))
                ?.querySelector("input")?.checked ?? null''')
            if adapter is not None:
                assert adapter, 'Linux home interface is visible but not selected by the guide'
                assert not js('return document.querySelector("#guide-prepare").disabled')
                check('Linux primary network adapter is selected in the native setup guide')
            assert js('return document.querySelector("#guide-https-mode option[value=inspect]").disabled')
            assert js('return document.querySelector("input[value=hotspot]").closest("label").hidden')
            check('Ubuntu guide visibly disables unsupported Inspect and hotspot setup')
            click('[data-page="home"]')
            wait_for(lambda: js('return !document.querySelector("#service-toggle").disabled'))
            assert js('return document.querySelector("#hide-to-tray").hidden')
            # Use a random free port instead of the user's normal proxy port.
            cli('config', 'set', 'proxyPort', str(free_port()))
            time.sleep(1.3)
            click('#service-toggle')
            wait_for(lambda: cli('status')['running'])
            shot('02-running-cs')
            check('Czech desktop starts the same daemon observed by CLI')
            click('[data-page="settings"]')
            assert js('return document.querySelector("#https-mode option[value=inspect]").disabled')
            changed_port = free_port()
            type_in('#proxy-port', changed_port)
            cli('config', 'set', 'adblockMode', '"strict"')
            click('#save-settings')
            wait_for(lambda: 'Zahodit' in js('return document.querySelector("#notice").innerText'))
            assert js('return document.querySelector("#proxy-port").value') == str(changed_port)
            assert cli('status')['settings']['proxyPort'] != changed_port
            shot('03-settings-conflict-cs')
            check('concurrent CLI edit is preserved and desktop draft survives rejected save')
            click('#discard-settings')
            wait_for(lambda: js('return document.querySelector("#settings-savebar").hidden && !document.querySelector("#proxy-port").disabled'))
            type_in('#proxy-port', changed_port)
            click('#save-settings')
            wait_for(lambda: cli('status')['settings']['proxyPort'] == changed_port)
            assert cli('status')['running']
            with socket.create_connection(('127.0.0.1', changed_port), timeout=5) as stream:
                stream.sendall(b'GET http://doubleclick.net/ HTTP/1.1\r\nHost: doubleclick.net\r\nConnection: close\r\n\r\n')
                assert b'403' in stream.recv(256)
            check('saving settings restarts the actual proxy on the selected port')
            assert field('#proxy-password')
            assert js('return document.querySelector("#proxy-password").type === "password"')
            old_credentials = cli('credentials', 'show')
            assert field('#proxy-password') == old_credentials['password']
            click('#rotate-password')
            wait_for(lambda: cli('credentials', 'show')['password'] != old_credentials['password'])
            new_credentials = cli('credentials', 'show')
            wait_for(lambda: field('#proxy-password') == new_credentials['password'])
            assert js('return document.querySelector("#proxy-password").type === "password"')
            assert cli('status')['running']
            assert 'proxyPassword' not in cli('status')['settings']
            check('desktop password rotation updates the daemon and keeps the key masked')

            original_port = cli('status')['settings']['proxyPort']
            type_in('#proxy-port', 0)
            wait_for(lambda: js('return document.querySelector("#save-settings").disabled'))
            assert js('return !!document.querySelector("#service-port-error").textContent.trim()')
            assert cli('status')['settings']['proxyPort'] == original_port
            shot('04-invalid-port-cs')
            click('#discard-settings')
            wait_for(lambda: field('#proxy-port') == str(original_port))
            if not js('return document.querySelector("#socks5-enabled").checked'):
                click('label[for="socks5-enabled"]')
            type_in('#socks5-port', original_port)
            wait_for(lambda: js('return document.querySelector("#save-settings").disabled'))
            assert js('return !!document.querySelector("#service-port-error").textContent.trim()')
            assert cli('status')['settings']['proxyPort'] == original_port
            click('#discard-settings')
            saved_socks = cli('status')['settings']
            wait_for(lambda: js('return document.querySelector("#settings-savebar").hidden')
                     and js('return document.querySelector("#socks5-enabled").checked') == saved_socks['socks5Enabled']
                     and field('#socks5-port') == str(saved_socks['socks5Port'])
                     and js('return document.querySelector("#notice").hidden'))
            check('invalid and duplicate ports are rejected before saving without changing daemon settings')

            with socket.socket() as occupied:
                occupied.bind(('127.0.0.1', 0))
                occupied.listen(1)
                blocked_port = occupied.getsockname()[1]
                type_in('#proxy-port', blocked_port)
                wait_for(lambda: not js('return document.querySelector("#save-settings").disabled'))
                assert field('#proxy-port') == str(blocked_port)
                click('#save-settings')
                wait_for(lambda: js('return document.querySelector("#notice").dataset.kind === "error"')
                         and not js('return document.querySelector("#save-settings").disabled'))
                port_error = js('return document.querySelector("#notice").textContent')
                assert 'Zvolený port už používá jiná služba.' in port_error, port_error
                assert 'operation_failed' not in port_error and 'Address already in use' not in port_error, port_error
                assert cli('status')['settings']['proxyPort'] == original_port
                assert cli('status')['running']
                assert field('#proxy-port') == str(blocked_port)
                wait_for(lambda: cli('status').get('lastError') is None
                         and cli('status').get('listenerError') is None
                         and cli('doctor')['health'] == 'ok')
                shot('05-occupied-port-cs')
                click('#discard-settings')
                wait_for(lambda: field('#proxy-port') == str(original_port)
                         and js('return document.querySelector("#settings-savebar").hidden')
                         and js('return document.querySelector("#notice").hidden'))
                assert cli('doctor')['health'] == 'ok'
                shot('06-discard-rollback-cs')
            type_in('#proxy-port', blocked_port)
            click('#save-settings')
            wait_for(lambda: cli('status')['settings']['proxyPort'] == blocked_port)
            assert cli('status')['running']
            check('occupied port reports a localized error, healthy rollback and discard; retry works after release')

            click('[data-page="home"]')
            click('#service-toggle')
            wait_for(lambda: not cli('status')['running'])
            assert cli('status')['settings']['enabled'] is False
            click('#service-toggle')
            wait_for(lambda: cli('status')['running'])
            check('native service switch stops and restarts the same daemon persistently')
            click('[data-locale="en"]')
            wait_for(lambda: js('return document.documentElement.lang === "en"'))
            click('[data-page="guide"]')
            shot('07-guide-en')
            clipped = clipped_guide_states()
            if clipped:
                visual_findings.append({'states':clipped,
                                        'screenshot':'07-guide-en.png', 'issue':'guide state text is visually clipped'})
                print('FINDING guide status is visually clipped: '+json.dumps(clipped), flush=True)
            assert not clipped, 'all guide state values must be fully visible'
            wd('POST', '/window/rect', {'width':780, 'height':640})
            assert js('return document.documentElement.scrollWidth <= innerWidth')
            shot('08-guide-min-en')
            clipped = clipped_guide_states()
            if clipped:
                visual_findings.append({'states':clipped,
                                        'screenshot':'08-guide-min-en.png', 'issue':'guide state text is clipped in minimum window'})
                print('FINDING minimum-window guide state is clipped: '+json.dumps(clipped), flush=True)
            assert not clipped, 'all guide state values must fit the minimum window'
            click('[data-page="settings"]')
            assert js('return document.documentElement.scrollWidth <= innerWidth')
            assert js('''return ["#proxy-port", "#socks5-port", "#proxy-user", "#proxy-password",
                "#https-mode", "#dns-mode"].every(selector => document.querySelector(selector).labels.length > 0)''')
            shot('09-settings-min-en')
            check('English guide and settings fit the minimum window and key fields have labels')
            click('[data-page="home"]')
            assert js('return document.documentElement.scrollWidth <= innerWidth')
            shot('10-small-window-en')
            # Keyboard interaction through WebDriver, then inspect actual focus.
            wd('POST', f'/element/{element("[data-page=home]")}/value', {'text':'\ue004'})
            assert js('return document.activeElement.matches("[data-page=settings]")')
            check('English UI fits the minimum-size window and keyboard navigation reaches settings')
            daemon.terminate()
            daemon.wait(timeout=15)
            wait_for(lambda: not js('return document.querySelector("#notice").hidden'))
            daemon = boot()
            wait_for(lambda: js('return document.querySelector("#notice").hidden'))
            assert cli('status')['running']
            check('desktop reconnects after daemon restart and persisted service resumes')
            if args.test_lan_guide:
                settings_before_guide = cli('status')['settings']
                assert not settings_before_guide['lanEnabled']
                assert settings_before_guide['listenIp'] is None
                assert settings_before_guide['listenIps'] == []
                click('[data-page="guide"]')
                wait_for(lambda: js('return !!document.querySelector("#guide-address-options input:checked")'))
                guide_ip = js('return document.querySelector("#guide-address-options input:checked").value')
                assert guide_ip in [entry['ip'] for entry in cli('status')['availableAddresses']]
                wait_for(lambda: not js('return document.querySelector("#guide-prepare").disabled'))
                click('#guide-prepare')
                wait_for(lambda: cli('status')['running']
                         and cli('status')['settings']['lanEnabled']
                         and cli('status')['settings']['listenIp'] == guide_ip
                         and guide_ip in cli('status')['settings']['listenIps'])
                assert cli('status')['settings']['proxyPort'] == settings_before_guide['proxyPort']
                with socket.create_connection((guide_ip, settings_before_guide['proxyPort']), timeout=5) as stream:
                    stream.sendall(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                    assert stream.makefile('rb').readline(1024).startswith(b'HTTP/1.1 407 '), 'LAN listener did not require proxy authentication'
                shot('11-guide-lan-vm-en')
                check('first guide LAN setup saves the selected address and opens a listener requiring proxy authentication')
            wd('DELETE', '/window')
            session = None
            assert cli('status')['running']
            check('closing the native desktop leaves the daemon and proxy running')
            (args.artifacts/'report.json').write_text(json.dumps({
                'checks':checks, 'visualFindings':visual_findings, 'binaries':binary_hashes,
                'capabilities':created['capabilities'],
                'userAgent':user_agent,
            }, indent=2)+'\n')
        finally:
            if session:
                try:
                    shot('failure-state')
                    wd('DELETE', '')
                except (OSError, ValueError, AssertionError):
                    pass
            if daemon is not None and daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=15)
            os.killpg(driver.pid, signal.SIGTERM)
            driver.wait(timeout=10)
            log.close()


if __name__ == '__main__':
    main()
