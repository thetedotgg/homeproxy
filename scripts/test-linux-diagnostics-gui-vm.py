#!/usr/bin/env python3
"""Installed diagnostics GUI acceptance on disposable homeproxy-qa / Xorg :0.

Uses native Tauri IPC and real files/service. Temporarily stops the QA system
service to verify a clearly partial export; restores it even on failure.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess

spec = importlib.util.spec_from_file_location('gui_fixture', Path(__file__).with_name('test-linux-gui-vm.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
require, wait_for, cli = fixture.require, fixture.wait_for, fixture.cli


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ack-disposable-vm', action='store_true', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    require(socket.gethostname() == 'homeproxy-qa', 'Disposable VM only')
    fixture.check_environment()
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
    gui = fixture.NativeGui(artifacts)
    manager = subprocess.Popen(['openbox'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    checks = []
    report = {'result': 'running', 'display': ':0', 'displayServer': 'Xorg', 'checks': checks}
    pid_before = fixture.service_pid()
    initial = cli('status')
    require(initial['serviceVersion'] == '1.2.3', 'Matching installed 1.2.3 service required')
    original_running = initial['running']
    original_recovery = initial['settings']['automaticRecovery']
    restored_service = False

    def export(partial):
        old_path = gui.js('return document.querySelector("#diagnostics-export-path").value')
        gui.click('#export-diagnostics')
        path = Path(wait_for('native export saved a new path', lambda: gui.js(
            'const p=document.querySelector("#diagnostics-export-path"); return p.value && p.value!==arguments[0] && p.value;', old_path)))
        require(path.parent == Path('/home/qa/Downloads') and path.is_file(), 'Actual Downloads file required')
        require(path.stat().st_mode & 0o777 == 0o600, 'Private native export permissions required')
        value = json.loads(path.read_text())
        require(value['partial'] is partial and value['guiVersion']=='1.2.3', 'Full/partial export metadata')
        require(bool(value.get('current')) != partial, 'Partial file cannot claim daemon state')
        require(fixture.PASSWORD not in path.read_text(), 'Fixture password leaked in export')
        if partial:
            require(set(value) == {'errorCode','guiVersion','exportedAtUnixMs','platform','partial'}, 'Unexpected partial data')
        checks.append('partial native file' if partial else 'full native file')
        return path

    try:
        gui.open()
        gui.page('home')
        gui.click('[data-locale="cs"]')
        wait_for('CZ diagnostics', lambda: gui.js('return document.documentElement.lang === "cs" && !!document.querySelector("#export-diagnostics")'))
        gui.page('home')
        first = export(False)
        second = export(False)
        require(first != second and first.is_file(), 'Exports must not overwrite earlier files')
        checks.append('no clobber')
        gui.shot('01-diagnostics-cs', '#diagnostics-card')
        gui.checked('#automatic-recovery', not original_recovery)
        gui.click('#diagnostics-save-settings')
        wait_for('real persisted watchdog toggle', lambda: cli('status')['settings']['automaticRecovery'] == (not original_recovery))
        gui.checked('#automatic-recovery', original_recovery)
        gui.click('#diagnostics-save-settings')
        wait_for('watchdog setting restored', lambda: cli('status')['settings']['automaticRecovery'] == original_recovery)
        checks.append('native toggle persisted through daemon')
        gui.click('[data-locale="en"]')
        wait_for('EN diagnostics', lambda: gui.js('return document.documentElement.lang === "en"'))
        gui.page('home')
        export(False)
        gui.shot('02-diagnostics-en', '#diagnostics-card')
        gui.page('guide')
        wait_for('guide service is initially enabled', lambda: gui.js('return document.querySelector("#guide-service-state").dataset.state === "ready";'))
        subprocess.run(['sudo','systemctl','stop','homeproxy.service'], check=True, timeout=30, capture_output=True)
        wait_for('unavailable local status', lambda: gui.js('return document.querySelector("#diagnostics-health-state").dataset.state === "unavailable"'), timeout=40)
        wait_for('unreachable service cannot display a cached On status', lambda: gui.js('const toggle=document.querySelector("#service-toggle"); return toggle.disabled && toggle.getAttribute("aria-pressed") === "mixed" && !toggle.classList.contains("is-on");'), timeout=40)
        wait_for('guide service reflects unavailability while open', lambda: gui.js('const state=document.querySelector("#guide-service-state"); return state.dataset.state === "pending" && state.textContent === document.querySelector("#service-label").textContent;'), timeout=40)
        gui.shot('03-guide-service-unavailable', '#guide-service-state')
        gui.page('home')
        export(True)
        gui.shot('03-service-unavailable-partial', '#diagnostics-card')
        checks.append('real unavailable service leaves export usable')
        subprocess.run(['sudo','systemctl','start','homeproxy.service'], check=True, timeout=30, capture_output=True)
        restored_service = True
        def restored_status():
            # systemctl start returns before the daemon's control socket is ready.
            # Treat that real startup interval as pending, then verify its JSON.
            result = subprocess.run(['/usr/bin/homeproxy', '--json', 'status'], capture_output=True, text=True, timeout=35)
            if result.returncode != 0:
                return False
            value = json.loads(result.stdout)
            return value.get('ok', True) and value.get('result', {}).get('serviceVersion') == '1.2.3'
        wait_for('daemon restored', restored_status)
        wait_for('desktop reconnected', lambda: gui.js('return !document.querySelector("#automatic-recovery").disabled'), timeout=40)
        wait_for('guide service returns to enabled', lambda: gui.js('return document.querySelector("#guide-service-state").dataset.state === "ready";'), timeout=40)
        pid_after_restore = fixture.service_pid()
        gui.close_window()
        require(fixture.service_pid() == pid_after_restore, 'Closing native GUI restarted daemon')
        require(cli('status')['running'] == original_running, 'GUI lifecycle changed proxy intent')
        checks.append('closing GUI preserves service and proxy intent')
        report.update(result='pass', initialPid=pid_before, restoredPid=pid_after_restore)
    finally:
        if not restored_service:
            subprocess.run(['sudo','systemctl','start','homeproxy.service'], timeout=30, capture_output=True)
        gui.cleanup()
        manager.terminate()
        manager.wait(timeout=10)
        (artifacts/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        (artifacts/'report.json').chmod(0o600)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
