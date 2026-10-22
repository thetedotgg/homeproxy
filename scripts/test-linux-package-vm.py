#!/usr/bin/env python3
"""Install, reboot, upgrade and purge packages in an explicitly disposable Ubuntu VM.

Requires a pre-created VM named homeproxy-qa, SSH key auth, and passwordless sudo.
NEVER point this at a user workstation or production server. The host is untouched.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--packages', type=Path, default=Path('target/linux-package'))
    parser.add_argument('--ack-disposable-vm', action='store_true', required=True)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    options = ['-i', str(args.identity), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
               '-o', 'ConnectTimeout=4', '-o', 'StrictHostKeyChecking=accept-new',
               '-o', f'UserKnownHostsFile={args.artifacts / "known_hosts"}', '-o', 'LogLevel=ERROR']
    checks = []
    log = (args.artifacts/'lifecycle.log').open('w')
    def ssh(command, expected=0, timeout=180):
        result = subprocess.run(['ssh', *options, '-p', str(args.port), 'qa@127.0.0.1', command],
                                text=True, capture_output=True, timeout=timeout)
        if expected is not None and result.returncode != expected:
            log.write(result.stdout + result.stderr);log.flush()
            raise AssertionError(f'VM command failed ({result.returncode}): {command}\n{result.stderr[-1500:]}')
        return result
    def check(label):
        checks.append(label);print('PASS '+label, flush=True)
        (args.artifacts/'report.json').write_text(json.dumps({'checks':checks,'complete':False},indent=2)+'\n')
    def wait_ready(previous_boot=None):
        deadline = time.monotonic()+120
        while time.monotonic()<deadline:
            try:
                result=ssh('cat /proc/sys/kernel/random/boot_id', expected=None, timeout=8)
            except subprocess.TimeoutExpired:
                continue
            if result.returncode==0 and (previous_boot is None or result.stdout.strip()!=previous_boot):
                return result.stdout.strip()
            time.sleep(1)
        raise AssertionError('VM did not boot/reboot within 120s')
    def cli(*parts, expected=0):
        result=ssh('homeproxy --json '+shlex.join(parts),expected=expected)
        value=json.loads(result.stdout)
        return value['result'] if expected==0 else value['error']
    def system_state(state, active):
        assert ssh('systemctl is-enabled homeproxy',expected=None).stdout.strip()==state
        assert ssh('systemctl is-active homeproxy',expected=None).stdout.strip()==active
    def install(path, downgrade=False):
        result=ssh('sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y '+
                   ('--allow-downgrades ' if downgrade else '')+shlex.quote(path), timeout=600)
        log.write(result.stdout+result.stderr);log.flush()
    try:
        wait_ready()
        assert ssh('hostname').stdout.strip()=='homeproxy-qa', 'Refusing non-QA host'
        ssh('cloud-init status --wait',timeout=180)
        environment=ssh('cat /etc/os-release; uname -a').stdout
        (args.artifacts/'environment.txt').write_text(environment)
        assert ssh('dpkg-query -W homeproxy 2>/dev/null',expected=None).returncode!=0, 'VM is not fresh'
        def one_package(pattern):
            matches=list(args.packages.glob(pattern))
            assert len(matches)==1, f'Expected exactly one package for {pattern}, got {matches}'
            return matches[0].resolve()
        server=one_package('homeproxy_[0-9]*_amd64.deb')
        desktop=one_package('homeproxy-desktop_[0-9]*_amd64.deb')
        version=subprocess.check_output(['dpkg-deb','-f',str(server),'Version'],text=True).strip()
        with tempfile.TemporaryDirectory(prefix='homeproxy-upgrade-') as temporary:
            temporary=Path(temporary)
            upgrades=[]
            for index in (0,1,2):
                stage=temporary/f'stage{index}'
                subprocess.run(['dpkg-deb','-R',str(server),str(stage)],check=True,capture_output=True)
                control=stage/'DEBIAN/control'
                control.write_text(control.read_text().replace(f'Version: {version}\n',f'Version: {version}+qa{index}\n'))
                upgrade=temporary/f'upgrade{index}.deb'
                subprocess.run(['dpkg-deb','--build','--root-owner-group',str(stage),str(upgrade)],check=True,capture_output=True)
                upgrades.append(upgrade)
            ssh('mkdir -p /var/tmp/homeproxy-qa-packages')
            for local, remote in [(server,'server.deb'),(desktop,'desktop.deb'),(upgrades[0],'upgrade0.deb'),(upgrades[1],'upgrade1.deb'),(upgrades[2],'upgrade2.deb')]:
                subprocess.run(['scp',*options,'-P',str(args.port),str(local),f'qa@127.0.0.1:/var/tmp/homeproxy-qa-packages/{remote}'],check=True,capture_output=True)
        helper=Path(__file__).with_name('test-linux-installed-traffic.py').resolve()
        subprocess.run(['scp',*options,'-P',str(args.port),str(helper),'qa@127.0.0.1:/var/tmp/homeproxy-qa-packages/traffic.py'],check=True,capture_output=True)
        log.write(ssh('sudo apt-get update',timeout=300).stdout);log.flush()
        install('/var/tmp/homeproxy-qa-packages/server.deb')
        system_state('enabled','active')
        assert cli('status',expected=4)['code']=='permission_denied'
        ssh('sudo usermod -aG homeproxy-admin qa')
        initial=cli('status')
        assert not initial['running'] and not initial['settings']['enabled']
        assert 'proxyPassword' not in initial['settings']
        assert cli('doctor')['health']=='ok'
        check('clean server install starts daemon with proxy disabled; only authorized group can control it')
        ssh('sudo useradd --system --no-create-home --shell /usr/sbin/nologin qa-untrusted')
        result=ssh('sudo -u qa-untrusted homeproxy --json status',expected=4)
        assert json.loads(result.stdout)['error']['code']=='permission_denied'
        ownership=ssh("sudo stat -c '%U:%G %a' /run/homeproxy/control.sock /var/lib/homeproxy /var/cache/homeproxy /var/lib/homeproxy/settings.json").stdout.splitlines()
        assert ownership==['homeproxy:homeproxy-admin 660','homeproxy:homeproxy-admin 700','homeproxy:homeproxy-admin 700','homeproxy:homeproxy-admin 600'],ownership
        assert ssh("ldd /usr/bin/homeproxyd /usr/bin/homeproxy | grep -Ei 'gtk|webkit|not found'",expected=None).returncode==1
        check('real service identity and canonical socket permissions isolate a second local user; no GUI dependency')
        cli('config','set','proxyPort','18179');cli('config','set','cacheEnabled','true');cli('start')
        assert cli('status')['running']
        before=ssh('sudo sha256sum /var/lib/homeproxy/settings.json').stdout.split()[0]
        ssh('sudo systemctl restart homeproxy')
        assert cli('status')['running']
        boot=ssh('cat /proc/sys/kernel/random/boot_id').stdout.strip()
        ssh('sudo systemctl reboot',expected=None)
        wait_ready(boot)
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            probe=ssh('homeproxy --json status',expected=None)
            if probe.returncode==0 and json.loads(probe.stdout)['result']['running']:break
            time.sleep(.2)
        else:raise AssertionError('Saved enabled proxy did not recover after VM reboot')
        assert ssh('sudo sha256sum /var/lib/homeproxy/settings.json').stdout.split()[0]==before
        ssh("python3 - <<'QA'\nimport socket\nwith socket.create_connection(('127.0.0.1',18179), timeout=5) as s:\n s.sendall(b'GET http://doubleclick.net/ HTTP/1.1\\r\\nHost: doubleclick.net\\r\\nConnection: close\\r\\n\\r\\n')\n assert b'403' in s.recv(256)\nQA")
        check('actual VM reboot restores enabled proxy and exact persisted settings')
        ssh('sudo python3 /var/tmp/homeproxy-qa-packages/traffic.py --ack-disposable-vm --report /var/tmp/homeproxy-qa-packages/traffic-report.json')
        (args.artifacts/'installed-traffic.json').write_text(ssh('cat /var/tmp/homeproxy-qa-packages/traffic-report.json').stdout)
        assert ssh('sudo sha256sum /var/lib/homeproxy/settings.json').stdout.split()[0]==before
        check('installed sandbox forwards real HTTP, CONNECT and SOCKS5 payloads and restores exact configuration')
        old_pid=ssh('systemctl show -p MainPID --value homeproxy').stdout.strip()
        install('/var/tmp/homeproxy-qa-packages/upgrade0.deb')
        system_state('enabled','active')
        assert cli('status')['running'] and cli('doctor')['health']=='ok'
        assert ssh('systemctl show -p MainPID --value homeproxy').stdout.strip()!=old_pid
        assert '(deleted)' not in ssh('sudo readlink /proc/$(systemctl show -p MainPID --value homeproxy)/exe').stdout
        assert ssh('sudo sha256sum /var/lib/homeproxy/settings.json').stdout.split()[0]==before
        check('active enabled upgrade replaces the running daemon and retains healthy proxy and exact settings')
        cli('stop');ssh('sudo systemctl restart homeproxy');assert not cli('status')['running']
        cli('start')
        ssh('sudo systemctl disable --now homeproxy')
        install('/var/tmp/homeproxy-qa-packages/upgrade1.deb')
        system_state('disabled','inactive')
        assert ssh('sudo sha256sum /var/lib/homeproxy/settings.json').stdout.split()[0]==before
        check('real package upgrade preserves administrator-disabled unit and configuration')
        ssh('sudo systemctl mask homeproxy')
        install('/var/tmp/homeproxy-qa-packages/upgrade2.deb')
        system_state('masked','inactive')
        check('real package upgrade preserves administrator mask')
        ssh('sudo systemctl unmask homeproxy; sudo systemctl enable --now homeproxy')
        assert cli('status')['running']
        ssh('sudo env DEBIAN_FRONTEND=noninteractive apt-get remove -y homeproxy',timeout=120)
        assert ssh('test -e /usr/bin/homeproxy',expected=None).returncode!=0
        assert ssh('systemctl is-active homeproxy',expected=None).stdout.strip()=='inactive'
        assert ssh('test -S /run/homeproxy/control.sock',expected=None).returncode!=0
        ssh("python3 - <<'QA'\nimport socket\ns=socket.socket();s.settimeout(2)\nassert s.connect_ex(('127.0.0.1',18179))!=0\nQA")
        boot=ssh('cat /proc/sys/kernel/random/boot_id').stdout.strip()
        ssh('sudo systemctl reboot',expected=None);wait_ready(boot)
        assert ssh('systemctl is-active homeproxy',expected=None).stdout.strip()=='inactive'
        check('remove stops daemon and listeners and prevents service startup after reboot')
        assert ssh('sudo test -f /var/lib/homeproxy/settings.json').returncode==0
        install('/var/tmp/homeproxy-qa-packages/server.deb')
        assert cli('status')['running']
        assert ssh('sudo sha256sum /var/lib/homeproxy/settings.json').stdout.split()[0]==before
        check('remove/reinstall keeps private state and safely resumes the previous proxy configuration')
        ssh('sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y homeproxy',timeout=120)
        assert ssh('sudo test -f /var/lib/homeproxy/settings.json').returncode==0
        assert ssh('test -L /etc/systemd/system/homeproxy.service',expected=None).returncode!=0
        install('/var/tmp/homeproxy-qa-packages/server.deb')
        assert cli('status')['running']
        check('purge clears package mask while retaining documented recovery data; reinstall works')
        install('/var/tmp/homeproxy-qa-packages/desktop.deb')
        assert ssh('dpkg-query -W -f=\'${Version}\' homeproxy-desktop').stdout==version
        assert ssh("ldd /usr/bin/klidna-sit | grep 'not found'",expected=None).returncode==1
        assert ssh('test -f /usr/share/applications/Homeproxy\\ Desktop.desktop',expected=None).returncode==0 or ssh("find /usr/share/applications -iname '*homeproxy*' -print").stdout
        check('desktop package installs on clean Ubuntu with resolvable native libraries and launcher')
        (args.artifacts/'systemd-security.txt').write_text(ssh('sudo systemd-analyze security homeproxy.service --no-pager',expected=None).stdout)
        (args.artifacts/'journal.txt').write_text(ssh('sudo journalctl -u homeproxy --no-pager -n 120').stdout)
        packages={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (server,desktop)}
        (args.artifacts/'report.json').write_text(json.dumps({'checks':checks,'complete':True,'packages':packages,'environment':environment},indent=2)+'\n')
    except Exception as error:
        (args.artifacts/'report.json').write_text(json.dumps({'checks':checks,'complete':False,'error':str(error)},indent=2)+'\n')
        for name, command in [('failure-journal.txt','sudo journalctl -u homeproxy --no-pager -n 150'),
                              ('failure-service.txt','systemctl status homeproxy --no-pager; dpkg-query -W homeproxy homeproxy-desktop')]:
            try:
                result=ssh(command,expected=None,timeout=15)
                (args.artifacts/name).write_text(result.stdout+result.stderr)
            except Exception:
                pass
        raise
    finally:
        log.close()


if __name__=='__main__':
    main()
