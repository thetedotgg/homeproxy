#!/usr/bin/env python3
"""Test the packaged sandbox in a disposable transient unit, without installing HomeProxy.

Requires passwordless sudo; creates only a unique /run/homeproxy-qa-* directory and
transient unit, removed on exit. Uses existing local accounts; no firewall/trust changes.
"""
import argparse
import configparser
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries-dir', type=Path, default=Path('target/debug'))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    subprocess.run(['sudo', '-n', 'true'], check=True)
    name = 'homeproxy-qa-' + uuid.uuid4().hex[:12]
    root = Path('/run') / name
    endpoint = root / 'run/control.sock'
    uid, gid = os.getuid(), os.getgid()
    shared_gid = grp.getgrnam('nogroup').gr_gid
    pwd.getpwnam('nobody')
    pwd.getpwnam('daemon')
    subprocess.run(['sudo', '-n', 'install', '-d', '-o', str(uid), '-g', str(gid), '-m', '0755', str(root)], check=True)
    results = []
    try:
        for binary in ('homeproxy', 'homeproxyd'):
            shutil.copy2(args.binaries_dir / binary, root / binary)
            (root / binary).chmod(0o755)
        unit = configparser.ConfigParser(interpolation=None)
        unit.optionxform = str
        unit.read('packaging/linux/homeproxy.service')
        replaced = {'ExecStart', 'User', 'Group', 'RuntimeDirectory', 'RuntimeDirectoryMode', 'StateDirectory', 'StateDirectoryMode', 'CacheDirectory', 'CacheDirectoryMode'}
        properties = [f'{key}={value}' for key, value in unit['Service'].items() if key not in replaced]
        properties += [f'User={uid}', f'Group={shared_gid}', f'ReadWritePaths={root}']
        command = ['sudo', '-n', 'systemd-run', '--quiet', '--unit', name]
        for value in properties:
            command += ['--property', value]
        command += [str(root / 'homeproxyd'), '--state-dir', str(root / 'state'), '--cache-dir', str(root / 'cache'), '--socket', str(endpoint), '--shared-socket']
        subprocess.run(command, check=True)

        def cli(*parts):
            result = subprocess.run([str(root / 'homeproxy'), '--socket', str(endpoint), '--json', *parts], capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, f'CLI failed: {result.stderr}'
            return json.loads(result.stdout)['result']

        def wait_for(predicate):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    if predicate():
                        return
                except (AssertionError, OSError, ValueError):
                    pass
                time.sleep(0.1)
            raise AssertionError('Transient systemd service did not reach expected state')

        wait_for(lambda: endpoint.exists() and cli('status')['platform'] == 'linux')
        assert cli('doctor')['health'] == 'ok'
        results.append('daemon starts under actual packaged sandbox restrictions')

        raw_client = '''import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect(sys.argv[1])
p=json.dumps({"version":1,"command":{"method":"status"}}).encode()
s.sendall(struct.pack("!I",len(p))+p)
def read(n):
 b=b""
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c: raise RuntimeError("truncated response")
  b+=c
 return b
r=json.loads(read(struct.unpack("!I",read(4))[0]))
assert "Ok" in r["result"]
assert "proxyPassword" not in r["result"]["Ok"]["settings"]
print("authorized")
'''
        authorized = subprocess.run(['sudo', '-n', '-u', 'nobody', '/usr/bin/python3', '-c', raw_client, str(endpoint)], capture_output=True, text=True, timeout=10)
        assert authorized.returncode == 0, 'Authorized group member could not use shared socket'
        denied = subprocess.run(['sudo', '-n', '-u', 'daemon', '/usr/bin/python3', '-c', raw_client, str(endpoint)], capture_output=True, text=True, timeout=10)
        assert denied.returncode != 0 and 'PermissionError' in denied.stderr
        results.append('real group member accepted and unrelated local UID denied by kernel')

        with socket.socket() as holder:
            holder.bind(('127.0.0.1', 0))
            port = holder.getsockname()[1]
        cli('config', 'set', 'proxyPort', str(port))
        assert cli('start')['running']
        assert cli('status')['availableAddresses'], 'AF_NETLINK address enumeration failed in sandbox'
        subprocess.run(['sudo', '-n', 'systemctl', 'restart', name], check=True)
        wait_for(lambda: cli('status')['running'])
        results.append('systemctl restart preserves enabled proxy and interface enumeration works')
        cli('stop')
        subprocess.run(['sudo', '-n', 'systemctl', 'restart', name], check=True)
        wait_for(lambda: not cli('status')['running'])
        results.append('explicit Stop remains disabled after systemctl restart')
        bad_run = root / 'bad-run'
        bad_run.mkdir(mode=0o750)
        subprocess.run(['sudo', '-n', 'chgrp', '0', str(bad_run)], check=True)
        rejected = subprocess.run([str(root/'homeproxyd'), '--state-dir', str(root/'bad-state'),
                                   '--cache-dir', str(root/'bad-cache'), '--socket', str(bad_run/'control.sock'),
                                   '--shared-socket'], capture_output=True, timeout=10)
        assert rejected.returncode != 0 and b'effective group' in rejected.stderr
        results.append('shared socket directory with an unexpected group is refused')
        for result in results:
            print('PASS ' + result)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({'passed': results, 'properties': properties, 'installation': False}, indent=2) + '\n')
    finally:
        subprocess.run(['sudo', '-n', 'systemctl', 'stop', name], capture_output=True)
        subprocess.run(['sudo', '-n', 'systemctl', 'reset-failed', name], capture_output=True)
        # All contents are owned by this test's UID; only /run entry removal needs sudo.
        for child in root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        subprocess.run(['sudo', '-n', 'rmdir', str(root)], check=True)


if __name__ == '__main__':
    main()
