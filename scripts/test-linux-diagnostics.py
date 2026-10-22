#!/usr/bin/env python3
"""Exercise capture-before-recovery on a real, isolated unprivileged daemon.

A test-only libc interposer makes just the fixture HTTP listener temporarily
stop accepting. A runtime rebind clears that fault. No app hooks, production
service, firewall changes, WAN targets or installed settings are used.
"""
import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

INTERPOSER = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static int fault_port(void) {
    const char *p=getenv("HP_QA_FAULT_MARKER");
    if (!p) return 0;
    FILE *f=fopen(p,"r"); if (!f) return 0;
    int port=0; (void)fscanf(f,"%d",&port); fclose(f); return port;
}
static int blocked(int fd) {
    int port=fault_port(); if (!port) return 0;
    struct sockaddr_in a; socklen_t n=sizeof(a);
    return getsockname(fd,(struct sockaddr *)&a,&n)==0 && a.sin_family==AF_INET && ntohs(a.sin_port)==port;
}
int accept4(int fd,struct sockaddr *a,socklen_t *n,int flags) {
    static int (*real)(int,struct sockaddr *,socklen_t *,int);
    if (!real) real=dlsym(RTLD_NEXT,"accept4");
    if (blocked(fd)) {errno=EAGAIN;return -1;} return real(fd,a,n,flags);
}
int accept(int fd,struct sockaddr *a,socklen_t *n) {
    static int (*real)(int,struct sockaddr *,socklen_t *);
    if (!real) real=dlsym(RTLD_NEXT,"accept");
    if (blocked(fd)) {errno=EAGAIN;return -1;} return real(fd,a,n);
}
int bind(int fd,const struct sockaddr *a,socklen_t n) {
    static int (*real)(int,const struct sockaddr *,socklen_t);
    if (!real) real=dlsym(RTLD_NEXT,"bind");
    int result=real(fd,a,n);
    int port=fault_port();
    if (result==0 && port && a->sa_family==AF_INET && ntohs(((const struct sockaddr_in *)a)->sin_port)==port) {
        const char *path=getenv("HP_QA_FAULT_MARKER");
        char evidence[4096]; snprintf(evidence,sizeof(evidence),"%s.rebound",path);
        int f=open(evidence,O_WRONLY|O_CREAT|O_EXCL,0600);
        if(f>=0){struct timespec t;clock_gettime(CLOCK_REALTIME,&t);char b[80];int size=snprintf(b,sizeof(b),"%ld.%09ld\n",t.tv_sec,t.tv_nsec);(void)write(f,b,size);close(f);}
        unlink(path);
    }
    return result;
}
'''


async def eventually(label, operation, predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = await operation()
        if predicate(value):
            return value
        await asyncio.sleep(.2)
    raise AssertionError(f'Timed out: {label}')


async def run(args):
    assert os.getuid() != 0, 'Use an unprivileged user'
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    spec = importlib.util.spec_from_file_location('stall_fixture', Path(__file__).with_name('test-linux-http-stall.py'))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    report = {'purpose': 'isolated real daemon capture-before-recovery',
              'binaryHashes': {n: hashlib.sha256((args.bin_dir/n).read_bytes()).hexdigest()
                               for n in ('homeproxyd', 'homeproxy')}}
    with tempfile.TemporaryDirectory(prefix='hp-watchdog-fault-') as temporary:
        root = Path(temporary)
        source, library, marker = root/'fault.c', root/'fault.so', root/'fault'
        source.write_text(INTERPOSER)
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        str(source), '-ldl', '-o', str(library)], check=True, timeout=20)
        saved_env = {k: os.environ.get(k) for k in ('LD_PRELOAD', 'HP_QA_FAULT_MARKER')}
        assert saved_env['LD_PRELOAD'] is None, 'Do not replace another interposer'
        os.environ.update(LD_PRELOAD=str(library), HP_QA_FAULT_MARKER=str(marker))
        try:
            async with fixture.fixture(args.bin_dir, output) as (daemon, invoke, request, errors):
                report['daemonPid'] = daemon.pid
                status = lambda: invoke('diagnostics', 'status')
                # Generation may first be observed on the next 15s tick, and the
                # 30s warmup boundary can fall just after a tick under build load.
                await eventually('warm local probe', status, lambda v: v['state']=='healthy', 85)
                settings = (await invoke('status'))['settings']
                marker.write_text(str(settings['proxyPort']))
                marker.chmod(0o600)
                # The fixed listener now accepts TCP handshakes but cannot answer.
                await eventually('automatic recovery', status, lambda v: v['recoveryCount'] >= 1 and v['state']=='healthy', 100)
                assert not marker.exists(), 'runtime did not rebind the failed listener'
                assert daemon.returncode is None, 'daemon was restarted or exited'
                await request('127.0.0.4', 'healthy')
                await invoke('doctor')
                diagnostic = await invoke('diagnostics', 'export')
                assert diagnostic['incidents'], 'pre-recovery incident missing from export'
                assert errors == [], errors
                report['diagnostic'] = diagnostic
                report['sameDaemonPid'] = True
                report['healthyForwardingAfterRecovery'] = True
                # The private incident must exist before the interposed runtime rebind.
                settings_path = next(Path('/proc', str(daemon.pid), 'cmdline').read_bytes().split(b'\0')[i+1]
                                     for i, a in enumerate(Path('/proc', str(daemon.pid), 'cmdline').read_bytes().split(b'\0'))
                                     if a == b'--state-dir')
                directory = Path(os.fsdecode(settings_path))/'diagnostics'
                files = list(directory.glob('incident-*.json'))
                assert files, 'no persisted incident'
                rebound = float(marker.with_suffix('.rebound').read_text())
                assert min(p.stat().st_mtime for p in files) <= rebound, 'incident persisted after recovery'
                assert directory.stat().st_mode & 0o777 == 0o700
                assert all(p.stat().st_mode & 0o777 == 0o600 for p in files)
                report['persistedBeforeRuntimeRebind'] = True
                report['privatePermissions'] = True
                await invoke('stop')
                await asyncio.sleep(20)
                stopped = await invoke('status')
                assert not stopped['running'] and not stopped['settings']['enabled']
                assert (await status())['recoveryCount'] == 1
                report['manualStopPreserved'] = True
        finally:
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    (output/'report.json').chmod(0o600)
    print(json.dumps({k: v for k, v in report.items() if k != 'diagnostic'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    asyncio.run(run(parser.parse_args()))
