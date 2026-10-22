#!/usr/bin/env python3
"""Reproduce HTTP body capacity retention in an isolated real Linux daemon.

The parent fixture is host-local and never dials an origin. Public addresses in
requests are protocol text only. No installed service or system setting changes.
By default, success means the defect was reproduced, NOT that proxy QA passed.
Use --expect-reclaimed when validating a future HTTP inactivity fix.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 3)
    except (ConnectionError, asyncio.TimeoutError):
        writer.transport.abort()


def host_address():
    interfaces = json.loads(subprocess.check_output(
        ['ip', '-j', '-4', 'addr', 'show'], text=True, timeout=5))
    return next(row['local'] for interface in interfaces
                for row in interface.get('addr_info', [])
                if row['family'] == 'inet' and row.get('scope') == 'global')


@asynccontextmanager
async def fixture(bin_dir, output):
    host = host_address()
    parent_writers = set()
    clients = []
    parent_errors = []

    async def parent(reader, writer):
        parent_writers.add(writer)
        try:
            assert writer.get_extra_info('peername')[0] == host
            headers = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            assert headers.startswith((b'CONNECT 1.1.1.1:80 ', b'CONNECT 1.1.1.1:443 '))
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await asyncio.wait_for(writer.drain(), 3)
            if headers.startswith(b'CONNECT 1.1.1.1:80 '):
                request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                assert request.startswith(b'GET ')
                if request.startswith(b'GET /healthy '):
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                                 b'Cache-Control: no-store\r\nConnection: close\r\n\r\nOK')
                    await asyncio.wait_for(writer.drain(), 3)
                    return
                assert request.startswith(b'GET /stall ')
                # Keep TCP healthy but leave the advertised HTTP body incomplete.
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n'
                             b'Cache-Control: no-store\r\n\r\nx')
                await asyncio.wait_for(writer.drain(), 3)
            while await reader.read(8192):
                pass
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as error:
            parent_errors.append(repr(error))
        finally:
            parent_writers.discard(writer)
            await close(writer)

    server = await asyncio.start_server(parent, host, 0)
    parent_port = server.sockets[0].getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        proxy_port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='hp-http-stall-') as temporary:
        root = Path(temporary)
        endpoint = root / 'control.sock'
        with (output / 'daemon.log').open('wb') as log:
            daemon = await asyncio.create_subprocess_exec(
                str(bin_dir / 'homeproxyd'), '--state-dir', str(root / 'state'),
                '--cache-dir', str(root / 'cache'), '--socket', str(endpoint),
                '--foreground', stdout=log, stderr=log)

            async def invoke(*parts, patch=None, expected_exit=0):
                command = await asyncio.create_subprocess_exec(
                    str(bin_dir / 'homeproxy'), '--socket', str(endpoint), '--json', *parts,
                    stdin=asyncio.subprocess.PIPE if patch is not None else None,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    out, err = await asyncio.wait_for(command.communicate(
                        json.dumps(patch).encode() if patch is not None else None), 10)
                finally:
                    if command.returncode is None:
                        command.kill()
                        await command.wait()
                value = json.loads(out)
                assert command.returncode == expected_exit, (parts, value, err.decode())
                assert value['ok'] == (expected_exit == 0), value
                return value['result'] if value['ok'] else value['error']

            async def request(peer, path='stall', admitted=True):
                reader, writer = await asyncio.wait_for(asyncio.open_connection(
                    '127.0.0.1', proxy_port, local_addr=(peer, 0)), 3)
                clients.append(writer)
                if path == 'connect':
                    payload = b'CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n'
                else:
                    payload = (f'GET http://1.1.1.1/{path} HTTP/1.1\r\n'
                               'Host: 1.1.1.1\r\nConnection: close\r\n\r\n').encode()
                writer.write(payload)
                try:
                    await asyncio.wait_for(writer.drain(), 3)
                    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
                except (ConnectionError, asyncio.IncompleteReadError):
                    assert not admitted, 'expected admitted request'
                    await close(writer)
                    return None
                assert admitted, 'expected socket rejection at capacity'
                assert header.startswith(b'HTTP/1.1 200'), header
                if path == 'stall':
                    assert await asyncio.wait_for(reader.readexactly(1), 3) == b'x'
                elif path == 'healthy':
                    assert await asyncio.wait_for(reader.readexactly(2), 3) == b'OK'
                    await close(writer)
                return reader, writer

            try:
                deadline = time.monotonic() + 5
                while not endpoint.exists():
                    assert daemon.returncode is None, 'daemon exited at startup'
                    assert time.monotonic() < deadline, 'control startup timeout'
                    await asyncio.sleep(.025)
                await invoke('config', 'apply', '--stdin', patch={
                    'proxyPort': proxy_port, 'dnsMode': 'system', 'cacheEnabled': False,
                    'tunnelIdleTimeoutSeconds': 60,
                    'upstreamProxies': [{'host': host, 'port': parent_port,
                                         'username': None, 'password': None}]})
                await invoke('start')
                yield daemon, invoke, request, parent_errors
            finally:
                for writer in clients:
                    writer.close()
                if daemon.returncode is None:
                    daemon.terminate()
                    try:
                        await asyncio.wait_for(daemon.wait(), 10)
                    except asyncio.TimeoutError:
                        daemon.kill()
                        await daemon.wait()
                server.close()
                await server.wait_closed()
                await asyncio.gather(*(close(writer) for writer in list(parent_writers)))


def snapshot_summary(value):
    stats = value['stats']
    live = stats['liveConnections']
    return {
        'running': value['running'], 'serviceVersion': value['serviceVersion'],
        'lastError': value['lastError'],
        **{key: stats[key] for key in (
            'activeConnections', 'connectionLimit', 'connectionLimitPerPeer',
            'rejectedConnections', 'idleConnectionsClosed', 'listenerRuntimeError')},
        'protocolCounts': {name: sum(row['protocol'] == name for row in live)
                           for name in {row['protocol'] for row in live}},
        'minIdleMs': min((row['idleMs'] for row in live), default=0),
        'maxIdleMs': max((row['idleMs'] for row in live), default=0),
        'historyHealthy': value['usageHistory']['healthy'],
    }


async def run(args):
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    report = {'purpose': 'defect reproduction, not a full acceptance test',
              'expectReclaimed': args.expect_reclaimed,
              'binaries': {name: hashlib.sha256((args.bin_dir / name).read_bytes()).hexdigest()
                           for name in ('homeproxyd', 'homeproxy')}}
    async with fixture(args.bin_dir, output) as (daemon, invoke, request, errors):
        report['daemonPid'] = daemon.pid
        await request('127.0.0.4', 'healthy')
        for peer in ('127.0.0.2', '127.0.0.3'):
            for _ in range(128):
                await request(peer)
        saturated = await invoke('status')
        assert saturated['stats']['activeConnections'] == 256
        await request('127.0.0.4', admitted=False)
        report['saturated'] = snapshot_summary(await invoke('status'))
        report['doctorAtCapacity'] = await invoke('doctor', expected_exit=6)
        # All sockets remain open and TCP-responsive. A legitimate 60s byte-idle
        # limit would release them; the HTTP response-header limit already elapsed.
        await asyncio.sleep(65)
        after = await invoke('status')
        report['after65Seconds'] = snapshot_summary(after)
        if args.expect_reclaimed:
            assert after['stats']['activeConnections'] == 0, report['after65Seconds']
            await request('127.0.0.4', 'healthy')
            await invoke('doctor')
        else:
            assert after['stats']['activeConnections'] == 256, report['after65Seconds']
            assert report['after65Seconds']['minIdleMs'] > 60_000
            assert after['stats']['idleConnectionsClosed'] == 0
            await request('127.0.0.4', admitted=False)
            await invoke('doctor', expected_exit=6)
        # Proxy toggle, not process restart: same PID and same Engine/history.
        await invoke('stop')
        await invoke('start')
        await request('127.0.0.4', 'healthy')
        await invoke('doctor')
        report['afterProxyToggle'] = snapshot_summary(await invoke('status'))
        assert report['afterProxyToggle']['activeConnections'] == 0
        assert daemon.returncode is None
        # Positive control for the previous raw CONNECT fix.
        idle_before_connect = report['afterProxyToggle']['idleConnectionsClosed']
        reader, _ = await request('127.0.0.4', 'connect')
        assert await asyncio.wait_for(reader.read(1), 65) == b''
        control = await invoke('status')
        report['rawConnectControl'] = snapshot_summary(control)
        assert control['stats']['activeConnections'] == 0
        assert control['stats']['idleConnectionsClosed'] == idle_before_connect + 1
        assert not errors, errors
        report['sameDaemonProcessAfterToggle'] = True
        report['defectReproduced'] = not args.expect_reclaimed
        report['elapsedSeconds'] = round(time.monotonic() - started, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--expect-reclaimed', action='store_true')
    asyncio.run(run(parser.parse_args()))
