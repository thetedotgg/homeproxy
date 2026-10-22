#!/usr/bin/env python3
"""Isolated real-daemon resilience QA; all traffic stays on this host.

Only the temporary child's NOFILE limit is changed. The local parent interprets
CONNECT as an echo fixture and never opens an origin socket. No installed service,
system proxy, credentials, firewall, or certificate store is modified.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import resource
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


def local_address():
    interfaces = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show'], text=True))
    return next(address['local'] for interface in interfaces
                for address in interface.get('addr_info', [])
                if address['family'] == 'inet' and address.get('scope') == 'global')


def summary(snapshot):
    stats = snapshot['stats']
    return {key: stats[key] for key in (
        'activeConnections', 'connectionLimit', 'connectionLimitPerPeer',
        'idleConnectionsClosed', 'listenerRuntimeError', 'listenerRuntimeErrors',
        'keepaliveConfigurationFailures', 'rejectedConnections')}


@asynccontextmanager
async def fixture(bin_dir, output, name, limited=False):
    host = local_address()
    parent_writers = set()
    clients = []

    async def parent(reader, writer):
        parent_writers.add(writer)
        try:
            assert writer.get_extra_info('peername')[0] == host
            request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            assert request.startswith(b'CONNECT 1.1.1.1:443 HTTP/1.1\r\n')
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await asyncio.wait_for(writer.drain(), 3)
            while data := await reader.read(8192):
                writer.write(data)
                await asyncio.wait_for(writer.drain(), 3)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            parent_writers.discard(writer)
            await close(writer)

    parent_server = await asyncio.start_server(parent, host, 0)
    parent_port = parent_server.sockets[0].getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        proxy_port = reservation.getsockname()[1]
    # Keep the Unix socket path short even when the report directory is deeply nested.
    with tempfile.TemporaryDirectory(prefix=f'hp-{name}-') as temporary:
        root = Path(temporary)
        endpoint = root / 'control.sock'
        with (output / f'{name}-daemon.log').open('wb') as log:
            def limit_child():
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            daemon = await asyncio.create_subprocess_exec(
                str(bin_dir / 'homeproxyd'), '--state-dir', str(root / 'state'),
                '--cache-dir', str(root / 'cache'), '--socket', str(endpoint), '--foreground',
                preexec_fn=limit_child if limited else None, stdout=log, stderr=log)

            async def invoke(*parts, patch=None, expected_exit=0):
                command = await asyncio.create_subprocess_exec(
                    str(bin_dir / 'homeproxy'), '--socket', str(endpoint), '--json', *parts,
                    stdin=asyncio.subprocess.PIPE if patch is not None else None,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    out, _ = await asyncio.wait_for(command.communicate(
                        json.dumps(patch).encode() if patch is not None else None), 10)
                finally:
                    if command.returncode is None:
                        command.kill()
                        await command.wait()
                value = json.loads(out)
                assert command.returncode == expected_exit, (parts, command.returncode, value)
                assert value['ok'] == (expected_exit == 0), value
                return value['result'] if value['ok'] else value['error']

            async def connect(peer='127.0.0.2', admitted=True):
                reader, writer = await asyncio.wait_for(asyncio.open_connection(
                    '127.0.0.1', proxy_port, local_addr=(peer, 0)), 3)
                clients.append(writer)
                writer.write(b'CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n')
                try:
                    await asyncio.wait_for(writer.drain(), 3)
                    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
                except (ConnectionError, asyncio.IncompleteReadError):
                    assert not admitted, 'expected an admitted CONNECT tunnel'
                    await close(writer)
                    return None
                assert admitted, 'expected capacity rejection'
                assert header.startswith(b'HTTP/1.1 200'), header
                await exchange((reader, writer))
                return reader, writer

            def fds():
                return len(list(Path(f'/proc/{daemon.pid}/fd').iterdir()))

            try:
                deadline = time.monotonic() + 5
                while not endpoint.exists():
                    assert daemon.returncode is None, 'temporary daemon exited at startup'
                    assert time.monotonic() < deadline, 'control socket startup timeout'
                    await asyncio.sleep(.025)
                await invoke('config', 'apply', '--stdin', patch={
                    'proxyPort': proxy_port, 'dnsMode': 'system', 'cacheEnabled': False,
                    'tunnelIdleTimeoutSeconds': 60,
                    'upstreamProxies': [{'host': host, 'port': parent_port,
                                         'username': None, 'password': None}]})
                await invoke('start')
                yield daemon, invoke, connect, fds, clients, proxy_port
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
                parent_server.close()
                await parent_server.wait_closed()
                await asyncio.gather(*(close(writer) for writer in list(parent_writers)))


async def exchange(stream, payload=b'resilience\0fixture'):
    reader, writer = stream
    writer.write(payload)
    await asyncio.wait_for(writer.drain(), 3)
    assert await asyncio.wait_for(reader.readexactly(len(payload)), 3) == payload


async def capacity(bin_dir, output):
    async with fixture(bin_dir, output, 'capacity') as (daemon, invoke, connect, fds, _, _):
        initial_fds = fds()
        for _ in range(128):
            await connect()
        await connect(admitted=False)
        saturated = await invoke('status')
        assert saturated['running'] and saturated['stats']['activeConnections'] == 128
        assert saturated['stats']['latestConnectionRejection']['reason'] == 'peer-limit'
        await invoke('doctor', expected_exit=6)
        active = await connect('127.0.0.3')
        live_id = next(row['id'] for row in (await invoke('status'))['stats']['liveConnections']
                       if row['peerIp'] == '127.0.0.3')
        await invoke('activity', 'clear')
        assert (await invoke('status'))['stats']['activeConnections'] == 129
        start = time.monotonic()
        for _ in range(13):
            await asyncio.sleep(5)
            await exchange(active)
        recovered = await invoke('status')
        assert recovered['running'] and recovered['lastError'] is None
        assert recovered['stats']['activeConnections'] == 1
        assert recovered['stats']['idleConnectionsClosed'] == 128
        assert recovered['stats']['liveConnections'][0]['id'] == live_id
        assert recovered['stats']['liveConnections'][0]['ageMs'] >= 60_000
        assert fds() <= initial_fds + 2, 'idle socket descriptors were retained'
        await invoke('doctor')
        await connect()
        assert daemon.returncode is None
        return {'pid': daemon.pid, 'elapsedSeconds': round(time.monotonic() - start, 2),
                'saturated': summary(saturated), 'recovered': summary(recovered),
                'fdsBefore': initial_fds, 'fdsAfterReclamation': fds() - 2,
                'checks': ['128 CONNECT relays admitted; 129th rejected; doctor degraded',
                           'live count survives activity clear',
                           '128 idle relays reclaimed automatically; same-peer CONNECT works again',
                           'active other peer keeps same ID and actual echoed payload beyond idle limit',
                           'doctor recovers and descriptors released without daemon or proxy restart']}


async def accept(bin_dir, output):
    async with fixture(bin_dir, output, 'accept', limited=True) as (
            daemon, invoke, connect, fds, clients, proxy_port):
        active = await connect()
        before = await invoke('status')
        live_id = before['stats']['liveConnections'][0]['id']
        pressure = []
        start = time.monotonic()
        while fds() < 64:
            assert time.monotonic() - start < 5, 'descriptor pressure not established'
            _, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', proxy_port), 1)
            clients.append(writer)
            pressure.append(writer)
            await asyncio.sleep(.005)
        # A queued arrival forces accept to report EMFILE rather than just wait.
        _, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', proxy_port), 1)
        clients.append(writer)
        pressure.append(writer)
        await asyncio.sleep(.3)
        assert fds() == 64 and daemon.returncode is None
        await exchange(active, b'working-at-NOFILE64')
        await asyncio.gather(*(close(writer) for writer in pressure))
        await asyncio.sleep(.5)
        await connect('127.0.0.3')
        recovered = await invoke('status')
        assert recovered['running'] and recovered['lastError'] is None
        assert recovered['stats']['listenerRuntimeErrors'] > 0, 'no actual accept fault observed'
        assert recovered['stats']['listenerRuntimeError'] is None
        assert any(row['id'] == live_id for row in recovered['stats']['liveConnections'])
        await exchange(active, b'original-tunnel-still-working')
        await invoke('doctor')
        return {'pid': daemon.pid, 'elapsedSeconds': round(time.monotonic() - start, 2),
                'rawPressureSockets': len(pressure), 'recovered': summary(recovered),
                'checks': ['only temporary daemon reaches NOFILE64; actual accept error counted',
                           'existing CONNECT echoes payload during exhaustion',
                           'original live ID and payload survive recovery; new CONNECT works',
                           'doctor healthy after successful accept without daemon or proxy restart']}


async def main(args):
    bin_dir = args.bin_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name in ['homeproxyd', 'homeproxy']:
        assert (bin_dir / name).is_file(), f'missing binary {name}'
    report = {'scope': 'actual Linux daemon; host-local fixtures; no origin egress or installed-service changes',
              'binarySha256': {name: hashlib.sha256((bin_dir / name).read_bytes()).hexdigest()
                               for name in ['homeproxyd', 'homeproxy']}}
    for name, run in [('capacity', capacity), ('accept', accept)]:
        if args.scenario in ['all', name]:
            report[name] = await run(bin_dir, output)
            (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            print(f'{name}: PASS', flush=True)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--scenario', choices=['all', 'capacity', 'accept'], default='all')
    asyncio.run(main(parser.parse_args()))
