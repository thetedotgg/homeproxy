#!/usr/bin/env python3
"""Browser QA transport for the built desktop UI and a disposable real daemon.

No product mocks, system service, production profile or network changes. The
transport replaces only Tauri invoke with Unix IPC; it does not verify WebKit.
Run after npm run build and cargo build -p homeproxy-service -p homeproxy-cli.
Ctrl+C closes only the child daemon and the temporary profile.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


def rpc(endpoint, command):
    payload = json.dumps({'version': 1, 'command': command}).encode()
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(30)
        stream.connect(str(endpoint))
        stream.sendall(struct.pack('!I', len(payload)) + payload)
        def exact(length):
            data = bytearray()
            while len(data) < length:
                chunk = stream.recv(length - len(data))
                if not chunk:
                    raise OSError('Truncated IPC response')
                data.extend(chunk)
            return data
        length = struct.unpack('!I', exact(4))[0]
        if length > 32 * 1024 * 1024:
            raise OSError('Oversized IPC response')
        result = json.loads(exact(length))['result']
        if 'Err' in result:
            error = result['Err']
            raise ValueError(f"HOMEPROXY_SERVICE:{error['code']}:{error['message']}")
        return result['Ok']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries-dir', type=Path, default=Path('target/debug'))
    parser.add_argument('--dist', type=Path, default=Path('dist'))
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    dist = args.dist.resolve()
    assert (dist / 'index.html').is_file()
    daemon_binary = (args.binaries_dir / 'homeproxyd').resolve()
    token = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix='homeproxy-cache-browser-') as temporary:
        root = Path(temporary)
        endpoint = root / 'run/control.sock'
        log = (root / 'daemon.log').open('wb')
        command = [str(daemon_binary), '--foreground', '--state-dir', str(root / 'state'),
                   '--cache-dir', str(root / 'cache'), '--socket', str(endpoint)]
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while not endpoint.exists():
                assert process.poll() is None, 'Child daemon exited'
                assert time.monotonic() < deadline, 'Daemon startup timeout'
                time.sleep(.05)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                proxy_port = listener.getsockname()[1]
            rpc(endpoint, {'method': 'config_patch', 'patch': {'proxyPort': proxy_port}})
            bridge = '''<script>
// Emulate the Linux desktop host; the collaborative browser may run on Windows.
Object.defineProperty(navigator,'userAgent',{get:()=> 'Mozilla/5.0 (X11; Linux x86_64) HomeProxyBrowserQA'});
window.__TAURI_INTERNALS__={invoke:async(cmd,args={})=>{
 const response=await fetch('/invoke',{method:'POST',headers:{'Content-Type':'application/json','X-QA-Token':TOKEN},body:JSON.stringify({cmd,args})});
 const value=await response.json();if(!value.ok)throw Error(value.error);return value.result;
}};
</script>'''.replace('TOKEN', json.dumps(token))
            class Handler(SimpleHTTPRequestHandler):
                def __init__(self, *parts, **kwargs):
                    super().__init__(*parts, directory=str(dist), **kwargs)
                def log_message(self, *_):
                    pass
                def answer(self, value, status=200):
                    payload = json.dumps(value).encode()
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                def do_GET(self):
                    if self.path not in ('/', '/index.html'):
                        return super().do_GET()
                    html = (dist / 'index.html').read_text().replace('<head>', '<head>' + bridge).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)
                def do_POST(self):
                    if self.path != '/invoke' or self.headers.get('X-QA-Token') != token:
                        return self.answer({'ok': False, 'error': 'QA token required'}, 403)
                    try:
                        length = int(self.headers.get('Content-Length', '0'))
                        if not 0 < length <= 256 * 1024:
                            raise ValueError('Invalid request size')
                        request = json.loads(self.rfile.read(length))
                        cmd, fields = request['cmd'], request.get('args', {})
                        if cmd == 'get_snapshot':
                            result = rpc(endpoint, {'method': 'desktop_snapshot'})
                        elif cmd in ('get_tls_status', 'prepare_tls_authority'):
                            result = rpc(endpoint, {'method': 'tls_status' if cmd == 'get_tls_status' else 'prepare_ca'})
                            result['clientTrustAcknowledged'] = result.get('clientTrustDeclared', False)
                        elif cmd == 'export_tls_certificate':
                            public = rpc(endpoint, {'method': 'export_ca', 'format': 'pem'})
                            result = {'certificatePem': public.get('certificatePem', public.get('certificate', '')),
                                      'sha256Fingerprint': public.get('sha256Fingerprint', '')}
                        elif cmd == 'get_usage_history':
                            result = rpc(endpoint, {'method': 'usage_history'})
                        elif cmd == 'prepare_offline':
                            result = rpc(endpoint, {'method': 'prepare_offline', 'request': fields['requestData']})
                        elif cmd == 'cancel_offline_preparation':
                            result = rpc(endpoint, {'method': 'cancel_offline_preparation', 'id': fields['id']})
                        elif cmd == 'release_offline_pin':
                            result = rpc(endpoint, {'method': 'release_offline_pin', 'key': fields['key']})
                        elif cmd == 'export_usage_history':
                            result = rpc(endpoint, {'method': 'export_usage_history', 'format': fields['format']})
                        else:
                            if cmd == 'apply_settings':
                                mutation = {'method': 'apply_settings', 'settings': fields['settings'],
                                            'expected_revision': fields['expectedRevision']}
                            elif cmd == 'set_running':
                                mutation = {'method': 'start' if fields['running'] else 'stop'}
                            elif cmd in ('clear_cache', 'clear_activity'):
                                mutation = {'method': cmd}
                            elif cmd == 'remove_filter_feed':
                                mutation = {'method': cmd, 'id': fields['id'],
                                            'expected_revision': fields['expectedRevision']}
                            elif cmd == 'import_filter_feed':
                                # Test-only transport adapter; production Tauri uses the shared Rust parser.
                                exact, wildcard = set(), set()
                                for line in fields['content'].lstrip('\ufeff').splitlines():
                                    line = line.strip()
                                    if not line or line.startswith(('#', '!')) or line == '[Adblock Plus 2.0]':
                                        continue
                                    line = line.split('#', 1)[0].strip()
                                    if line.startswith('||') and line.endswith('^'):
                                        wildcard.add(line[2:-1].rstrip('.').lower())
                                    else:
                                        parts = line.split()
                                        if parts[0] in ('0.0.0.0', '127.0.0.1'):
                                            exact.update(item.rstrip('.').lower() for item in parts[1:] if item not in ('localhost', 'localhost.localdomain', 'broadcasthost'))
                                        elif len(parts) == 1:
                                            exact.add(parts[0].rstrip('.').lower())
                                        else:
                                            raise ValueError('Unsupported filter line')
                                name = fields['name'].strip()
                                feed = {'id': 'feed-' + hashlib.sha256(name.lower().encode()).hexdigest()[:32],
                                        'name': name, 'domainsSortedExact': sorted(exact),
                                        'domainsSortedWildcard': sorted(wildcard)}
                                mutation = {'method': cmd, 'feed': feed,
                                            'expected_revision': fields['expectedRevision']}
                            else:
                                raise ValueError('Unsupported QA command: ' + cmd)
                            rpc(endpoint, mutation)
                            result = rpc(endpoint, {'method': 'desktop_snapshot'})
                        self.answer({'ok': True, 'result': result})
                    except (OSError, ValueError, KeyError) as error:
                        self.answer({'ok': False, 'error': str(error)})
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({'url': f'http://127.0.0.1:{server.server_port}',
                'socket': str(endpoint), 'profile': str(root), 'daemonPid': process.pid,
                'transport': 'test-only browser invoke to real Unix IPC; no native WebKit'}) + '\n')
            print(f'Browser QA ready: http://127.0.0.1:{server.server_port}', flush=True)
            server.serve_forever()
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=15)
            log.close()


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        main()
    except KeyboardInterrupt:
        pass
