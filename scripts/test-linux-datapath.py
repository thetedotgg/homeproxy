#!/usr/bin/env python3
"""Exercise release HomeProxy traffic in disposable Linux network namespaces.

Requires passwordless sudo, unshare, nsenter, iproute2 and existing release
binaries. The public-looking origin has no route outside the outer namespace.
No host interfaces, routes, firewall rules, trust stores or accounts are changed.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


ORIGIN = "1.1.1.123"
SERVER = "192.168.77.1"
CLIENT = "192.168.77.2"
CLIENT_TWO = "192.168.77.3"
TRANSFER = bytes(range(256)) * 4096


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError(f"socket closed after {len(data)} of {size} bytes")
        data.extend(chunk)
    return bytes(data)


def headers(sock):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        assert len(data) < 16_384, "response headers too large"
        data.extend(exact(sock, 1))
    return bytes(data)


def client_main():
    spec = json.load(sys.stdin)
    op = spec["op"]
    proxy = (SERVER, spec["port"])
    password = spec.get("password", "")
    username = spec.get("username", "domov")
    client_ip = spec.get("client_ip", CLIENT)

    def digest(challenge, method, uri):
        match = re.search(r'nonce="([^"]+)"', challenge, re.IGNORECASE)
        if match is None:
            return ""
        nonce = match.group(1)
        md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
        ha1 = md5(f"{username}:HomeProxy:{password}")
        ha2 = md5(f"{method}:{uri}")
        response = md5(f"{ha1}:{nonce}:00000001:qa-client:auth:{ha2}")
        return (
            f'Proxy-Authorization: Digest username="{username}", realm="HomeProxy", '
            f'nonce="{nonce}", uri="{uri}", response="{response}", algorithm=MD5, '
            'qop=auth, nc=00000001, cnonce="qa-client"\r\n'
        )

    def tcp():
        sock = socket.socket()
        try:
            sock.settimeout(5)
            sock.bind((client_ip, 0))
            sock.connect(proxy)
            return sock
        except OSError:
            sock.close()
            raise

    if op == "probe":
        try:
            with tcp():
                result = {"connected": True}
        except ConnectionRefusedError:
            result = {"connected": False}
    elif op == "http":
        target = spec.get("target", f"http://{ORIGIN}/public")
        def exchange(auth):
            with tcp() as sock:
                upstream_auth = spec.get("upstream_auth", "")
                if upstream_auth:
                    upstream_auth = f"Authorization: Bearer {upstream_auth}\r\n"
                request = (
                    f"GET {target} HTTP/1.1\r\nHost: {target.split('/')[2]}\r\n"
                    f"{auth}{upstream_auth}Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())
                response = bytearray()
                while True:
                    chunk = sock.recv(65_536)
                    if not chunk:
                        break
                    response.extend(chunk)
                head, _, body = response.partition(b"\r\n\r\n")
                status = int(head.split(b" ", 2)[1])
                return {"status": status, "headers": head.decode("latin1"), "body": body.decode("latin1")}
        result = exchange("")
        if password and result["status"] == 407 and "proxy-authenticate: Digest" in result["headers"]:
            result = exchange(digest(result["headers"], "GET", target))
    elif op in ("connect", "https"):
        target = spec.get("target", f"{ORIGIN}:{8080 if op == 'https' else 443}")
        with tcp() as sock:
            sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            challenge = headers(sock).decode("latin1")
            challenge_status = int(challenge.split(" ", 2)[1])
            challenge_has_digest = "proxy-authenticate: digest" in challenge.lower()
        auth = digest(challenge, "CONNECT", target) if password else ""
        with tcp() as sock:
            sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n".encode())
            head = headers(sock)
            status = int(head.split(b" ", 2)[1])
            result = {
                "status": status,
                "challenge_status": challenge_status,
                "challenge_has_digest": challenge_has_digest,
            }
            if status == 200:
                if op == "https":
                    context = ssl.create_default_context(cafile=spec["certificate"])
                    with context.wrap_socket(sock, server_hostname=ORIGIN) as secure:
                        result["tls_version"] = secure.version()
                        secure.sendall(f"GET /tls HTTP/1.1\r\nHost: {ORIGIN}\r\nConnection: close\r\n\r\n".encode())
                        response = bytearray()
                        while chunk := secure.recv(4096):
                            response.extend(chunk)
                        tls_head, _, body = response.partition(b"\r\n\r\n")
                        result["https_status"] = int(tls_head.split(b" ", 2)[1])
                        result["body"] = body.decode("ascii")
                else:
                    started = time.monotonic()
                    sock.sendall(struct.pack("!I", len(TRANSFER)) + TRANSFER)
                    result["sha256"] = hashlib.sha256(exact(sock, len(TRANSFER))).hexdigest()
                    if spec.get("timed"):
                        result["transfer_seconds"] = round(time.monotonic() - started, 3)
    elif op in ("socks", "udp"):
        with tcp() as sock:
            sock.sendall(b"\x05\x02\x00\x02")
            method = exact(sock, 2)
            assert method[0] == 5
            result = {"method": method[1]}
            if method[1] == 2:
                name = username.encode()
                secret = password.encode()
                assert name and secret and len(name) < 256 and len(secret) < 256
                sock.sendall(bytes([1, len(name)]) + name + bytes([len(secret)]) + secret)
                result["auth"] = exact(sock, 2).hex()
                if result["auth"] != "0100":
                    print(json.dumps(result))
                    return
            elif method[1] != 0:
                print(json.dumps(result))
                return
            target = socket.inet_aton(spec.get("target", "0.0.0.0" if op == "udp" else ORIGIN))
            command = 3 if op == "udp" else 1
            destination_port = 0 if op == "udp" else spec.get("target_port", 443)
            sock.sendall(bytes([5, command, 0, 1]) + target + struct.pack("!H", destination_port))
            reply = exact(sock, 4)
            result["reply"] = reply[1]
            if reply[3] == 1:
                bound_ip = socket.inet_ntoa(exact(sock, 4))
            elif reply[3] == 4:
                bound_ip = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
            else:
                raise AssertionError(f"unexpected SOCKS address type {reply[3]}")
            bound_port = struct.unpack("!H", exact(sock, 2))[0]
            if reply[1] == 0 and op == "socks":
                sock.sendall(struct.pack("!I", len(TRANSFER)) + TRANSFER)
                result["sha256"] = hashlib.sha256(exact(sock, len(TRANSFER))).hexdigest()
            if reply[1] == 0 and op == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind((client_ip, 0))
                    udp.settimeout(1 if spec.get("drop") else 5)
                    payload = b"udp-probe"
                    dst = socket.inet_aton(spec.get("udp_target", ORIGIN))
                    frame = b"\x00\x00\x00\x01" + dst + struct.pack("!H", 5353) + payload
                    udp.sendto(frame, (bound_ip, bound_port))
                    try:
                        received, _ = udp.recvfrom(2048)
                        result["udp_payload"] = received[10:].decode()
                    except socket.timeout:
                        result["udp_payload"] = None
    else:
        raise AssertionError(f"unknown client operation {op}")
    print(json.dumps(result))


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TLSServer(TCPServer):
    def get_request(self):
        stream, address = super().get_request()
        try:
            return self.ssl_context.wrap_socket(stream, server_side=True), address
        except Exception:
            stream.close()
            raise


class HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        request = headers(self.request).decode("latin1")
        line = request.split("\r\n", 1)[0]
        path = line.split(" ", 2)[1]
        if "proxy-authorization:" in request.lower():
            self.server.leaked_proxy_authorization = True
        with self.server.counter_lock:
            self.server.hits[path] += 1
            count = self.server.hits[path]
        if path == "/public":
            body, policy = f"public-{count}".encode(), "public, max-age=120"
        elif path == "/private":
            body, policy = f"private-{count}".encode(), "private, max-age=120"
        elif path == "/auth":
            token = request.lower().split("authorization: bearer ", 1)[-1].split("\r\n", 1)[0]
            body, policy = f"origin-{token}-{count}".encode(), "public, max-age=120"
        else:
            body, policy = b"missing", "no-store"
        self.request.sendall(
            f"HTTP/1.1 200 OK\r\nCache-Control: {policy}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        )


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        length = struct.unpack("!I", exact(self.request, 4))[0]
        assert length <= len(TRANSFER)
        remaining = length
        while remaining:
            data = self.request.recv(min(65_536, remaining))
            assert data
            self.request.sendall(data)
            remaining -= len(data)


class TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        request = headers(self.request)
        assert request.startswith(b"GET /tls HTTP/1.1\r\n")
        with self.server.counter_lock:
            self.server.hits += 1
            count = self.server.hits
        body = f"tls-{count}".encode()
        self.request.sendall(
            f"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        )


def inside_main(args):
    original_uid = int(os.environ["SUDO_UID"])
    original_gid = int(os.environ["SUDO_GID"])
    username = pwd.getpwuid(original_uid).pw_name
    release = args.binaries_dir.resolve()
    source_cli, source_daemon = release / "homeproxy", release / "homeproxyd"
    assert source_cli.is_file() and source_daemon.is_file(), "build release binaries first"

    def privileged(*parts):
        run(parts, capture_output=True)

    privileged("ip", "link", "set", "lo", "up")
    privileged("ip", "address", "add", f"{ORIGIN}/32", "dev", "lo")
    assert not run(["ip", "route", "show", "default"], capture_output=True).stdout.strip()
    namespace = subprocess.Popen(["unshare", "--net", "--", "sleep", "infinity"])
    passed = []
    daemon_process = None
    http = echo = tls_origin = None
    udp = None
    private_udp_sockets = []
    private_udp_hits = []
    stop_udp = threading.Event()
    with tempfile.TemporaryDirectory(prefix="homeproxy-datapath-") as temporary:
        root = Path(temporary)
        os.chown(root, original_uid, original_gid)
        os.chmod(root, 0o700)
        binaries = root / "binaries"
        binaries.mkdir(mode=0o755)
        cli, daemon = binaries / "homeproxy", binaries / "homeproxyd"
        shutil.copy2(source_cli, cli)
        shutil.copy2(source_daemon, daemon)
        cli_sha256 = hashlib.sha256(cli.read_bytes()).hexdigest()
        daemon_sha256 = hashlib.sha256(daemon.read_bytes()).hexdigest()
        log = (root / "daemon.log").open("wb")
        try:
            parent_ns = os.readlink("/proc/self/ns/net")
            for _ in range(100):
                if os.readlink(f"/proc/{namespace.pid}/ns/net") != parent_ns:
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("child namespace did not start")
            privileged("ip", "link", "add", "hpqah", "type", "veth", "peer", "name", "hpqac")
            privileged("ip", "link", "set", "hpqac", "netns", str(namespace.pid))
            privileged("ip", "address", "add", f"{SERVER}/24", "dev", "hpqah")
            privileged("ip", "link", "set", "hpqah", "up")
            for command in [
                ("ip", "link", "set", "lo", "up"),
                ("ip", "address", "add", f"{CLIENT}/24", "dev", "hpqac"),
                ("ip", "address", "add", f"{CLIENT_TWO}/24", "dev", "hpqac"),
                ("ip", "link", "set", "hpqac", "up"),
            ]:
                privileged("nsenter", "--target", str(namespace.pid), "--net", *command)
            assert not run(
                ["nsenter", "--target", str(namespace.pid), "--net", "ip", "route", "show", "default"],
                capture_output=True,
            ).stdout.strip()

            http = TCPServer((ORIGIN, 80), HTTPHandler)
            http.hits = Counter()
            http.counter_lock = threading.Lock()
            http.leaked_proxy_authorization = False
            threading.Thread(target=http.serve_forever, daemon=True).start()
            echo = TCPServer((ORIGIN, 443), EchoHandler)
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            certificate, private_key = root / "fixture.crt", root / "fixture.key"
            run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(private_key), "-out", str(certificate), "-days", "1",
                 "-subj", f"/CN={ORIGIN}", "-addext", f"subjectAltName=IP:{ORIGIN}"],
                capture_output=True,
            )
            os.chmod(certificate, 0o644)
            os.chmod(private_key, 0o600)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(str(certificate), str(private_key))
            tls_origin = TLSServer((ORIGIN, 8080), TLSHandler)
            tls_origin.ssl_context = tls_context
            tls_origin.counter_lock = threading.Lock()
            tls_origin.hits = 0
            threading.Thread(target=tls_origin.serve_forever, daemon=True).start()
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind((ORIGIN, 5353))
            udp.settimeout(0.2)
            udp_hits = []

            def udp_origin():
                while not stop_udp.is_set():
                    try:
                        data, peer = udp.recvfrom(2048)
                    except socket.timeout:
                        continue
                    except OSError:
                        if stop_udp.is_set():
                            break
                        raise
                    udp_hits.append(data)
                    udp.sendto(b"udp:" + data, peer)
            threading.Thread(target=udp_origin, daemon=True).start()

            def private_udp_origin(listener):
                while not stop_udp.is_set():
                    try:
                        data, peer = listener.recvfrom(2048)
                    except socket.timeout:
                        continue
                    except OSError:
                        if stop_udp.is_set():
                            break
                        raise
                    private_udp_hits.append((listener.getsockname()[0], data))
                    listener.sendto(b"private:" + data, peer)

            for private_ip in ("127.0.0.1", SERVER):
                listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                listener.bind((private_ip, 5353))
                listener.settimeout(0.2)
                private_udp_sockets.append(listener)
                threading.Thread(target=private_udp_origin, args=(listener,), daemon=True).start()

            state, cache, endpoint = root / "state", root / "cache", root / "run/control.sock"

            def as_owner():
                os.setgroups([])
                os.setgid(original_gid)
                os.setuid(original_uid)

            daemon_process = subprocess.Popen(
                [str(daemon), "--foreground", "--state-dir", str(state), "--cache-dir", str(cache), "--socket", str(endpoint)],
                stdout=log, stderr=log, preexec_fn=as_owner,
            )

            def invoke(*command, success=True):
                result = subprocess.run(
                    [str(cli), "--socket", str(endpoint), "--json", *command],
                    capture_output=True, text=True, timeout=35, preexec_fn=as_owner,
                )
                assert (result.returncode == 0) == success, (command, result.returncode, result.stderr)
                value = json.loads(result.stdout)
                assert value["ok"] == success
                return value["result"] if success else value["error"]

            def config_apply(patch):
                result = subprocess.run(
                    [str(cli), "--socket", str(endpoint), "--json", "config", "apply", "--stdin"],
                    input=json.dumps(patch), capture_output=True, text=True, timeout=35, preexec_fn=as_owner,
                )
                assert result.returncode == 0, result.stderr or result.stdout
                assert json.loads(result.stdout)["ok"]

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if endpoint.exists():
                    break
                assert daemon_process.poll() is None, "daemon exited during startup"
                time.sleep(0.05)
            else:
                raise AssertionError("daemon socket did not appear")

            settings = invoke("status")["settings"]
            assert not settings["enabled"]
            creds = invoke("credentials", "show")
            port = 17891
            socks_port = 11080
            config_apply({
                "lanEnabled": True, "listenIp": SERVER, "proxyPort": port,
                "socks5Enabled": True, "socks5UdpEnabled": True, "socks5Port": socks_port,
                "cacheEnabled": True,
            })
            assert invoke("start")["running"]
            assert invoke("doctor")["health"] == "ok"

            def client(op, *, port=port, password=creds["password"], **extra):
                spec = {"op": op, "port": port, "password": password, "username": creds["username"], **extra}
                response = run(
                    ["nsenter", "--target", str(namespace.pid), "--net", "runuser", "-u", username,
                     "--", sys.executable, str(Path(__file__).resolve()), "--client"],
                    input=json.dumps(spec), capture_output=True, timeout=15,
                )
                return json.loads(response.stdout)

            def check(label):
                passed.append(label)
                print(f"PASS {label}", flush=True)

            no_auth = client("http", password="")
            bad_auth = client("http", password="wrong-password")
            assert no_auth["status"] == bad_auth["status"] == 407
            bad_socks = client("socks", port=socks_port, password="wrong-password")
            assert bad_socks["method"] == 2 and bad_socks["auth"] == "0101"
            assert http.hits["/public"] == 0
            good = client("http")
            assert good["status"] == 200 and good["body"] == "public-1", good
            assert not http.leaked_proxy_authorization
            check("external LAN HTTP authentication and no credential leak to origin")

            cached = client("http")
            assert cached["body"] == "public-1"
            assert "HomeProxy; hit" in cached["headers"]
            assert http.hits["/public"] == 1
            private1 = client("http", target=f"http://{ORIGIN}/private")
            private2 = client("http", target=f"http://{ORIGIN}/private")
            assert private1["body"] == "private-1" and private2["body"] == "private-2"
            assert http.hits["/private"] == 2
            auth1 = client("http", target=f"http://{ORIGIN}/auth", upstream_auth="qa-a")
            auth2 = client("http", target=f"http://{ORIGIN}/auth", upstream_auth="qa-b")
            assert auth1["body"] == "origin-qa-a-1" and auth2["body"] == "origin-qa-b-2"
            assert http.hits["/auth"] == 2
            invoke("cache", "clear")
            refetched = client("http")
            assert refetched["body"] == "public-2" and http.hits["/public"] == 2
            check("public cache hit and clear; private and authorized responses remain separate")

            transfer_digest = hashlib.sha256(TRANSFER).hexdigest()
            tunnel = client("connect")
            assert tunnel == {
                "status": 200, "challenge_status": 407,
                "challenge_has_digest": True, "sha256": transfer_digest,
            }, tunnel
            bad_tunnel = client("connect", password="wrong-password")
            assert bad_tunnel["challenge_status"] == bad_tunnel["status"] == 407, bad_tunnel
            assert bad_tunnel["challenge_has_digest"], bad_tunnel
            socks = client("socks", port=socks_port)
            assert socks["method"] == 2 and socks["auth"] == "0100"
            assert socks["reply"] == 0 and socks["sha256"] == transfer_digest
            check("CONNECT Digest challenge and wrong password; authenticated SOCKS5 and CONNECT carry byte-exact 1 MiB transfers")

            before_tls = invoke("status")["stats"]["cacheBytesSaved"]
            https1 = client("https", certificate=str(certificate))
            https2 = client("https", certificate=str(certificate))
            assert https1["status"] == https2["status"] == 200
            assert https1["challenge_status"] == https2["challenge_status"] == 407
            assert https1["challenge_has_digest"] and https2["challenge_has_digest"]
            assert https1["https_status"] == https2["https_status"] == 200
            assert https1["body"] == "tls-1" and https2["body"] == "tls-2"
            assert https1["tls_version"].startswith("TLSv1.")
            assert tls_origin.hits == 2
            assert invoke("status")["stats"]["cacheBytesSaved"] == before_tls
            check("verified HTTPS TLS handshake and distinct uncached responses through CONNECT tunnel")

            udp_result = client("udp", port=socks_port)
            assert udp_result["method"] == 2 and udp_result["reply"] == 0, udp_result
            assert udp_result["udp_payload"] == "udp:udp-probe"
            assert udp_hits == [b"udp-probe"]
            for private_ip in ("127.0.0.1", SERVER):
                private_udp = client("udp", port=socks_port, udp_target=private_ip, drop=True)
                assert private_udp["udp_payload"] is None, (private_ip, private_udp)
            assert not private_udp_hits, private_udp_hits
            assert udp_hits == [b"udp-probe"]
            check("SOCKS5 UDP relays public destination and never reaches live private UDP listeners")

            config_apply({
                "deviceLimits": [{
                    "ip": CLIENT, "uploadBytesPerSecond": 0,
                    "downloadBytesPerSecond": 128 * 1024,
                }],
            })
            assert invoke("status")["running"]
            limited = client("connect", timed=True)
            assert limited["status"] == 200 and limited["sha256"] == transfer_digest
            assert limited["transfer_seconds"] >= 6.5, limited
            config_apply({"deviceLimits": []})
            assert invoke("status")["settings"]["deviceLimits"] == []
            unlimited = client("connect", timed=True)
            assert unlimited["status"] == 200 and unlimited["sha256"] == transfer_digest
            assert unlimited["transfer_seconds"] < limited["transfer_seconds"] - 3, (limited, unlimited)
            check("per-device 128 KiB/s download limit slows 1 MiB without corruption and clearing restores speed")

            assert client("http", target="http://127.0.0.1/private")["status"] == 403
            assert client("connect", target="127.0.0.1:443")["status"] == 403
            private_socks = client("socks", port=socks_port, target="127.0.0.1")
            assert private_socks["reply"] == 2
            assert client("connect", target=f"{ORIGIN}:22")["status"] == 403
            assert client("http", target="http://ads.doubleclick.net/banner")["status"] == 403
            check("private destinations, restricted CONNECT port and ad host are blocked")

            invoke("devices", "deny", CLIENT)
            with ThreadPoolExecutor(max_workers=2) as pool:
                denied = pool.submit(client, "http")
                allowed = pool.submit(client, "http", client_ip=CLIENT_TWO)
                assert denied.result()["status"] == 407
                assert allowed.result()["status"] == 200
            assert client("socks", port=socks_port)["method"] == 255
            invoke("devices", "allow", CLIENT)
            assert client("http")["status"] == 200
            check("device deny/allow isolates two simultaneous client IPs in a separate network namespace")

            status = invoke("status")
            assert status["running"] and status["stats"]["blockedRequests"] >= 1
            assert status["stats"]["cacheBytesSaved"] > 0
            invoke("stop")
            assert not invoke("status")["running"]
            assert not client("probe")["connected"]
            assert not client("probe", port=socks_port)["connected"]
            check("CLI state and counters match observed traffic; Stop closes listeners")

            if args.report:
                report = {
                    "passed": passed, "count": len(passed), "release_daemon": str(source_daemon),
                    "release_cli": str(source_cli), "client_ips": [CLIENT, CLIENT_TWO],
                    "tested_daemon_sha256": daemon_sha256,
                    "tested_cli_sha256": cli_sha256,
                    "origin_ip": ORIGIN, "network": "two disposable Linux network namespaces",
                    "origin_hits": dict(http.hits), "tls_origin_hits": tls_origin.hits,
                    "udp_origin_hits": len(udp_hits),
                    "private_udp_origin_hits": len(private_udp_hits),
                    "transfer_bytes_each": len(TRANSFER), "transfer_sha256": transfer_digest,
                    "limited_transfer_seconds": limited["transfer_seconds"],
                    "unlimited_transfer_seconds": unlimited["transfer_seconds"],
                    "host_network_changes": False,
                }
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2) + "\n")
                os.chown(args.report, original_uid, original_gid)
            print(f"{len(passed)} release-daemon data path scenarios passed", flush=True)
        finally:
            if daemon_process is not None:
                if daemon_process.poll() is None:
                    daemon_process.send_signal(signal.SIGTERM)
                try:
                    daemon_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    daemon_process.kill()
                    daemon_process.wait(timeout=5)
            stop_udp.set()
            if udp is not None:
                udp.close()
            for listener in private_udp_sockets:
                listener.close()
            if http is not None:
                http.shutdown()
                http.server_close()
            if echo is not None:
                echo.shutdown()
                echo.server_close()
            if tls_origin is not None:
                tls_origin.shutdown()
                tls_origin.server_close()
            namespace.terminate()
            namespace.wait(timeout=5)
            log.close()
            if sys.exc_info()[0] is not None and args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                diagnostic = args.report.with_name(args.report.stem + "-daemon.log")
                shutil.copyfile(root / "daemon.log", diagnostic)
                os.chmod(diagnostic, 0o600)
                os.chown(diagnostic, original_uid, original_gid)
                failure = {
                    "passed": passed,
                    "count": len(passed),
                    "failure_type": sys.exc_info()[0].__name__,
                    "tested_daemon_sha256": daemon_sha256,
                    "tested_cli_sha256": cli_sha256,
                    "daemon_log": str(diagnostic),
                }
                args.report.write_text(json.dumps(failure, indent=2) + "\n")
                os.chown(args.report, original_uid, original_gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries-dir", type=Path, default=Path("target/release"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.client:
        client_main()
    elif args.inside:
        inside_main(args)
    else:
        assert os.geteuid() != 0, "run as an ordinary user with sudo -n available"
        command = [
            "sudo", "-n", "unshare", "--net", "--", sys.executable, str(Path(__file__).resolve()),
            "--inside", "--binaries-dir", str(args.binaries_dir.resolve()),
        ]
        if args.report:
            command += ["--report", str(args.report.resolve())]
        raise SystemExit(subprocess.call(command))


if __name__ == "__main__":
    main()
