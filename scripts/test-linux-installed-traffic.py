#!/usr/bin/env python3
"""Exercise the installed systemd proxy inside the disposable homeproxy-qa VM.

Run as root inside that VM with --ack-disposable-vm. The fixture address is
added only to the guest loopback interface and removed before exit. No DNS,
public endpoint, host network interface, firewall, or trust store is touched.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading


ORIGIN = "1.1.1.123"
PAYLOAD = bytes(range(256)) * 256


def command(*args, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True, check=True)


def cli(*args, input=None):
    result = command("homeproxy", "--json", *args, input=input)
    value = json.loads(result.stdout)
    assert value["ok"], (args, value.get("error", {}).get("code"))
    return value["result"]


def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        data = stream.recv(length - len(result))
        assert data, f"upstream closed at {len(result)} of {length} bytes"
        result.extend(data)
    return bytes(result)


def response_headers(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        assert len(result) < 16_384
        result.extend(exact(stream, 1))
    return bytes(result)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request = response_headers(self.request)
        assert request.startswith(b"GET http") or request.startswith(b"GET /")
        self.server.hits.append(request)
        body = b"installed-systemd-http-ok"
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body
        )


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        length = struct.unpack("!I", exact(self.request, 4))[0]
        assert length == len(PAYLOAD)
        self.server.hits.append(length)
        self.request.sendall(exact(self.request, length))


def exchange_http(port):
    with socket.create_connection(("127.0.0.1", port), 5) as stream:
        stream.settimeout(5)
        stream.sendall(
            f"GET http://{ORIGIN}/installed-qa HTTP/1.1\r\n"
            f"Host: {ORIGIN}\r\nConnection: close\r\n\r\n".encode()
        )
        data = bytearray()
        while chunk := stream.recv(4096):
            data.extend(chunk)
    head, marker, body = bytes(data).partition(b"\r\n\r\n")
    assert marker and head.startswith(b"HTTP/1.1 200 "), head
    assert body == b"installed-systemd-http-ok", body


def exchange_echo(stream):
    stream.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
    result = exact(stream, len(PAYLOAD))
    assert result == PAYLOAD
    return hashlib.sha256(result).hexdigest()


def exchange_connect(port):
    with socket.create_connection(("127.0.0.1", port), 5) as stream:
        stream.settimeout(5)
        target = f"{ORIGIN}:443"
        stream.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        head = response_headers(stream)
        assert head.startswith(b"HTTP/1.1 200 "), head
        return exchange_echo(stream)


def exchange_socks(port):
    with socket.create_connection(("127.0.0.1", port), 5) as stream:
        stream.settimeout(5)
        stream.sendall(b"\x05\x01\x00")
        assert exact(stream, 2) == b"\x05\x00"
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ORIGIN) + struct.pack("!H", 443))
        head = exact(stream, 4)
        assert head[:2] == b"\x05\x00", head
        assert head[3] in (1, 4), head
        exact(stream, 6 if head[3] == 1 else 18)
        return exchange_echo(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ack-disposable-vm", action="store_true", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    assert os.geteuid() == 0, "run as root inside the disposable VM"
    assert command("hostname").stdout.strip() == "homeproxy-qa", "refusing a non-QA host"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert command("systemctl", "is-active", "homeproxy").stdout.strip() == "active"
    assert command("dpkg-query", "-W", "-f=${Status}", "homeproxy").stdout.strip() == "install ok installed"
    pid = int(command("systemctl", "show", "-p", "MainPID", "--value", "homeproxy").stdout)
    assert pid > 1 and Path(f"/proc/{pid}/exe").resolve() == Path("/usr/bin/homeproxyd")
    original = cli("status")
    assert original["running"], "installed proxy must already be running"
    settings = original["settings"]
    proxy_port = settings["proxyPort"]
    socks_port = 11080 if proxy_port != 11080 else 11081
    previous_socks = {"socks5Enabled": settings["socks5Enabled"], "socks5Port": settings["socks5Port"]}
    assert f"{ORIGIN}/32" not in command("ip", "-4", "address", "show", "dev", "lo").stdout, "fixture alias already exists"

    alias_added = False
    settings_changed = False
    http = echo = None
    passed = []
    try:
        command("ip", "address", "add", f"{ORIGIN}/32", "dev", "lo")
        alias_added = True
        assert f"{ORIGIN}/32" in command("ip", "-4", "address", "show", "dev", "lo").stdout

        http = Server((ORIGIN, 80), HttpHandler)
        http.hits = []
        echo = Server((ORIGIN, 443), EchoHandler)
        echo.hits = []
        threading.Thread(target=http.serve_forever, daemon=True).start()
        threading.Thread(target=echo.serve_forever, daemon=True).start()

        cli("config", "apply", "--stdin", input=json.dumps({"socks5Enabled": True, "socks5Port": socks_port}))
        settings_changed = True
        assert cli("status")["running"] and cli("doctor")["health"] == "ok"
        assert int(command("systemctl", "show", "-p", "MainPID", "--value", "homeproxy").stdout) == pid

        exchange_http(proxy_port)
        assert len(http.hits) == 1
        passed.append("installed systemd service forwards real HTTP to a guest-only origin")

        digest = hashlib.sha256(PAYLOAD).hexdigest()
        assert exchange_connect(proxy_port) == digest
        assert exchange_socks(socks_port) == digest
        assert echo.hits == [len(PAYLOAD), len(PAYLOAD)]
        passed.append("installed systemd service forwards byte-exact CONNECT and dedicated SOCKS5 TCP")

        after = cli("status")
        assert after["running"] and cli("doctor")["health"] == "ok"
        assert after["stats"]["socks5Connections"] >= original["stats"]["socks5Connections"] + 1
        passed.append("service remains healthy and reports observed SOCKS5 traffic")

    finally:
        cleanup_errors = []
        if settings_changed:
            try:
                cli("config", "apply", "--stdin", input=json.dumps(previous_socks))
            except Exception as error:
                cleanup_errors.append(("SOCKS settings", error))
        if http:
            try:
                http.shutdown()
                http.server_close()
            except Exception as error:
                cleanup_errors.append(("HTTP origin", error))
        if echo:
            try:
                echo.shutdown()
                echo.server_close()
            except Exception as error:
                cleanup_errors.append(("TCP origin", error))
        if alias_added:
            try:
                command("ip", "address", "del", f"{ORIGIN}/32", "dev", "lo")
            except Exception as error:
                cleanup_errors.append(("guest loopback alias", error))
        if cleanup_errors:
            raise AssertionError(f"guest fixture cleanup failed: {[name for name, _ in cleanup_errors]}")

    report = {
        "passed": passed,
        "count": len(passed),
        "package_version": command("dpkg-query", "-W", "-f=${Version}", "homeproxy").stdout.strip(),
        "installed_daemon_sha256": hashlib.sha256(Path("/usr/bin/homeproxyd").read_bytes()).hexdigest(),
        "origin_ip": ORIGIN,
        "payload_bytes_each": len(PAYLOAD),
        "payload_sha256": digest,
        "systemd_pid": pid,
        "client_source": "guest loopback; external LAN authentication is tested separately",
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": passed, "count": len(passed)}))


if __name__ == "__main__":
    main()
