#!/usr/bin/env python3
"""Collect a bounded, read-only Ubuntu HomeProxy incident before Stop/Start.

Python 3 standard library only. Does not elevate privileges or contact origins.
Run as the desktop user first; sudo is an explicit operator choice. The report
contains LAN IPs and resource counters; review it before sharing. Free-form CLI
and journal messages are classified, never saved. Output files are private.
"""

import argparse
import collections
import datetime
import ipaddress
import json
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import time

COMMAND_TIMEOUT = 5.0
COMMAND_BYTES = 1024 * 1024
REPORT_BYTES = 4 * 1024 * 1024
PROTOCOLS = {"tcp", "http", "connect", "socks5", "socks5-udp", "websocket", "inspect"}
STATS_NUMBERS = """activeConnections connectionLimit connectionLimitPerPeer
idleConnectionsClosed keepaliveConfigurationFailures listenerRuntimeErrors
rejectedConnections uploadBytes downloadBytes uploadBytesPerSecond
downloadBytesPerSecond originBytes deliveredBytes cacheMisses cacheBypasses
totalRequests blockedRequests cacheHits cacheBytesSaved compressedImages
compressionBytesSaved connectTunnels socks5Connections
 authenticatedExternalRequests successfulExternalRequests uniqueClients savedBytes""".split()
SETTING_NUMBERS = """version tunnelIdleTimeoutSeconds proxyPort socks5Port lanDnsPort
historyRetentionDays scheduleUtcOffsetMinutes cacheLimitGib cacheMaxObjectMib
responseBufferLimitMib responseBufferBudgetMib offlineMaxStaleHours""".split()
SETTING_BOOLS = """enabled lanEnabled socks5Enabled socks5UdpEnabled lanAuthEnabled
pacEnabled pacDirectFallback upstreamDirectFallback lanDnsEnabled cacheEnabled
httpsClientTrustAcknowledged""".split()
SYSTEM_PROPERTIES = """MainPID ActiveState SubState Result NRestarts LimitNOFILE
LimitNOFILESoft TasksCurrent TasksMax MemoryCurrent MemoryMax CPUUsageNSec
ExecMainStartTimestampMonotonic ExecMainCode ExecMainStatus""".split()
SYSTEM_ENUMS = {"active", "inactive", "failed", "activating", "deactivating", "reloading",
                "running", "dead", "exited", "start", "stop", "auto-restart", "success",
                "exit-code", "signal", "core-dump", "timeout", "oom-kill", "resources"}


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def numbers(data, keys):
    if not isinstance(data, dict):
        return {}
    return {key: data[key] for key in keys if type(data.get(key)) in (int, float)
            and abs(data[key]) <= 2 ** 64 and math.isfinite(data[key])}


def booleans(data, keys):
    if not isinstance(data, dict):
        return {}
    return {key: data[key] for key in keys if type(data.get(key)) is bool}


def diagnostics(message):
    """Fixed vocabulary only: paths, credentials, hostnames and prose never escape."""
    if not isinstance(message, str) or not message:
        return {"present": False}
    lower = message[:COMMAND_BYTES].lower()
    patterns = {
        "fd-exhaustion": r"too many open files|emfile|enfile",
        "disk-full": r"no space left|enospc|disk full",
        "permission-denied": r"permission denied|eacces|eperm",
        "timeout": r"timed?\s*out|timeout",
        "connection-refused": r"connection refused|econnrefused",
        "network-unreachable": r"network is unreachable|no route to host|enetunreach|ehostunreach",
        "connection-reset": r"connection reset|econnreset|broken pipe",
        "memory-exhaustion": r"out of memory|cannot allocate memory|enomem|oom",
        "capacity": r"connection (?:limit|capacity)|capacity exhausted|no free connection slots|peer-limit|global-limit",
        "quota": r"quota|kvóta|kvóty",
        "history": r"history|historie|historii",
        "checkpoint": r"checkpoint|persist",
        "listener": r"listener|accept|bind|address already in use",
        "dns": r"dns|name resolution",
        "tls": r"tls|certificate|certifik",
    }
    result = {"present": True, "categories": [key for key, pattern in patterns.items()
                                               if re.search(pattern, lower)]}
    result["osErrorNumbers"] = sorted({int(number) for number in
                                       re.findall(r"(?:os error|errno)[ :()]+(\d{1,3})", lower)})
    return result


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) and "%" not in value else None
    except ValueError:
        return None


def project_status(value):
    """Allowlist types AND fields; unknown/nested private data is discarded."""
    if not isinstance(value, dict):
        raise ValueError("status must be an object")
    result = booleans(value, ["running", "tlsInspectionReady", "supportsHttpsInspection"])
    version = value.get("serviceVersion")
    if isinstance(version, str) and re.fullmatch(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})", version):
        result["serviceVersion"] = version
    history = value.get("usageHistory")
    result["usageHistory"] = {"available": isinstance(history, dict)}
    if isinstance(history, dict):
        result["usageHistory"].update({**booleans(history, ["healthy"]),
                                      **numbers(history, ["retentionDays", "rowCount", "monthCount",
                                                          "quotaDebtCount", "quotaCreditCount"]),
                                      "error": diagnostics(history.get("error"))})
    for key in ("proxyAddresses", "socks5Addresses"):
        addresses = value.get(key)
        if isinstance(addresses, list):
            result[key] = [safe for address in addresses[:256] if isinstance(address, str)
                           for safe in [endpoint(address)] if safe is not None]
    available = value.get("availableAddresses")
    if isinstance(available, list):
        result["availableAddresses"] = [{"ip": valid_ip(row["ip"])} for row in available[:256]
                                        if isinstance(row, dict) and valid_ip(row.get("ip"))]
    bind_error = value.get("listenerError")
    if isinstance(bind_error, dict):
        result["listenerError"] = {}
        for key, allowed in {"service": {"http", "socks5", "dns"},
                             "reason": {"inUse", "accessDenied", "addressUnavailable", "other"}}.items():
            if isinstance(bind_error.get(key), str) and bind_error[key] in allowed:
                result["listenerError"][key] = bind_error[key]
        address = bind_error.get("endpoint")
        if isinstance(address, str) and endpoint(address):
            result["listenerError"]["endpoint"] = endpoint(address)
    settings = value.get("settings", {})
    result["settings"] = {**numbers(settings, SETTING_NUMBERS),
                          **booleans(settings, SETTING_BOOLS)}
    for key in ("upstreamProxies", "deviceProfiles", "deviceLimits", "deniedClientIps",
                "allowDomains", "blockDomains", "filterFeeds"):
        if isinstance(settings, dict) and isinstance(settings.get(key), list):
            result["settings"][key + "Count"] = len(settings[key])
    if isinstance(settings, dict):
        for key, allowed in {"httpsMode": {"tunnel", "inspect"},
                             "cacheMode": {"online", "offline"},
                             "dnsMode": {"system", "cloudflare"}}.items():
            if isinstance(settings.get(key), str) and settings[key] in allowed:
                result["settings"][key] = settings[key]
    stats = value.get("stats", {})
    result["stats"] = numbers(stats, STATS_NUMBERS)
    if isinstance(stats, dict):
        result["stats"]["listenerRuntimeError"] = diagnostics(stats.get("listenerRuntimeError"))
        live = stats.get("liveConnections")
        if isinstance(live, list):
            rows = []
            for row in live[:256]:
                if not isinstance(row, dict):
                    continue
                safe = numbers(row, ["id", "ageMs", "idleMs"])
                peer = valid_ip(row.get("peerIp"))
                if peer:
                    safe["peerIp"] = peer
                if isinstance(row.get("protocol"), str) and row["protocol"] in PROTOCOLS:
                    safe["protocol"] = row["protocol"]
                rows.append(safe)
            result["stats"]["liveConnections"] = rows
            result["stats"]["liveConnectionsTruncated"] = len(live) > 256
        rejection = stats.get("latestConnectionRejection")
        if isinstance(rejection, dict):
            safe = numbers(rejection, ["limit", "unixMs"])
            for key in ("peerIp", "listenerIp"):
                address = valid_ip(rejection.get(key))
                if address:
                    safe[key] = address
            if rejection.get("reason") in ("peer-limit", "global-limit"):
                safe["reason"] = rejection["reason"]
            result["stats"]["latestConnectionRejection"] = safe
    quotas = value.get("quotaStatuses")
    if isinstance(quotas, list):
        result["quotaStatuses"] = [
            {**numbers(row, ["dailyBytes", "monthlyBytes", "dailyQuotaMib", "monthlyQuotaMib",
                             "warningPercent"]),
             **booleans(row, ["warning", "blocked", "historyHealthy"])}
            for row in quotas[:256] if isinstance(row, dict)]
        result["quotaStatusesTruncated"] = len(quotas) > 256
    cache = value.get("cache", {})
    result["cache"] = {**numbers(cache, ["usedBytes", "entryCount"]),
                       **booleans(cache, ["pendingMaintenance", "measured", "usageIsCurrent"])}
    if isinstance(cache, dict):
        for key in ("measurementError", "maintenanceError"):
            result["cache"][key] = diagnostics(cache.get(key))
    result["lastError"] = diagnostics(value.get("lastError"))
    return result


def run_command(argv, timeout=COMMAND_TIMEOUT, max_bytes=COMMAND_BYTES):
    """Drain capped pipes in memory; kill only this collector's command group."""
    started = time.monotonic()
    output = {"returncode": None, "timedOut": False, "truncated": False}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 stdin=subprocess.DEVNULL, start_new_session=True,
                                 env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except OSError as error:
        output.update({"unavailable": True, "errno": error.errno})
        return output, "", ""
    with selectors.DefaultSelector() as selector:
        for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        deadline = started + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                output["timedOut"] = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                room = max(0, max_bytes - len(buffer))
                buffer.extend(chunk[:room])
                if len(chunk) > room:
                    output["truncated"] = True
        # Pipes can close while the child still runs. Bound that wait as well.
        try:
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            output["timedOut"] = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=1)
    child.stdout.close()
    child.stderr.close()
    output.update({"returncode": child.returncode,
                   "durationSeconds": round(time.monotonic() - started, 3)})
    return output, buffers["stdout"].decode("utf-8", "replace"), buffers["stderr"].decode("utf-8", "replace")


def capture(argv, projector, timeout=COMMAND_TIMEOUT):
    meta, stdout, stderr = run_command(argv, timeout=timeout)
    result = {"command": meta, "stderr": diagnostics(stderr)}
    if meta.get("timedOut") or meta.get("truncated") or meta.get("unavailable"):
        result["dataUnavailable"] = True
        return result
    try:
        result["data"] = projector(stdout)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        result["invalidOutput"] = True
    return result


def cli_projection(text, action):
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("CLI envelope must be an object")
    result = booleans(value, ["ok"])
    if value.get("ok") is False:
        error = value.get("error", {})
        if isinstance(error, dict):
            code = error.get("code")
            if code in ("unavailable", "degraded", "input", "unauthorized", "forbidden",
                        "unsafe_socket", "protocol", "io", "timeout"):
                result["errorCode"] = code
            result["error"] = diagnostics(error.get("message"))
        return result
    payload = value.get("result")
    if action == "status":
        result["status"] = project_status(payload)
    elif isinstance(payload, dict):
        result["doctor"] = {}
        for key, allowed in {"health": {"ok", "degraded"},
                             "state": {"running", "intentionally stopped"}}.items():
            if isinstance(payload.get(key), str) and payload[key] in allowed:
                result["doctor"][key] = payload[key]
    else:
        raise ValueError("CLI result must be an object")
    return result


def system_projection(text):
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in SYSTEM_PROPERTIES:
            if value.isdigit() and len(value) <= 20:
                result[key] = int(value)
            elif value in SYSTEM_ENUMS or value == "infinity":
                result[key] = value
    return result


def version_projection(text):
    # Only a semver adjacent to a fixed product name is retained.
    return {"versions": re.findall(r"\b(homeproxy(?:d)?)\s+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]{1,32})?)\b", text)[:4]}


def package_projection(text):
    result = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[0] in ("homeproxy", "homeproxy-desktop"):
            if re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{0,80}", fields[1]):
                result.append({"package": fields[0], "version": fields[1],
                               "installed": fields[2] == "ii "})
    return result


def journal_projection(text):
    rows, unclassified = [], 0
    for line in text.splitlines()[:200]:
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        summary = diagnostics(value.get("MESSAGE"))
        if not summary.get("categories") and not summary.get("osErrorNumbers"):
            unclassified += 1
        row = {"diagnostic": summary}
        for key in ("__REALTIME_TIMESTAMP", "PRIORITY"):
            number = value.get(key)
            if isinstance(number, str) and number.isdigit() and len(number) <= 20:
                row[key] = number
        rows.append(row)
    return {"events": rows, "unclassifiedEvents": unclassified,
            "note": "Free-form messages, hostnames, identities and paths omitted."}


def endpoint(value):
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)\]:(\d{1,5}|\*)", value)
    else:
        match = re.fullmatch(r"(.+):(\d{1,5}|\*)", value)
    if not match:
        return None
    address, port = match.groups()
    address = address.split("%", 1)[0]
    if address != "*" and not valid_ip(address):
        return None
    if port != "*" and int(port) > 65535:
        return None
    return {"address": address, "port": int(port) if port != "*" else "*"}


def socket_projection(text, listeners=False):
    states, rows = collections.Counter(), []
    allowed = {"ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT",
               "CLOSE", "CLOSE-WAIT", "LAST-ACK", "LISTEN", "CLOSING", "UNCONN"}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in allowed:
            continue
        states[fields[0]] += 1
        if listeners:
            local = endpoint(fields[3])
            if local and len(rows) < 512:
                rows.append({"state": fields[0], "local": local})
    return {"states": dict(states), **({"listeners": rows} if listeners else {})}


def network_projection(text, routes=False):
    value = json.loads(text)
    if not isinstance(value, list):
        raise ValueError("IP data must be an array")
    result = []
    for item in value[:256]:
        if not isinstance(item, dict):
            continue
        safe = numbers(item, ["ifindex", "mtu", "metric"])
        if routes:
            for key in ("gateway", "prefsrc"):
                address = valid_ip(item.get(key))
                if address:
                    safe[key] = address
            dst = item.get("dst")
            try:
                safe["dst"] = "default" if dst == "default" else str(ipaddress.ip_network(dst, strict=False))
            except (ValueError, TypeError):
                pass
        else:
            safe["addresses"] = []
            addresses = item.get("addr_info", [])
            if isinstance(addresses, list):
                for address in addresses[:64]:
                    if isinstance(address, dict) and valid_ip(address.get("local")):
                        safe["addresses"].append({"local": valid_ip(address["local"]),
                                                   **numbers(address, ["prefixlen"])})
        # Interface names, MACs, SSIDs and route hostnames are not preserved.
        result.append(safe)
    return result


def read_small(path, limit=65536):
    with open(path, "r", encoding="utf-8", errors="replace") as source:
        return source.read(limit)


def proc_snapshot(pid):
    result = {"pid": pid}
    root = "/proc/" + str(pid)
    try:
        text = read_small(root + "/status")
        keys = {"VmPeak", "VmSize", "VmHWM", "VmRSS", "RssAnon", "RssFile", "VmSwap",
                "Threads", "FDSize", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}
        result["status"] = {}
        for line in text.splitlines():
            key, _, value = line.partition(":")
            if key in keys:
                match = re.fullmatch(r"\s*(\d{1,20})(?:\s+kB)?\s*", value)
                if match:
                    result["status"][key] = int(match[1])
            elif key == "State" and re.match(r"\s*[RSDZTIX]\b", value):
                result["state"] = value.strip()[0]
        limits = read_small(root + "/limits")
        result["limits"] = {}
        for line in limits.splitlines():
            match = re.fullmatch(r"(Max open files|Max processes|Max address space|Max locked memory)\s+(\d+|unlimited)\s+(\d+|unlimited)\s+\w*", line)
            if match:
                result["limits"][match[1]] = {"soft": match[2], "hard": match[3]}
    except OSError as error:
        result["statusErrorErrno"] = error.errno
    try:
        kinds = collections.Counter()
        with os.scandir(root + "/fd") as descriptors:
            for index, entry in enumerate(descriptors):
                if index >= 20000:
                    result["fdTruncated"] = True
                    break
                try:
                    target = os.readlink(entry.path)
                    kind = ("socket" if target.startswith("socket:[") else
                            "pipe" if target.startswith("pipe:[") else
                            "anonymous" if target.startswith("anon_inode:") else "file-or-device")
                    kinds[kind] += 1
                except OSError:
                    kinds["unreadable"] += 1
        result["fdKinds"] = dict(kinds)
        result["fdCount"] = sum(kinds.values())
    except OSError as error:
        result["fdErrorErrno"] = error.errno
    try:
        channels = collections.Counter()
        with os.scandir(root + "/task") as tasks:
            for index, entry in enumerate(tasks):
                if index >= 512:
                    result["tasksTruncated"] = True
                    break
                if not entry.name.isdigit():
                    continue
                try:
                    value = read_small(entry.path + "/wchan", 128).strip()
                    channels[value if re.fullmatch(r"[A-Za-z0-9_]{1,80}", value) else "omitted"] += 1
                except OSError:
                    channels["unreadable"] += 1
        result["taskWaitChannels"] = dict(channels)
    except OSError as error:
        result["taskErrorErrno"] = error.errno
    return result


def filesystem_snapshot():
    result = {}
    for label, path in (("root", "/"), ("service-state", "/var/lib/homeproxy"),
                        ("service-cache", "/var/cache/homeproxy")):
        try:
            info = os.statvfs(path)
            result[label] = {"capacityBytes": info.f_blocks * info.f_frsize,
                             "availableBytes": info.f_bavail * info.f_frsize,
                             "freeBytes": info.f_bfree * info.f_frsize,
                             "freeInodes": info.f_favail}
        except OSError as error:
            result[label] = {"errno": error.errno}
    return result


def prepare_output(path):
    """Traverse without symlinks; pin directory inode and exclusively create file."""
    absolute = os.path.abspath(path)
    parts = absolute.split(os.sep)
    if absolute == "/":
        raise ValueError("output directory must not be root")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(parts[1:]):
            if index == len(parts[1:]) - 1:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory)
                except FileExistsError:
                    raise ValueError("output directory already exists; choose a new directory") from None
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid():
            raise ValueError("output directory must belong to the current user")
        # Refuse a repeat run before changing directory permissions.
        try:
            os.stat("incident.json", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("incident.json already exists; choose a new output directory")
        os.fchmod(directory, 0o700)
        descriptor = os.open("incident.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)
        return directory, descriptor
    except BaseException:
        os.close(directory)
        raise


def collect(args):
    cli = ["homeproxy"] + (["--socket", args.socket] if args.socket else []) + ["--json"]
    report = {"metadata": {
        "schemaVersion": 1, "startedUtc": utc_now(), "effectiveUid": os.geteuid(),
        "platform": "linux", "commandTimeoutSeconds": COMMAND_TIMEOUT,
        "commandOutputLimitBytes": COMMAND_BYTES, "reportLimitBytes": REPORT_BYTES,
        "samplesRequested": args.samples, "intervalSeconds": args.interval,
        "customControlSocket": bool(args.socket),
        "serviceScope": "Installed homeproxy.service; may differ from a custom control socket",
        "socketSummaryScope": "Host-wide TCP state counts and TCP/UDP listeners, not only HomeProxy",
        "permissions": "Directory 0700, report 0600; no automatic sudo",
        "privacy": "LAN peer/listener/interface/route IPs retained; review before sharing",
        "notCollected": ["settings files", "environment", "credentials", "CA/keys", "core dumps",
                         "browsing/activity/history rows", "client/profile names", "origin socket addresses",
                         "raw CLI errors", "raw journal messages", "external network probes"],
        "mutations": "Only the requested diagnostic output directory/file"}, "samples": []}
    report["versions"] = {
        "cli": capture(["homeproxy", "--version"], version_projection),
        "daemon": capture(["homeproxyd", "--version"], version_projection),
        "packages": capture(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n",
                              "homeproxy", "homeproxy-desktop"], package_projection)}
    try:
        uptime = read_small("/proc/uptime", 128).split()[0]
        report["uptimeSeconds"] = float(uptime)
    except (OSError, ValueError, IndexError):
        report["uptimeUnavailable"] = True
    for sample_index in range(args.samples):
        sample = {"sample": sample_index + 1, "startedUtc": utc_now()}
        sample["service"] = capture(["systemctl", "show", "homeproxy.service", "--no-pager",
                                     "--property=" + ",".join(SYSTEM_PROPERTIES)], system_projection)
        pid = sample["service"].get("data", {}).get("MainPID")
        if type(pid) is int and 0 < pid < 2 ** 31:
            sample["process"] = proc_snapshot(pid)
        sample["status"] = capture(cli + ["status"], lambda text: cli_projection(text, "status"))
        sample["doctor"] = capture(cli + ["doctor"], lambda text: cli_projection(text, "doctor"))
        sample["tcpStates"] = capture(["ss", "-H", "-tan"], socket_projection)
        sample["tcpListeners"] = capture(["ss", "-H", "-ltn"], lambda text: socket_projection(text, True))
        sample["udpListeners"] = capture(["ss", "-H", "-lun"], lambda text: socket_projection(text, True))
        sample["completedUtc"] = utc_now()
        report["samples"].append(sample)
        if sample_index + 1 < args.samples:
            time.sleep(args.interval)
    report["network"] = {
        "addresses": capture(["ip", "-j", "address", "show"], network_projection),
        "routesV4": capture(["ip", "-j", "-4", "route", "show"], lambda text: network_projection(text, True)),
        "routesV6": capture(["ip", "-j", "-6", "route", "show"], lambda text: network_projection(text, True))}
    report["filesystems"] = filesystem_snapshot()
    report["journal"] = capture(["journalctl", "--unit=homeproxy.service", "--since=-2days",
                                 "--lines=200", "--output=json", "--no-pager", "--quiet"], journal_projection)
    report["metadata"]["completedUtc"] = utc_now()
    return report


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="New private report directory; must not exist, and its parent must exist")
    parser.add_argument("--socket", help="Optional local HomeProxy Unix control socket (no service changes)")
    parser.add_argument("--samples", type=int, default=3, help="Status sample count, 1–10 (default 3)")
    parser.add_argument("--interval", type=float, default=2.0, help="Pause between completed samples, 0–30 seconds")
    args = parser.parse_args(argv)
    if not 1 <= args.samples <= 10:
        parser.error("--samples must be between 1 and 10")
    if not math.isfinite(args.interval) or not 0 <= args.interval <= 30:
        parser.error("--interval must be finite and between 0 and 30")
    return args


def main(argv=None):
    args = arguments(argv)
    if sys.platform != "linux":
        print("This collector requires Linux.", file=sys.stderr)
        return 2
    try:
        directory, descriptor = prepare_output(args.output_dir)
    except (OSError, ValueError):
        print("Cannot safely create report. Use a new directory with an existing parent, owned by you; symlinks are refused.", file=sys.stderr)
        return 2
    try:
        report = collect(args)
        data = json.dumps(report, indent=2, allow_nan=False).encode("utf-8") + b"\n"
        if len(data) > REPORT_BYTES:
            raise ValueError("report too large")
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = None
            destination.write(data)
        print("Collected incident.json in the requested directory. Review before sharing; no service changes were made.")
        return 0
    except (OSError, ValueError, KeyboardInterrupt):
        print("Collection interrupted or failed; report is incomplete. Choose a new directory before retrying.", file=sys.stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


if __name__ == "__main__":
    sys.exit(main())
