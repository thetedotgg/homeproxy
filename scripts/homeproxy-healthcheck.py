#!/usr/bin/env python3
"""Read-only HomeProxy health check for long-running Ubuntu installs.

Python 3 standard library only. Changes nothing: runs `homeproxy --json doctor`
and `status`, checks free disk space and repeated client TLS failures per host,
lists the most frequent cache bypass reasons, warns when HTTPS Inspect with cache
has produced no cache HIT yet, and optionally fetches
https://www.youtube.com/generate_204 through the proxy.
Exit 0 = OK, 1 = warning, 2 = failure. Suitable for a manual run or a timer.

The optional end-to-end probe reads the proxy URL (with Digest credentials when
LAN authentication is on) from HOMEPROXY_HEALTH_PROXY, never from arguments, so
the password does not appear in the process list or shell history.
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys

TIMEOUT = 10
TLS_ERRORS = ("TLS-handshake-rejected", "TLS-handshake-timeout")
PROBE_URL = "https://www.youtube.com/generate_204"
BYPASS_REASONS_SHOWN = 5
BYPASS_WARNING_MIN = 50
REASON_CODE = re.compile(r"[a-z0-9-]{1,64}")


def run_cli(cli, action):
    try:
        done = subprocess.run(cli + [action], capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"{action}: {type(error).__name__}"
    try:
        value = json.loads(done.stdout)
    except ValueError:
        return None, f"{action}: invalid output (exit {done.returncode})"
    if not isinstance(value, dict):
        return None, f"{action}: invalid output"
    if value.get("ok") is False:
        error = value.get("error")
        message = error.get("message") if isinstance(error, dict) else None
        return None, f"{action}: {message or 'failed'}"
    return value.get("result"), None


def tls_failures(status):
    activity = (status.get("stats") or {}).get("activity") or []
    counts = collections.Counter(
        (row.get("peerIp", "?"), row.get("host", "?"))
        for row in activity
        if isinstance(row, dict) and row.get("error") in TLS_ERRORS
    )
    return counts.most_common()


def bypass_reasons(stats):
    """(code, count) pairs, most frequent first; reason codes are fixed labels."""
    reasons = stats.get("cacheBypassReasons")
    if not isinstance(reasons, dict):
        return []
    items = [
        (code if REASON_CODE.fullmatch(code) else "other", count)
        for code, count in reasons.items()
        if isinstance(code, str) and type(count) is int and count > 0
    ]
    merged = collections.Counter()
    for code, count in items:
        merged[code] += count
    return sorted(merged.items(), key=lambda item: (-item[1], item[0]))


def stat_count(stats, key):
    value = stats.get(key)
    return value if type(value) is int and value >= 0 else 0


def probe(proxy):
    curl = shutil.which("curl")
    if not curl:
        return None, "curl is not installed; end-to-end probe skipped"
    try:
        # The proxy URL may carry credentials: pass it through the child's private
        # environment (/proc/<pid>/environ is owner-only), never through argv.
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        env["https_proxy"] = proxy
        done = subprocess.run(
            [curl, "-q", "--silent", "--show-error", "--proxy-anyauth",
             "--max-time", "15", "--output", os.devnull, "--write-out", "%{http_code}",
             PROBE_URL],
            capture_output=True, text=True, timeout=20, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"probe: {type(error).__name__}"
    code = (done.stdout or "").strip()
    if done.returncode == 0 and code == "204":
        return True, "YouTube generate_204 through the proxy: 204"
    stderr = (done.stderr or "").strip()
    detail = stderr.splitlines()[-1] if stderr else f"HTTP {code}"
    return False, f"YouTube probe through the proxy failed: {detail}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--socket", help="control socket of an isolated daemon")
    parser.add_argument("--min-free-mib", type=int, default=1024,
                        help="warn below this free space on --disk-path (default 1024)")
    parser.add_argument("--disk-path", default="/var", help="filesystem holding state/cache")
    parser.add_argument("--tls-threshold", type=int, default=3,
                        help="warn when one client fails TLS to one host this often (default 3)")
    args = parser.parse_args()

    cli = ["homeproxy"] + (["--socket", args.socket] if args.socket else []) + ["--json"]
    level = 0
    lines = []

    def report(new_level, text):
        nonlocal level
        level = max(level, new_level)
        lines.append(("OK  ", "WARN", "FAIL")[new_level] + " " + text)

    doctor, error = run_cli(cli, "doctor")
    if error:
        report(2, error)
    else:
        report(0, f"doctor: {(doctor or {}).get('state', 'ok')}")

    status, error = run_cli(cli, "status")
    if error:
        report(2, error)
    elif isinstance(status, dict):
        history = status.get("usageHistory")
        if isinstance(history, dict) and history.get("healthy") is False:
            report(2, f"usage history unhealthy: {history.get('error')}")
        failures = [(key, n) for key, n in tls_failures(status) if n >= args.tls_threshold]
        for (peer, host), count in failures[:10]:
            report(1, f"client {peer} failed HTTPS inspection for {host} {count}x "
                      "(the app does not trust the HomeProxy CA; add a domain exception)")
        if not failures:
            report(0, "no repeated client TLS failures in recent activity")
        stats = status.get("stats") if isinstance(status.get("stats"), dict) else {}
        settings = status.get("settings") if isinstance(status.get("settings"), dict) else {}
        reasons = bypass_reasons(stats)
        if reasons:
            shown = ", ".join(f"{code} {n}" for code, n in reasons[:BYPASS_REASONS_SHOWN])
            report(0, f"cache bypass reasons (top {BYPASS_REASONS_SHOWN}): {shown}")
        bypasses = max(stat_count(stats, "cacheBypasses"), sum(n for _, n in reasons))
        if (settings.get("cacheEnabled") is True and settings.get("httpsMode") == "inspect"
                and stat_count(stats, "cacheHits") == 0 and bypasses >= BYPASS_WARNING_MIN):
            report(1, f"cache is on with HTTPS Inspect but has 0 HITs after {bypasses} bypasses "
                      "(check client CA trust, inspection scope and the bypass reasons above)")

    try:
        free_mib = shutil.disk_usage(args.disk_path).free // (1024 * 1024)
        report(1 if free_mib < args.min_free_mib else 0,
               f"free space on {args.disk_path}: {free_mib} MiB")
    except OSError as error:
        report(1, f"free space on {args.disk_path}: {error.strerror}")

    proxy = os.environ.get("HOMEPROXY_HEALTH_PROXY")
    if proxy:
        ok, text = probe(proxy)
        report(0 if ok else (1 if ok is None else 2), text)

    for line in lines:
        print(line)
    return level


if __name__ == "__main__":
    sys.exit(main())
