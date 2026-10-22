#!/usr/bin/env python3
"""Privacy, bounded execution and output safety tests for the incident collector."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("incident", Path(__file__).with_name("collect-linux-incident.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class PrivacyTests(unittest.TestCase):
    def test_nested_credentials_and_browsing_are_absent_but_live_capacity_remains(self):
        secret = "private-secret-string"
        source = {"running": True, "settings": {
            "proxyPassword": secret, "proxyUsername": secret, "enabled": True,
            "tunnelIdleTimeoutSeconds": 1800,
            "upstreamProxies": [{"username": secret, "password": secret, "authToken": secret}],
            "deviceProfiles": [{"name": secret, "credentials": {"token": secret}}]},
            "stats": {"activeConnections": 128, "connectionLimit": 256,
                      "listenerRuntimeError": f"Permission denied (os error 13) /home/{secret}",
                      "clients": [{"name": secret}], "activity": [{"host": secret}],
                      "history": {"rows": [{"identity": secret}]},
                      "liveConnections": [{"id": 1, "peerIp": "192.0.2.1", "protocol": "connect",
                                           "ageMs": 4567, "idleMs": 1234, "host": secret,
                                           "username": secret}]},
            "quotaStatuses": [{"profileId": secret, "dailyBytes": 2048, "historyHealthy": False,
                               "blocked": True}],
            "cache": {"usedBytes": 30, "maintenanceError": f"No space left on device: {secret}"},
            "lastError": f"Timeout talking to https://{secret}/secret?token={secret}"}
        safe = collector.project_status(source)
        self.assertNotIn(secret, json.dumps(safe))
        self.assertEqual(safe["settings"]["upstreamProxiesCount"], 1)
        self.assertEqual(safe["stats"]["activeConnections"], 128)
        self.assertEqual(safe["stats"]["liveConnections"][0],
                         {"id": 1, "peerIp": "192.0.2.1", "protocol": "connect", "ageMs": 4567, "idleMs": 1234})
        self.assertFalse(safe["quotaStatuses"][0]["historyHealthy"])
        self.assertEqual(safe["stats"]["listenerRuntimeError"]["osErrorNumbers"], [13])
        self.assertIn("disk-full", safe["cache"]["maintenanceError"]["categories"])

    def test_serialized_service_shape_keeps_version_history_health_and_listeners(self):
        envelope = {"ok": True, "result": {
            "running": True, "serviceVersion": "1.2.2", "revision": "private-revision",
            "supportsHttpsInspection": True,
            "settings": {"enabled": True, "dnsMode": "cloudflare", "httpsMode": "tunnel", "cacheMode": "online"},
            "stats": {"activeConnections": 0, "liveConnections": []},
            "proxyAddresses": ["127.0.0.1:8080", "192.0.2.1:8080", "private-user:password@host:8080"],
            "socks5Addresses": ["192.0.2.1:1080"],
            "availableAddresses": [{"interfaceName": "private-interface", "ip": "192.0.2.1"}],
            "listenerError": {"service": "http", "endpoint": "192.0.2.1:8080", "reason": "inUse"},
            "usageHistory": {"healthy": False, "error": "Permission denied (os error 13): /private-path",
                             "retentionDays": 60, "rows": [{"identity": "private-client"}],
                             "months": [{"identity": "private-client"}]},
            "quotaStatuses": [{"profileId": "private-profile", "dailyBytes": 10, "monthlyBytes": 20,
                               "dailyQuotaMib": 1, "monthlyQuotaMib": 2, "warningPercent": 80,
                               "warning": False, "blocked": True, "historyHealthy": False}]}}
        safe = collector.cli_projection(json.dumps(envelope), "status")["status"]
        self.assertEqual(safe["serviceVersion"], "1.2.2")
        self.assertTrue(safe["usageHistory"]["available"])
        self.assertFalse(safe["usageHistory"]["healthy"])
        self.assertEqual(safe["usageHistory"]["retentionDays"], 60)
        self.assertEqual(safe["usageHistory"]["error"]["osErrorNumbers"], [13])
        self.assertEqual(len(safe["proxyAddresses"]), 2)
        self.assertEqual(safe["availableAddresses"], [{"ip": "192.0.2.1"}])
        self.assertEqual(safe["listenerError"]["reason"], "inUse")
        self.assertNotIn("private", json.dumps(safe))
        del envelope["result"]["usageHistory"]
        envelope["result"]["serviceVersion"] = "password=private-version"
        absent = collector.cli_projection(json.dumps(envelope), "status")["status"]
        self.assertEqual(absent["usageHistory"], {"available": False})
        self.assertNotIn("serviceVersion", absent)
        doctor = collector.cli_projection(json.dumps({"ok": False, "error": {"code": "degraded",
            "message": "A proxy client has no free connection slots"}}), "doctor")
        self.assertIn("capacity", doctor["error"]["categories"])
        stopped = collector.cli_projection(json.dumps({"ok": True, "result": {
            "health": "ok", "state": "intentionally stopped"}}), "doctor")
        self.assertEqual(stopped["doctor"]["state"], "intentionally stopped")

    def test_private_data_in_allowed_fields_is_not_saved(self):
        source = {"running": "secret", "settings": {"enabled": {"token": "secret"},
                  "cacheMode": "secret", "tunnelIdleTimeoutSeconds": "secret"},
                  "stats": {"activeConnections": "secret", "liveConnections": [
                      {"peerIp": "user:secret@host", "protocol": "secret", "id": {"secret": 1}}]},
                  "quotaStatuses": [{"dailyBytes": "secret", "blocked": "secret"}]}
        source["stats"]["liveConnections"].append({"peerIp": "fe80::1%secret"})
        source["stats"]["totalRequests"] = 10 ** 1000
        self.assertNotIn("secret", json.dumps(collector.project_status(source)))

    def test_failed_cli_has_no_raw_stdout_stderr_or_messages(self):
        meta = {"returncode": 6, "timedOut": False, "truncated": False}
        raw = json.dumps({"ok": False, "error": {"code": "degraded", "message":
                         "too many open files /private/secret-name password=secret-password"},
                         "settings": {"password": "secret-password"}})
        with patch.object(collector, "run_command", return_value=(meta, raw, "secret-password")):
            safe = collector.capture(["homeproxy", "--json", "doctor"],
                                     lambda text: collector.cli_projection(text, "doctor"))
        self.assertNotIn("secret", json.dumps(safe))
        self.assertEqual(safe["data"]["errorCode"], "degraded")
        self.assertIn("fd-exhaustion", safe["data"]["error"]["categories"])
        with patch.object(collector, "run_command", return_value=(meta, "secret-invalid-json", "secret-stderr")):
            invalid = collector.capture(["homeproxy", "--json", "status"],
                                        lambda text: collector.cli_projection(text, "status"))
        self.assertTrue(invalid["invalidOutput"])
        self.assertNotIn("secret", json.dumps(invalid))

    def test_journal_never_saves_free_form_messages(self):
        text = json.dumps({"MESSAGE": "quota history failed /home/private-user token=private-token",
                           "__REALTIME_TIMESTAMP": "12345", "PRIORITY": "3", "_HOSTNAME": "private-host"})
        safe = collector.journal_projection(text)
        self.assertNotIn("private", json.dumps(safe))
        self.assertEqual(safe["events"][0]["PRIORITY"], "3")
        self.assertIn("history", safe["events"][0]["diagnostic"]["categories"])

    def test_socket_summaries_do_not_retain_origin_or_process(self):
        established = "ESTAB 0 0 192.0.2.1:8080 198.51.100.99:443 users:((private-name))\n"
        safe = collector.socket_projection(established)
        self.assertEqual(safe, {"states": {"ESTAB": 1}})
        listening = "LISTEN 0 128 [::]:8080 [::]:* users:((private-name))\n"
        self.assertEqual(collector.socket_projection(listening, True)["listeners"][0]["local"],
                         {"address": "::", "port": 8080})

    def test_network_omits_mac_interface_names_and_arbitrary_routes(self):
        addresses = [{"ifindex": 2, "ifname": "private-user-interface", "address": "aa:bb:cc:dd:ee:ff",
                      "addr_info": [{"local": "192.0.2.1", "prefixlen": 24, "label": "private-label"}]}]
        safe = collector.network_projection(json.dumps(addresses))
        self.assertEqual(safe[0]["addresses"], [{"local": "192.0.2.1", "prefixlen": 24}])
        self.assertNotIn("private", json.dumps(safe))
        routes = collector.network_projection(json.dumps([{"dst": "private-host", "dev": "private-dev",
                                                            "gateway": "192.0.2.254"}]), True)
        self.assertEqual(routes, [{"gateway": "192.0.2.254"}])


class ExecutionTests(unittest.TestCase):
    def test_command_timeout_kills_child_and_drops_partial_sensitive_data(self):
        started = time.monotonic()
        metadata, _, _ = collector.run_command(
            [sys.executable, "-c", "import time; print('private-password', flush=True); time.sleep(30)"], timeout=0.15)
        self.assertTrue(metadata["timedOut"])
        self.assertLess(time.monotonic() - started, 2)
        with patch.object(collector, "run_command", return_value=(metadata, "private-password", "private-stderr")):
            safe = collector.capture(["homeproxy"], lambda raw: raw)
        self.assertNotIn("private", json.dumps(safe))
        self.assertTrue(safe["dataUnavailable"])

    def test_output_is_bounded_and_marked_incomplete(self):
        metadata, stdout, _ = collector.run_command([sys.executable, "-c", "print('x' * 100000)"], max_bytes=1024)
        self.assertEqual(metadata["returncode"], 0)
        self.assertTrue(metadata["truncated"])
        self.assertEqual(len(stdout), 1024)

    def test_missing_executable_only_records_errno(self):
        metadata, stdout, stderr = collector.run_command(["/no-such/private-path"])
        self.assertTrue(metadata["unavailable"])
        self.assertEqual(metadata["errno"], 2)
        self.assertEqual((stdout, stderr), ("", ""))
        self.assertNotIn("private", json.dumps(metadata))

    def test_all_collector_commands_are_read_only_and_bounded(self):
        commands = []
        def fake_run(argv, timeout=collector.COMMAND_TIMEOUT, max_bytes=collector.COMMAND_BYTES):
            commands.append(argv)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 5)
            self.assertLessEqual(max_bytes, 1024 * 1024)
            if argv[:1] == ["homeproxy"] and "--json" in argv:
                data = {"running": True, "settings": {}, "stats": {}} if argv[-1] == "status" else {"health": "ok", "state": "running"}
                raw = json.dumps({"ok": True, "result": data})
            elif argv[:1] == ["ip"]:
                raw = "[]"
            else:
                raw = ""
            return {"returncode": 0, "timedOut": False, "truncated": False}, raw, ""
        args = argparse.Namespace(samples=3, interval=0, socket="/private-user/control.sock")
        with patch.object(collector, "run_command", side_effect=fake_run):
            report = collector.collect(args)
        self.assertEqual(len(report["samples"]), 3)
        self.assertNotIn("private-user", json.dumps(report))
        self.assertEqual([cmd[-1] for cmd in commands if cmd[0] == "homeproxy" and "--json" in cmd],
                         ["status", "doctor"] * 3)
        for cmd in commands:
            executable = cmd[0]
            self.assertIn(executable, {"homeproxy", "homeproxyd", "dpkg-query", "systemctl", "ss", "ip", "journalctl"})
            if executable == "homeproxy":
                self.assertTrue(cmd == ["homeproxy", "--version"] or cmd[-1] in ("status", "doctor"))
            elif executable == "homeproxyd":
                self.assertEqual(cmd, ["homeproxyd", "--version"])
            elif executable == "systemctl":
                self.assertEqual(cmd[1:3], ["show", "homeproxy.service"])
            elif executable == "ip":
                self.assertEqual(cmd[-1], "show")
            elif executable == "journalctl":
                self.assertIn("--lines=200", cmd)
                self.assertIn("--since=-2days", cmd)
            self.assertNotIn("sudo", cmd)

    def test_sampling_validation(self):
        for args in (["--samples", "0"], ["--samples", "11"], ["--interval", "nan"],
                     ["--interval", "inf"], ["--interval", "-1"], ["--interval", "31"]):
            with self.subTest(args=args), patch("sys.stderr"), self.assertRaises(SystemExit):
                collector.arguments(["--output-dir", "/tmp/example", *args])


class OutputTests(unittest.TestCase):
    def test_private_modes_and_refusal_to_clobber(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            directory, descriptor = collector.prepare_output(str(output))
            os.write(descriptor, b"first-report")
            os.close(descriptor)
            os.close(directory)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "incident.json").stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                collector.prepare_output(str(output))
            self.assertEqual((output / "incident.json").read_text(), "first-report")

    def test_output_directory_and_parent_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "target"
            target.mkdir()
            link = base / "link"
            link.symlink_to(target, target_is_directory=True)
            for path in (link, link / "new-report"):
                with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                    collector.prepare_output(str(path))
            self.assertFalse((target / "incident.json").exists())
            self.assertFalse((target / "new-report").exists())

    def test_existing_empty_directory_permissions_are_not_changed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "existing"
            output.mkdir(mode=0o755)
            original = stat.S_IMODE(output.stat().st_mode)
            with self.assertRaises(ValueError):
                collector.prepare_output(str(output))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), original)
            self.assertEqual(list(output.iterdir()), [])

    def test_existing_output_file_symlink_does_not_touch_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "report"
            output.mkdir()
            target = base / "private-target"
            target.write_text("must-not-change")
            (output / "incident.json").symlink_to(target)
            with self.assertRaises(ValueError):
                collector.prepare_output(str(output))
            self.assertEqual(target.read_text(), "must-not-change")

    def test_main_writes_only_sanitized_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            with patch.object(collector, "collect", return_value={"samples": [], "safe": True}), patch("sys.stdout"):
                self.assertEqual(collector.main(["--output-dir", str(output)]), 0)
            self.assertEqual(json.loads((output / "incident.json").read_text()), {"samples": [], "safe": True})


if __name__ == "__main__":
    unittest.main()
