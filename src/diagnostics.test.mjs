import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import { createTranslator } from "../target/ui-tests/i18n.js";

// Keep the root-owned test manifest untouched; transpile this pure module in memory.
const source = await readFile(new URL("./diagnostics.ts", import.meta.url), "utf8");
const emitted = ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022}}).outputText;
const { diagnosticStates, diagnosticStateKey, parseDiagnosticsStatus, parseDiagnosticExport, diagnosticExportErrorKey } = await import(`data:text/javascript;base64,${Buffer.from(emitted).toString("base64")}`);
const status = {enabled: true, state: "healthy", recoveryCount: 4, lastIncidentAt: 1_790_000_000_123, storageAvailable: true};

test("all contracted local health states have distinct matching Czech and English labels", () => {
  const cs = createTranslator("cs"), en = createTranslator("en");
  for (const state of diagnosticStates) {
    const key = diagnosticStateKey(state);
    assert.ok(cs(key).trim()); assert.ok(en(key).trim());
    assert.notEqual(cs(key), en(key));
    assert.equal(parseDiagnosticsStatus({...status, state}).state, state);
  }
  assert.equal(diagnosticStates.length, 9);
  assert.match(cs("diagnosticsBoundary"), /Neověřuje.*internetu/);
  assert.match(en("diagnosticsBoundary"), /does not verify internet/);
  assert.match(cs("diagnosticsPrivacy"), /IP.*čítače/);
  assert.match(en("diagnosticsPrivacy"), /IP.*counters/);
  assert.match(cs("diagnosticsPartial"), /pouze částečný/);
  assert.match(en("diagnosticsPartial"), /Only a partial/);
  for (const key of ["diagnosticsLoading", "diagnosticsExporting", "diagnosticsRecoveryPending", "diagnosticsRecoveryUnavailable", "diagnosticsSaved", "diagnosticsStorageUnavailable", "diagnosticsExportFailed", "diagnosticsDownloadsUnavailable", "diagnosticsTooLarge"]) {
    assert.ok(cs(key)); assert.ok(en(key)); assert.notEqual(cs(key), en(key));
  }
});

test("status parser rejects malformed or future health responses instead of claiming healthy", () => {
  assert.deepEqual(parseDiagnosticsStatus(status), status);
  assert.deepEqual(parseDiagnosticsStatus({...status, enabled: false, state: "disabled", lastIncidentAt: null, storageAvailable: false}), {...status, enabled: false, state: "disabled", lastIncidentAt: null, storageAvailable: false});
  for (const invalid of [null, {}, {...status, state: "internetHealthy"}, {...status, recoveryCount: -1}, {...status, recoveryCount: 1.5}, {...status, recoveryCount: Number.MAX_SAFE_INTEGER + 1}, {...status, lastIncidentAt: "today"}, {...status, lastIncidentAt: 8_640_000_000_000_001}, {...status, storageAvailable: "yes"}, {...status, enabled: 1}]) assert.equal(parseDiagnosticsStatus(invalid), null);
  assert.equal(diagnosticStateKey("new-state"), "diagnosticsUnavailable");
});

test("native export results require an actual path, fixed generated filename, and explicit partial flag", () => {
  const saved = {path: "/home/test/Downloads/HomeProxy-diagnostika-123-1-0-0.json", fileName: "HomeProxy-diagnostika-123-1-0-0.json", partial: false};
  assert.deepEqual(parseDiagnosticExport(saved), saved);
  assert.equal(parseDiagnosticExport({...saved, partial: true}).partial, true);
  for (const invalid of [null, {}, {...saved, path: ""}, {...saved, fileName: "../report.json"}, {...saved, partial: undefined}]) assert.equal(parseDiagnosticExport(invalid), null);
});

test("export failures never reveal raw credentials, private URLs or native error text", () => {
  const failure = "secret password https://user:key@private.example/page?token=123 PRIVATE KEY";
  for (const error of [failure, new Error(failure), {message: failure}, "HOMEPROXY_DIAGNOSTICS:write_failed"]) {
    const key = diagnosticExportErrorKey(error);
    assert.equal(key, "diagnosticsExportFailed");
    for (const locale of ["cs", "en"]) assert.doesNotMatch(createTranslator(locale)(key), /secret|private\.example|token=123|PRIVATE KEY/);
  }
  assert.equal(diagnosticExportErrorKey("HOMEPROXY_DIAGNOSTICS:downloads_unavailable"), "diagnosticsDownloadsUnavailable");
  assert.equal(diagnosticExportErrorKey("HOMEPROXY_DIAGNOSTICS:report_too_large"), "diagnosticsTooLarge");
});

test("native commands are registered on both platforms and watchdog is independent of embedded maintenance", async () => {
  const [linux, embedded] = await Promise.all(["linux", "embedded"].map(name => readFile(new URL(`../src-tauri/src/${name}.rs`, import.meta.url), "utf8")));
  for (const backend of [linux, embedded]) {
    const registration = backend.split(".invoke_handler(tauri::generate_handler![")[1].split("])")[0];
    for (const command of ["get_diagnostics_status", "export_diagnostics"]) assert.ok(registration.includes(command));
  }
  assert.match(linux, /request\(Command::DiagnosticsStatus\)/);
  assert.match(linux, /request\(Command::ExportDiagnostics\)/);
  assert.match(embedded, /spawn\(async move \{\s*watchdog_engine\.run_watchdog\(\)\.await/);
  assert.match(embedded, /startup_engine\.run_periodic_maintenance\(\)\.await/);
});

test("export and local-health polling have independent UI lifetimes; recovery uses ordinary revision save", async () => {
  const main = await readFile(new URL("./main.ts", import.meta.url), "utf8");
  const polling = main.split("async function refreshDiagnostics(): Promise<void> {")[1].split('\nbyId("export-diagnostics")')[0];
  assert.match(polling, /invoke<unknown>\("get_diagnostics_status"\)/);
  assert.doesNotMatch(polling, /get_snapshot|if \(busy/);
  const exportHandler = main.split('byId("export-diagnostics").addEventListener')[1].split('byId("diagnostics-export-path")')[0];
  assert.match(exportHandler, /invoke<unknown>\("export_diagnostics"\)/);
  assert.doesNotMatch(exportHandler, /runBusy|new Blob|URL\.createObjectURL|!snapshot/);
  assert.match(main, /exportButton\.disabled = diagnosticsExporting;/);
  assert.match(main, /draft\.automaticRecovery \?\?= true/);
  assert.match(main, /invoke<AppSnapshot>\("apply_settings", \{ settings: draft, expectedRevision: draftRevision \}\)/);
  assert.match(main, /if \(!snapshot && !startupErrorShown\)/);
});
