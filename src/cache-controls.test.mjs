import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { savingsStatus } from "../target/ui-tests/cache-controls.js";

test("savings status distinguishes independent controls and real HTTPS prerequisites", () => {
  const saved = { cacheEnabled: false, compressionPreset: "balanced", responseBufferLimitMib: 8,
    responseBufferBudgetMib: 64, httpsMode: "tunnel", httpsClientTrustAcknowledged: false, httpsInspectHosts: [] };
  assert.deepEqual(savingsStatus(saved, true), ["savingsCacheOff", "savingsImagesOn", "savingsHttpOnly"]);
  assert.deepEqual(savingsStatus(saved, false), ["savingsStopped"]);
  assert.deepEqual(savingsStatus({ ...saved, cacheEnabled: true, compressionPreset: "off" }, true),
    ["savingsCacheOn", "savingsImagesOff", "savingsHttpOnly"]);
  for (const field of ["responseBufferLimitMib", "responseBufferBudgetMib"]) {
    assert.equal(savingsStatus({ ...saved, [field]: 0 }, true)[1], "savingsImagesBufferOff");
  }
  const inspect = { ...saved, httpsMode: "inspect", httpsClientTrustAcknowledged: true, httpsInspectHosts: ["example.org"] };
  assert.equal(savingsStatus(inspect, true)[2], "savingsInspectSelected");
  assert.equal(savingsStatus({ ...inspect, httpsClientTrustAcknowledged: false }, true)[2], "savingsHttpOnly");
  assert.equal(savingsStatus({ ...inspect, httpsInspectHosts: [] }, true)[2], "savingsHttpOnly");
  const all = { ...inspect, httpsInspectionScope: "allSupportedHosts", httpsInspectHosts: [] };
  assert.equal(savingsStatus(all, true)[2], "savingsInspectAll");
  assert.equal(savingsStatus({ ...all, httpsClientTrustAcknowledged: false }, true)[2], "savingsHttpOnly");
  assert.equal(savingsStatus({ ...all, httpsMode: "tunnel" }, true)[2], "savingsHttpOnly");
});
import { cacheUsageState, parseCacheInteger, validateCacheInputs, validateCacheValues } from "../target/ui-tests/cache-controls.js";
import { createTranslator, translateServiceError } from "../target/ui-tests/i18n.js";

const defaults = { cacheLimitGib: "8", cacheMaxObjectMib: "1024", responseBufferLimitMib: "8", responseBufferBudgetMib: "64" };
const check = (patch) => validateCacheInputs({ ...defaults, ...patch });

test("defaults are valid and parse to the exact numbers", () => {
  const result = check({});
  assert.equal(result.ok, true);
  assert.deepEqual(result.values, { cacheLimitGib: 8, cacheMaxObjectMib: 1024, responseBufferLimitMib: 8, responseBufferBudgetMib: 64 });
});

test("parser accepts only whole numbers inside bounds", () => {
  assert.equal(parseCacheInteger("1", 1, 1024), 1);
  assert.equal(parseCacheInteger("1024", 1, 1024), 1024);
  assert.equal(parseCacheInteger(" 7 ", 0, 8), 7);
  for (const bad of ["", " ", "0", "1025", "-1", "1.5", "1,5", "1e2", "0x10", "+3", "abc", "NaN", "Infinity", "9999999999"]) {
    assert.equal(parseCacheInteger(bad, 1, 1024), null, JSON.stringify(bad));
  }
  assert.equal(parseCacheInteger("0", 0, 8), 0);
  assert.equal(parseCacheInteger("9", 0, 8), null);
});

test("each field enforces its own min and max", () => {
  for (const [field, good, bad] of [
    ["cacheLimitGib", ["1", "1024"], ["0", "1025", ""]],
    ["cacheMaxObjectMib", ["1", "1024"], ["0", "1025", "2.5"]],
    ["responseBufferLimitMib", ["0", "8"], ["9", "-1"]],
    ["responseBufferBudgetMib", ["8", "512"], ["513", "-1"]],
  ]) {
    for (const value of good) assert.equal(check({ [field]: value }).ok, true, `${field}=${value}`);
    for (const value of bad) {
      const result = check({ [field]: value });
      assert.equal(result.ok, false, `${field}=${value}`);
      assert.equal(result.values, null);
      assert.deepEqual(result.errors[0], { kind: "range", field });
    }
  }
});

test("per-response limit cannot exceed the total budget; zero budget needs zero limit", () => {
  assert.deepEqual(check({ responseBufferLimitMib: "8", responseBufferBudgetMib: "4" }).errors, [{ kind: "limitAboveBudget" }]);
  assert.equal(check({ responseBufferLimitMib: "4", responseBufferBudgetMib: "4" }).ok, true);
  assert.deepEqual(check({ responseBufferLimitMib: "1", responseBufferBudgetMib: "0" }).errors, [{ kind: "budgetZeroNeedsLimitZero" }]);
  assert.equal(check({ responseBufferLimitMib: "0", responseBufferBudgetMib: "0" }).ok, true);
});

test("zero per-response limit with a positive budget is allowed", () => {
  const result = check({ responseBufferLimitMib: "0", responseBufferBudgetMib: "64" });
  assert.equal(result.ok, true);
  assert.equal(result.values.responseBufferLimitMib, 0);
});

test("validateCacheValues applies the same rules to numeric drafts", () => {
  assert.equal(validateCacheValues({ cacheLimitGib: 8, cacheMaxObjectMib: 1, responseBufferLimitMib: 0, responseBufferBudgetMib: 0 }).ok, true);
  assert.equal(validateCacheValues({ cacheLimitGib: 8.5, cacheMaxObjectMib: 1, responseBufferLimitMib: 0, responseBufferBudgetMib: 0 }).ok, false);
});

test("usage state never presents missing, errored or stale data as current", () => {
  assert.equal(cacheUsageState({ usedBytes: 0, entryCount: 0, pendingMaintenance: false, measured: false, usageIsCurrent: false }), "unavailable");
  assert.equal(cacheUsageState(undefined), "unavailable");
  assert.equal(cacheUsageState({ usedBytes: 0, entryCount: 0, pendingMaintenance: false }), "current");
  assert.equal(cacheUsageState({ usedBytes: 5, entryCount: 1, pendingMaintenance: false, usageIsCurrent: true, measurementError: null }), "current");
  assert.equal(cacheUsageState({ usedBytes: 5, entryCount: 1, pendingMaintenance: false, usageIsCurrent: false, measurementError: null }), "stale");
  assert.equal(cacheUsageState({ usedBytes: 0, entryCount: 0, pendingMaintenance: false, usageIsCurrent: true, measurementError: "io" }), "error");
});

test("CZ and EN carry every cache control string with the same placeholders", () => {
  const source = await_i18n();
  const cs = createTranslator("cs");
  const en = createTranslator("en");
  for (const key of source) {
    const czText = cs(key, { min: "MIN", max: "MAX" });
    const enText = en(key, { min: "MIN", max: "MAX" });
    assert.ok(czText && enText, key);
    assert.notEqual(czText, enText, key);
    assert.equal(czText.includes("MIN"), enText.includes("MIN"), key);
  }
});
test("server-side cache validation errors are localized through the Linux IPC envelope", () => {
  const detail = "Buffer odpovědi nesmí překročit sdílený rozpočet bufferů.";
  assert.match(translateServiceError(`HOMEPROXY_SERVICE:invalid_config:${detail}`, "cs", "linux"), /Buffer odpovědi/);
  assert.match(translateServiceError(`HOMEPROXY_SERVICE:invalid_config:${detail}`, "en", "linux"), /Response buffer must not exceed/);
});
function await_i18n() {
  return [
    "cacheDiskLimitLabel", "cacheMaxObjectLabel", "bufferLimitLabel", "bufferBudgetLabel", "cacheBoundaryHelp", "cacheRestartNote",
    "cacheUsageStale", "cacheUsageError", "cacheUsageUnavailable", "cacheMaintenancePending",
    "cacheErrorDisk", "cacheErrorMaxObject", "cacheErrorBufferLimit", "cacheErrorBufferBudget", "cacheErrorLimitAboveBudget", "cacheErrorBudgetZero",
  ];
}

const main = await readFile(new URL("./main.ts", import.meta.url), "utf8");

// Runs the real applyDirtyDraft source with fake inputs to prove invalid cache text never reaches apply_settings.
function applyHarness(rawInputs) {
  const body = main.split("async function applyDirtyDraft(): Promise<boolean> {")[1].split("\n}\n")[0].replaceAll("invoke<AppSnapshot>", "invoke");
  const calls = [];
  const payloads = [];
  const notices = [];
  const factory = new Function("validateCacheInputs", "rawInputs", "calls", "notices", "payloads", `
    let draft = { cacheLimitGib: 8 }, dirty = true, draftRevision = "r1", snapshot = null;
    const hasInvalidDeviceLimits = () => false;
    const validateServicePorts = () => null;
    const servicePortErrorMessage = () => "port";
    const t = key => key;
    const showNotice = message => notices.push(message);
    const syncFromSnapshot = () => {};
    const invoke = async (name,args) => { calls.push(name); payloads.push(args); return {}; };
    const currentCacheValidation = () => validateCacheInputs(rawInputs);
    const cacheErrorText = validation => "cache-error:" + validation.errors[0].kind;
    const currentOfflineValidation = () => ({error:null,values:{}});
    const offlineErrorText = () => "offline-error";
    const hasInvalidPolicy = () => false;
    const applyPolicyDraft = () => {};
    const hasInvalidRouting = () => false;
    const applyRoutingDraft = () => {};
    return async () => { ${body} };
  `);
  return { run: factory(validateCacheInputs, rawInputs, calls, notices, payloads), calls, notices, payloads };
}

test("applyDirtyDraft blocks saving invalid, empty, decimal and cross-field cache input", async () => {
  for (const patch of [{ cacheLimitGib: "" }, { cacheLimitGib: "2.5" }, { cacheMaxObjectMib: "2000" }, { responseBufferLimitMib: "9" }, { responseBufferLimitMib: "8", responseBufferBudgetMib: "4" }]) {
    const harness = applyHarness({ ...defaults, ...patch });
    assert.equal(await harness.run(), false, JSON.stringify(patch));
    assert.deepEqual(harness.calls, [], JSON.stringify(patch));
    assert.equal(harness.notices.length, 1);
  }
});

test("applyDirtyDraft saves valid cache input through apply_settings", async () => {
  const harness = applyHarness({ ...defaults, cacheLimitGib: "20", cacheMaxObjectMib: "32" });
  assert.equal(await harness.run(), true);
  assert.deepEqual(harness.calls, ["apply_settings"]);
  assert.equal(harness.payloads[0].settings.cacheLimitGib, 20);
  assert.equal(harness.payloads[0].settings.cacheMaxObjectMib, 32);
});

test("guided prepare explains invalid cache input and never reaches the daemon", async () => {
  const body = main.split("async function prepareGuidedSetup(): Promise<void> {")[1].split("\n}\n")[0]
    .replaceAll("invoke<AppSnapshot>", "invoke").replace("(ip): ip is string", "(ip)");
  const notices = [], calls = [];
  const run = new Function("notices", "calls", `
    const snapshot={},draft={},busy=false,guideSelectedIp="192.168.1.20";
    const currentCacheValidation=()=>({ok:false});
    const showNotice=m=>notices.push(m),cacheErrorText=()=>"invalid-cache";
    const invoke=async()=>calls.push("invoke");
    return async()=>{${body}};
  `)(notices, calls);
  await run();
  assert.deepEqual(notices,["invalid-cache"]);
  assert.deepEqual(calls,[]);
});

test("dirty draft survives a periodic snapshot without resetting visible cache input", () => {
  const body=main.split("function syncFromSnapshot(next: AppSnapshot, forceDraft = false): void {")[1].split("\n}\n")[0];
  const run=new Function(`let dirty=true,draft={cacheLimitGib:20},snapshot=null,cacheInputsNeedReset=false,draftRevision="old";
    const syncGuideSelection=()=>{},render=()=>{},inspectionSupported=()=>false;
    return (next,forceDraft=false)=>{${body};return {draft,cacheInputsNeedReset,draftRevision,dirty};};`)();
  assert.deepEqual(run({settings:{cacheLimitGib:8},revision:"new"}),{
    draft:{cacheLimitGib:20},cacheInputsNeedReset:false,draftRevision:"old",dirty:true,
  });
});

test("the save button is gated on cache validity", () => {
  assert.match(main, /saveButton\.disabled = !dirty \|\| busy \|\| Boolean\(portError\) \|\| cacheInvalid/);
  assert.match(main, /saveButton\.disabled = busy \|\| !currentCacheValidation\(\)\.ok/);
});
