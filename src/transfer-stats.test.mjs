import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createTranslator } from "../target/ui-tests/i18n.js";

const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");
const controls = source.split("function closeTransferReset(): void {")[1]
  .split('byId("activity-pause")')[0];
const resetCode = (`function closeTransferReset(): void {${controls}`)
  .replaceAll(": void", "")
  .replaceAll("byId<HTMLButtonElement>", "byId")
  .replaceAll("invoke<Stats>", "invoke");
const busyCode = source.split("async function runBusy(action: () => Promise<void>): Promise<void> {")[1]
  .split("\nasync function copyText")[0].replace(/}\s*$/, "");
const refreshCode = source.split("async function refresh(): Promise<void> {")[1]
  .split("\n}\n")[0].replaceAll("invoke<AppSnapshot>", "invoke");

function harness(invoke, locale = "en") {
  const nodes = new Map();
  let focused = null;
  const byId = (id) => {
    if (!nodes.has(id)) nodes.set(id, {
      hidden: id === "traffic-reset-confirmation", disabled: false, textContent: "",
      attrs: {}, listeners: {}, dataset: {},
      setAttribute(key, value) { this.attrs[key] = value; },
      addEventListener(kind, handler) { this.listeners[kind] = handler; },
      focus() { focused = id; },
    });
    return nodes.get(id);
  };
  const notices = [];
  const ui = new Function("byId", "invoke", "t", "notices", `
    let snapshot = {stats:{uploadBytes:700,downloadBytes:900},settings:{proxyPort:17891}};
    let busy = false, refreshing = false, snapshotUnavailable = false;
    let activitySnapshotGeneration = 0, actionPromise;
    let startupErrorShown = true;
    const locale = "${locale}";
    const setTextIfChanged = (node, text) => {node.textContent = text;};
    const translateBackendMessage = text => text;
    const showNotice = (text, kind) => notices.push({text,kind});
    const render = () => renderTransferReset();
    const renderDiagnostics = () => {};
    const refreshTlsStatus = async () => {};
    const loadSnapshotWhenReady = load => load();
    const syncFromSnapshot = next => {snapshot = next;};
    function runBusy(action) {
      actionPromise = (async () => {${busyCode}})();
      return actionPromise;
    }
    ${resetCode}
    render();
    return {
      snapshot: () => snapshot,
      settle: () => actionPromise,
      refresh: async () => {${refreshCode}},
      unavailable: value => {snapshotUnavailable=value;render();},
    };
  `)(byId, invoke, createTranslator(locale), notices);
  return {
    ...ui, notices, node: byId, focused: () => focused,
    click(id) { const node = byId(id); if (!node.disabled) node.listeners.click(); },
    escape() { byId("traffic-reset-confirmation").listeners.keydown({key:"Escape",preventDefault(){}}); },
  };
}

test("reset confirmation can be cancelled without calling the backend in both locales", () => {
  for (const locale of ["cs", "en"]) {
    let calls = 0;
    const ui = harness(() => { calls++; }, locale);
    ui.click("traffic-reset");
    assert.equal(ui.node("traffic-reset-confirmation").hidden, false);
    assert.equal(ui.focused(), "traffic-reset-cancel");
    ui.escape();
    assert.equal(ui.node("traffic-reset-confirmation").hidden, true);
    assert.equal(ui.focused(), "traffic-reset");
    ui.click("traffic-reset");
    ui.click("traffic-reset-cancel");
    assert.equal(calls, 0);
    assert.deepEqual(ui.snapshot().stats, {uploadBytes:700,downloadBytes:900});
    ui.unavailable(true);
    assert.equal(ui.node("traffic-reset").disabled, true);
    assert.equal(ui.node("traffic-reset-confirm").disabled, true);
  }
});

test("reset waits for the real result, rejects double clicks and preserves snapshot settings", async () => {
  let resolve, calls = 0;
  const ui = harness(command => {
    assert.equal(command, "reset_transfer_stats");
    calls++;
    return new Promise(done => { resolve = done; });
  });
  const settings = ui.snapshot().settings;
  ui.click("traffic-reset");
  ui.click("traffic-reset-confirm");
  ui.click("traffic-reset-confirm");
  assert.equal(calls, 1);
  assert.equal(ui.node("traffic-reset").disabled, true);
  assert.equal(ui.node("traffic-reset-cancel").disabled, true);
  assert.equal(ui.snapshot().stats.downloadBytes, 900);
  const actual = {uploadBytes:17,downloadBytes:42,transferStatsResetUnixMs:12345};
  resolve(actual);
  await ui.settle();
  await Promise.resolve();
  assert.deepEqual(ui.snapshot().stats, actual);
  assert.equal(ui.snapshot().settings, settings);
  assert.equal(ui.node("traffic-reset-confirmation").hidden, true);
  assert.equal(ui.node("traffic-reset").disabled, false);
  assert.equal(ui.focused(), "traffic-reset");
  assert.equal(ui.notices.at(-1).kind, "success");
});

test("failed reset keeps displayed totals and permits retry without claiming success", async () => {
  const ui = harness(async () => { throw Error("reset unavailable"); });
  ui.click("traffic-reset");
  ui.click("traffic-reset-confirm");
  await ui.settle();
  await Promise.resolve();
  assert.deepEqual(ui.snapshot().stats, {uploadBytes:700,downloadBytes:900});
  assert.equal(ui.node("traffic-reset-confirmation").hidden, false);
  assert.equal(ui.node("traffic-reset-confirm").disabled, false);
  assert.equal(ui.focused(), "traffic-reset-confirm");
  assert.deepEqual(ui.notices, [{text:"reset unavailable",kind:"error"}]);
  ui.escape();
  assert.equal(ui.node("traffic-reset-confirmation").hidden, true);
  assert.equal(ui.focused(), "traffic-reset");
});

test("pre-reset polling results and errors cannot overwrite reset, and fresh polling resumes", async () => {
  for (const rejectOld of [false, true]) {
    let release, reject;
    let pending = new Promise((resolve, fail) => { release=resolve;reject=fail; });
    const actual = {uploadBytes:0,downloadBytes:0,transferStatsResetUnixMs:12345};
    const ui = harness(command => command === "get_snapshot" ? pending : Promise.resolve(actual));
    const stale = structuredClone(ui.snapshot());
    const refresh = ui.refresh();
    ui.click("traffic-reset");
    ui.click("traffic-reset-confirm");
    await ui.settle();
    if (rejectOld) reject(Error("stale poll unavailable")); else release(stale);
    await refresh;
    assert.deepEqual(ui.snapshot().stats, actual);
    assert.equal(ui.notices.length, 1);
    pending = Promise.resolve({stats:{uploadBytes:5,downloadBytes:8,transferStatsResetUnixMs:12345}});
    await ui.refresh();
    assert.equal(ui.snapshot().stats.downloadBytes, 8);
  }
});
