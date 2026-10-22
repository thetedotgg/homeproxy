import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createTranslator } from "../target/ui-tests/i18n.js";
const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");
const body = source.split("function renderConnectionRejections(): void {")[1].split("\nfunction renderActivity")[0].replace(/}\s*$/, "");
const render = new Function("snapshot", "byId", "t", "formatCount", "formatActivityTime", "setTextIfChanged", body);
function display(stats, locale) {
  const nodes = new Map();
  const byId = id => { if (!nodes.has(id)) nodes.set(id, {hidden:false,textContent:""}); return nodes.get(id); };
  render({stats}, byId, createTranslator(locale), String, () => "12:00:01", (node,text) => { node.textContent=text; });
  return nodes;
}
test("capacity diagnostics tolerate older snapshots and hide zero history", () => {
  for (const stats of [{}, {rejectedConnections:0,latestConnectionRejection:null}]) assert.equal(display(stats,"en").get("connection-rejections").hidden,true);
});
test("capacity diagnostics use the recorded concurrent limit and forget cleared peer metadata", () => {
  for (const locale of ["cs","en"]) {
    const stats = {rejectedConnections:7,latestConnectionRejection:{peerIp:"192.168.1.9",listenerIp:"192.168.1.2",unixMs:1,reason:"peer-limit",limit:17}};
    const nodes=display(stats,locale);
    assert.match(nodes.get("connection-rejection-total").textContent,/7/);
    assert.match(nodes.get("connection-rejection-total").textContent,/histor/);
    assert.match(nodes.get("connection-rejection-latest").textContent,/17/);
    assert.match(nodes.get("connection-rejection-latest").textContent,/12:00:01/);
    stats.latestConnectionRejection=null;
    const cleared=display(stats,locale);
    assert.equal(cleared.get("connection-rejections").hidden,false);
    assert.match(cleared.get("connection-rejection-total").textContent,/7/);
    assert.equal(cleared.get("connection-rejection-latest").textContent,"");
    assert.equal(cleared.get("connection-rejection-latest").hidden,true);
  }
});

test("clearing activity discards pending snapshots and errors but accepts the next fresh snapshot", async () => {
  const refreshBody = source.split("async function refresh(): Promise<void> {")[1].split("\n}\n")[0].replace("invoke<AppSnapshot>", "invoke");
  const clearBody = source.split('byId("activity-clear").addEventListener("click", () => void runBusy(async () => {')[1].split("\n}));")[0];
  for (const rejectOld of [false, true]) {
    const state = {stats:{rejectedConnections:7,latestConnectionRejection:{peerIp:"192.168.1.9"},activity:[{id:1}]}};
    let release;
    let fail;
    let pending = new Promise((resolve, reject) => { release = resolve; fail = reject; });
    const notices = [];
    const harness = new Function("initial", "load", "notices", `
      let snapshot = initial, displayedActivity = initial.stats.activity;
      let busy = false, refreshing = false, activitySnapshotGeneration = 0;
      const loadSnapshotWhenReady = load;
      const refreshTlsStatus = async () => {};
      const invoke = async () => {};
      const syncFromSnapshot = next => { snapshot = next; };
      const renderConnectionRejections = () => {};
      const renderActivity = () => {};
      const showNotice = message => notices.push(message);
      const translateBackendMessage = message => message;
      const locale = "en";
      return {refresh: async () => {${refreshBody}}, clear: async () => {${clearBody}}, read: () => snapshot};
    `)(state, () => pending, notices);
    const oldSnapshot = structuredClone(state);
    const oldRefresh = harness.refresh();
    await harness.clear();
    if (rejectOld) fail(new Error("old snapshot failed"));
    else release(oldSnapshot);
    await oldRefresh;
    assert.equal(harness.read().stats.latestConnectionRejection, null);
    assert.deepEqual(harness.read().stats.activity, []);
    assert.equal(harness.read().stats.rejectedConnections, 7);
    assert.deepEqual(notices, []);
    pending = Promise.resolve({stats:{rejectedConnections:8,latestConnectionRejection:{peerIp:"192.168.1.10"},activity:[]}});
    await harness.refresh();
    assert.equal(harness.read().stats.latestConnectionRejection.peerIp, "192.168.1.10");
    assert.equal(harness.read().stats.rejectedConnections, 8);
  }
});
