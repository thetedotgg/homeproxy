import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { selectedGuideEndpoint } from "../target/ui-tests/setup.js";
const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");
const body = source.split("async function toggleService(): Promise<void> {")[1].split('\nbyId<HTMLButtonElement>("home-guide")')[0].replace(/}\s*$/, "").replaceAll("invoke<AppSnapshot>", "invoke");

test("Stop skips draft validation and never force-resets pending edits", async () => {
  const calls = []; let forced;
  const run = new Function("invoke", "syncFromSnapshot", `let snapshot = {running:true};let busy=false;let draft={proxyPort:0};const runBusy=fn=>fn();const applyDirtyDraft=()=>{throw Error('must not validate Stop');};return async()=>{${body}};`)(async (command, args) => { calls.push({command,args}); return {running:false}; }, (_snapshot, force) => { forced=force; });
  await run();
  assert.deepEqual(calls,[{command:"set_running",args:{running:false}}]);
  assert.notEqual(forced,true);
});

test("guide endpoint respects the chosen active LAN listener without falling back to another", () => {
  assert.equal(selectedGuideEndpoint(["127.0.0.1:3128", "192.168.1.2:3128", "192.168.2.2:3128"], "192.168.2.2"), "192.168.2.2:3128");
  assert.equal(selectedGuideEndpoint(["192.168.1.2:1080", "192.168.2.2:1080"], "192.168.2.2"), "192.168.2.2:1080");
  assert.equal(selectedGuideEndpoint(["192.168.1.2:3128"], "192.168.2.2"), null);
});

test("guided setup removes stale listeners but preserves available explicit selections and legacy fallback", () => {
  const selectionBody = source.split("function selectedLanIps(settings: Settings): string[] {")[1].split("\n}")[0];
  const selectedLanIps = new Function("settings", selectionBody);
  const expression = source.match(/intendedSettings\.listenIps = ([^\n]+);/)[1].replace("(ip): ip is string", "(ip)");
  const select = new Function("intendedSettings", "guideSelectedIp", "selectedLanIps", "availableIps", `return ${expression};`);
  const availableIps = new Set(["192.168.68.51", "192.168.2.2"]);
  assert.deepEqual(select({listenIps:["192.168.68.52","192.168.2.2"],listenIp:"192.168.68.52"}, "192.168.68.51", selectedLanIps, availableIps), ["192.168.2.2","192.168.68.51"]);
  assert.deepEqual(select({listenIps:[],listenIp:"192.168.68.52"}, "192.168.68.51", selectedLanIps, availableIps), ["192.168.68.51"]);
  assert.deepEqual(select({listenIps:[],listenIp:"192.168.2.2"}, "192.168.68.51", selectedLanIps, availableIps), ["192.168.2.2","192.168.68.51"]);
});
