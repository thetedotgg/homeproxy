import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");
const body = source.split("async function runBusy(action: () => Promise<void>): Promise<void> {")[1].split("\nasync function copyText")[0].replace(/}\s*$/, "").replaceAll("invoke<AppSnapshot>", "invoke");
function harness(render, invoke = () => new Promise(() => {})) {
  return new Function("render", "invoke", `let busy = false, activitySnapshotGeneration = 0; const showNotice = () => {}; const translateBackendMessage = v => v; const locale = 'en'; const syncFromSnapshot = () => {}; const listenerBindFailureMessage = () => ''; return { run: async action => { ${body} }, busy: () => busy };`)(render, invoke);
}
test("render failure releases busy and reports the failure", async () => {
  let renders = 0;
  const ui = harness(() => { if (++renders === 1) throw Error("render failed"); });
  await ui.run(async () => {}).catch(() => {});
  assert.equal(ui.busy(), false);
});
test("failed action releases busy without waiting for a recovery IPC", async () => {
  const ui = harness(() => {});
  const result = await Promise.race([ui.run(async () => { throw Error("save failed"); }).then(() => "done"), new Promise(resolve => setTimeout(() => resolve("stuck"), 100))]);
  assert.equal(result, "done");
  assert.equal(ui.busy(), false);
});
test("busy actions cannot overlap and remain locked until the mutation settles", async () => {
  const ui = harness(() => {});
  let settle;
  const first = ui.run(() => new Promise(resolve => { settle = resolve; }));
  let secondRan = false;
  await ui.run(async () => { secondRan = true; });
  assert.equal(secondRan, false);
  assert.equal(ui.busy(), true);
  settle(); await first;
  assert.equal(ui.busy(), false);
});
