import assert from "node:assert/strict";
import test from "node:test";
import {parseHostRules, parsePublicEndpoints, showInspectHostEditor, validateOfflineInputs} from "../target/ui-tests/offline-controls.js";

test("host boundaries reject URL, ports, duplicates and broken wildcard labels", () => {
  assert.deepEqual(parseHostRules("Example.org\n*.cdn.example.org"), ["example.org", "*.cdn.example.org"]);
  for (const raw of ["https://example.org", "example.org:443", "example.org\nEXAMPLE.ORG", "*example.org", "-x.example"]) assert.equal(parseHostRules(raw), null);
});
test("public endpoints require explicit exact domains and paths", () => {
  assert.deepEqual(parsePublicEndpoints("example.org/docs/\ncdn.example.org/"), [{host:"example.org",pathPrefix:"/docs/"},{host:"cdn.example.org",pathPrefix:"/"}]);
  for (const raw of ["https://example.org/", "*.example.org/", "example.org", "example.org/a?token=x", "example.org/a#x", "example.org/a\\b"]) assert.equal(parsePublicEndpoints(raw), null);
});
test("inspection cannot be enabled without domains and declared client trust", () => {
  const raw = {inspectHosts:"example.org",bypassHosts:"",endpoints:"",staleHours:"168"};
  assert.equal(validateOfflineInputs(raw,"inspect",false).error,"trust");
  assert.equal(validateOfflineInputs({...raw,inspectHosts:""},"inspect",true).error,"trust");
  assert.equal(validateOfflineInputs(raw,"inspect",true).error,null);
  assert.equal(validateOfflineInputs({...raw,inspectHosts:""},"tunnel",false).error,null);
  for (const staleHours of ["", "-1", "1.5", "8761", "1e2"]) assert.equal(validateOfflineInputs({...raw,staleHours},"tunnel",false).error,"staleHours");
});
test("all-supported scope needs client trust and preserves validated selected-host rules", () => {
  const raw = {inspectHosts:"",bypassHosts:"*.private.example",endpoints:"",staleHours:"168"};
  assert.equal(validateOfflineInputs(raw,"inspect",true,"allSupportedHosts").error,null);
  assert.equal(validateOfflineInputs(raw,"inspect",false,"allSupportedHosts").error,"trust");
  assert.equal(validateOfflineInputs(raw,"inspect",true,"selectedHosts").error,"trust");
  assert.equal(validateOfflineInputs({...raw,inspectHosts:"*"},"inspect",true,"allSupportedHosts").error,"hosts");
  assert.deepEqual(validateOfflineInputs({...raw,inspectHosts:"example.org"},"inspect",true,"allSupportedHosts").values.httpsInspectHosts,["example.org"]);
});
test("invalid pending domain rules remain editable after switching to all-supported scope", () => {
  const raw = {inspectHosts:"https://unfinished.example",bypassHosts:"",endpoints:"",staleHours:"168"};
  assert.equal(validateOfflineInputs(raw,"inspect",true,"allSupportedHosts").error,"hosts");
  assert.equal(showInspectHostEditor("allSupportedHosts",raw.inspectHosts),true);
  for (const partial of ["", "e", "example", "example.", "example.org"]) {
    assert.equal(showInspectHostEditor("allSupportedHosts",partial,true),true);
  }
  assert.equal(showInspectHostEditor("allSupportedHosts","example.org"),false);
  assert.equal(showInspectHostEditor("selectedHosts","example.org"),true);
});

// Execute the real guide guard: old LAN activity cannot verify a pending HTTPS scope.
test("guide verification is invalidated until the selected HTTPS scope is saved", async () => {
  const {readFile} = await import("node:fs/promises");
  const main = await readFile(new URL("./main.ts", import.meta.url),"utf8");
  const body=main.split("function guideIsVerified(): boolean {")[1].split("\n}\n")[0];
  const verified=new Function("snapshot","draft",`
    const guideSelectedIp="192.168.1.20",guideBaselineSuccessfulRequests=0;
    const selectedLanIps=()=>[guideSelectedIp],guideProxyAddress=()=>"192.168.1.20:3128";
    const connectionVerified=(current,baseline)=>current>baseline;
    ${body}
  `);
  const snapshot={running:true,settings:{lanEnabled:true,httpsInspectionScope:"selectedHosts"},stats:{successfulExternalRequests:1}};
  assert.equal(verified(snapshot,{httpsInspectionScope:"allSupportedHosts"}),false);
  assert.equal(verified(snapshot,{httpsInspectionScope:"selectedHosts"}),true);
  snapshot.settings.httpsInspectionScope="allSupportedHosts";
  assert.equal(verified(snapshot,{httpsInspectionScope:"allSupportedHosts"}),true);
  assert.match(main,/snapshot\.settings\.httpsInspectionScope \?\? "selectedHosts"\) === draft\.httpsInspectionScope/);
});
