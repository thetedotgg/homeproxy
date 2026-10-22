import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import qrcode from "qrcode-generator";

// device-setup.ts has no imports, so it is transpiled here instead of relying on the test build list.
const source = await readFile(new URL("./device-setup.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const {
  buildPhoneSetupUrl,
  choosePhoneSetupIp,
  formatFingerprint,
  isEligibleSetupIpv4,
  normalizeFingerprint,
  phoneSetupAddresses,
  phoneSetupSignature,
  phoneSetupState,
  qrModulePath,
} = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const HEX = "0123456789abcdef".repeat(4);
const COLON = formatFingerprint(HEX);
const base = {
  running: true,
  lanEnabled: true,
  listenIps: ["192.168.1.20"],
  available: [{ ip: "192.168.1.20", unsafe: false }],
  proxyEndpoints: ["127.0.0.1:3128", "192.168.1.20:3128"],
  proxyPort: 3128,
  caPrepared: true,
  fingerprint: COLON,
  locale: "cs",
  preferredIp: null,
  guidedIp: null,
};
const state = (patch = {}) => phoneSetupState({ ...base, ...patch });

test("only strict RFC 1918 IPv4 addresses are eligible", () => {
  for (const ip of [
    "10.0.0.2", "10.255.255.254", "172.16.0.5", "172.31.255.254", "192.168.1.20",
    // Without a subnet mask .0 and .255 can be ordinary hosts (e.g. in a /23); the backend accepts them too.
    "192.168.1.0", "192.168.1.255", "10.0.0.0", "172.16.0.255",
  ]) assert.equal(isEligibleSetupIpv4(ip), true, ip);
  for (const ip of [
    "", "0.0.0.0", "8.8.8.8", "127.0.0.1", "169.254.1.1", "100.64.0.1", "172.15.0.1", "172.32.0.1", "192.169.0.1",
    "11.0.0.1", "192.167.1.1", "255.255.255.255", "192.168.01.2", "192.168.1", "192.168.1.2.3", "192.168.1.256",
    " 192.168.1.2", "192.168.1.2 ", "::1", "fe80::1", "::ffff:192.168.1.2", "192.168.1.2:80", "192.168.1.2/",
    "a.b.c.d", "0x0a.0.0.1", "１９２.168.1.2", null, undefined, 3232235796,
  ]) assert.equal(isEligibleSetupIpv4(ip), false, JSON.stringify(ip));
});

test("fingerprints normalize to 64 lowercase hex and display in full colon form", () => {
  assert.equal(normalizeFingerprint(COLON), HEX);
  assert.equal(normalizeFingerprint(HEX.toUpperCase()), HEX);
  assert.equal(normalizeFingerprint(COLON.replaceAll(":", " ")), HEX);
  for (const bad of [null, undefined, "", HEX.slice(1), `${HEX}00`, `${HEX.slice(2)}zz`, "-----BEGIN CERTIFICATE-----"]) {
    assert.equal(normalizeFingerprint(bad), null, String(bad));
  }
  assert.equal(COLON.split(":").length, 32);
  assert.match(COLON, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
});

test("the setup URL has the exact public contract and nothing else", () => {
  assert.equal(buildPhoneSetupUrl("192.168.1.20", 3128, "cs", COLON), `http://192.168.1.20:3128/homeproxy/setup?lang=cs&fp=${HEX}`);
  assert.equal(buildPhoneSetupUrl("10.0.0.2", 80, "en", HEX), `http://10.0.0.2:80/homeproxy/setup?lang=en&fp=${HEX}`);
  assert.equal(buildPhoneSetupUrl("10.0.0.2", 80, "de", HEX), `http://10.0.0.2:80/homeproxy/setup?lang=en&fp=${HEX}`);
  for (const [ip, port] of [["8.8.8.8", 3128], ["192.168.1.20", 0], ["192.168.1.20", 65536], ["192.168.1.20", 31.5]]) {
    assert.equal(buildPhoneSetupUrl(ip, port, "cs", HEX), null);
  }
  const url = new URL(buildPhoneSetupUrl("192.168.1.20", 3128, "cs", HEX));
  assert.equal(url.protocol, "http:");
  assert.equal(url.username + url.password, "");
  assert.equal(url.pathname, "/homeproxy/setup");
  assert.deepEqual([...url.searchParams.keys()], ["lang", "fp"]);
  assert.equal(url.hash, "");
});

test("hostile input is rejected rather than escaped into the URL or markup", () => {
  for (const ip of ['192.168.1.2"><script>', "192.168.1.2@evil.test", "192.168.1.2#x", "192.168.1.2?x=1", "user:pass@192.168.1.2"]) {
    assert.equal(buildPhoneSetupUrl(ip, 3128, "cs", HEX), null, ip);
  }
  assert.equal(buildPhoneSetupUrl("192.168.1.2", 3128, "cs", `${HEX.slice(0, 60)}"<&>`), null);
  assert.equal(buildPhoneSetupUrl("192.168.1.2", 3128, 'cs&user=x"', HEX), `http://192.168.1.2:3128/homeproxy/setup?lang=en&fp=${HEX}`);
  const url = buildPhoneSetupUrl("192.168.1.2", 3128, "cs", HEX);
  assert.match(url, /^[A-Za-z0-9:/.?=&]+$/);
});

test("the URL never contains proxy credentials or certificate material", () => {
  const secrets = { proxyUsername: "domov", proxyPassword: "Sup3r-Secret-Key", certificatePem: "-----BEGIN CERTIFICATE-----MIIB" };
  const result = phoneSetupState({ ...base, ...secrets });
  assert.equal(result.kind, "ready");
  const serialized = JSON.stringify(result);
  for (const value of Object.values(secrets)) assert.ok(!serialized.includes(value), value);
  assert.ok(!/user|pass|key|pem|BEGIN/i.test(result.url));
});

test("address selection uses saved, bound, safe private IPs and honours the user and guide choice", () => {
  const multi = {
    ...base,
    listenIps: ["192.168.1.20", "10.8.0.2", "172.20.0.1", "192.168.137.1", "100.64.1.2", "192.168.1.20"],
    available: [
      { ip: "192.168.1.20", unsafe: false },
      { ip: "10.8.0.2", unsafe: true },
      { ip: "172.20.0.1", unsafe: false },
      { ip: "192.168.137.1", unsafe: false },
      { ip: "100.64.1.2", unsafe: false },
    ],
    proxyEndpoints: ["192.168.1.20:3128", "10.8.0.2:3128", "192.168.137.1:3128", "100.64.1.2:3128"],
  };
  assert.deepEqual(phoneSetupAddresses(multi), ["192.168.1.20", "192.168.137.1"]);
  assert.equal(choosePhoneSetupIp(["192.168.1.20", "192.168.137.1"], null, "192.168.137.1"), "192.168.137.1");
  assert.equal(choosePhoneSetupIp(["192.168.1.20", "192.168.137.1"], "192.168.1.20", "192.168.137.1"), "192.168.1.20");
  assert.equal(choosePhoneSetupIp(["192.168.1.20"], "192.168.9.9", "10.8.0.2"), "192.168.1.20");
  assert.equal(choosePhoneSetupIp([], "192.168.1.20", null), null);
  assert.equal(phoneSetupState({ ...multi, guidedIp: "192.168.137.1" }).ip, "192.168.137.1");
  assert.equal(phoneSetupState({ ...multi, guidedIp: "10.8.0.2" }).ip, "192.168.1.20");
  // An available but unsaved address is never offered.
  assert.deepEqual(phoneSetupAddresses({ ...base, listenIps: [], available: [{ ip: "192.168.1.30", unsafe: false }], proxyEndpoints: ["192.168.1.30:3128"] }), []);
  // A saved address whose listener is on another port is not reachable on the advertised port.
  assert.deepEqual(phoneSetupAddresses({ ...base, proxyEndpoints: ["192.168.1.20:8080"] }), []);
});

test("losing any precondition drops the URL immediately with an actionable blocker", () => {
  assert.equal(state().kind, "ready");
  const cases = [
    [{ caPrepared: false }, ["ca"]],
    [{ fingerprint: null }, ["ca"]],
    [{ fingerprint: "short" }, ["ca"]],
    [{ running: false }, ["stopped"]],
    [{ lanEnabled: false }, ["lan"]],
    [{ running: false, lanEnabled: false, caPrepared: false }, ["ca", "stopped", "lan"]],
    [{ proxyEndpoints: ["127.0.0.1:3128"] }, ["address"]],
    [{ available: [] }, ["address"]],
    [{ available: [{ ip: "192.168.1.20", unsafe: true }] }, ["address"]],
    [{ listenIps: ["8.8.8.8"], available: [{ ip: "8.8.8.8", unsafe: false }], proxyEndpoints: ["8.8.8.8:3128"] }, ["address"]],
  ];
  for (const [patch, blockers] of cases) {
    const result = state(patch);
    assert.equal(result.kind, "blocked", JSON.stringify(patch));
    assert.deepEqual(result.blockers, blockers, JSON.stringify(patch));
    assert.equal("url" in result, false);
  }
  // Inspect mode and client trust acknowledgement are not preconditions for phone bootstrap.
  assert.equal(state({ httpsMode: "tunnel", httpsClientTrustAcknowledged: false, tlsInspectionReady: false }).kind, "ready");
});

test("polling with an unchanged payload keeps the same render signature", () => {
  const ready = state();
  assert.equal(phoneSetupSignature(state()), phoneSetupSignature(ready));
  // Duplicate listener entries in a later snapshot do not change what the card shows.
  assert.equal(phoneSetupSignature(state({ proxyEndpoints: [...base.proxyEndpoints, "192.168.1.20:3128"] })), phoneSetupSignature(ready));
  assert.notEqual(phoneSetupSignature(state({ locale: "en" })), phoneSetupSignature(ready));
  assert.notEqual(phoneSetupSignature(state({ fingerprint: "f".repeat(64) })), phoneSetupSignature(ready));
  assert.notEqual(phoneSetupSignature(state({ running: false })), phoneSetupSignature(ready));
  assert.ok(!phoneSetupSignature(state({ running: false })).includes("http://"));
});

test("a stale selection falls back to an eligible address instead of keeping an old URL", () => {
  const two = {
    ...base,
    listenIps: ["192.168.1.20", "192.168.137.1"],
    available: [{ ip: "192.168.1.20", unsafe: false }, { ip: "192.168.137.1", unsafe: false }],
    proxyEndpoints: ["192.168.1.20:3128", "192.168.137.1:3128"],
  };
  assert.match(phoneSetupState({ ...two, preferredIp: "192.168.137.1" }).url, /^http:\/\/192\.168\.137\.1:3128\//);
  // The chosen adapter disappears: the URL moves to the remaining saved address.
  const moved = phoneSetupState({ ...two, preferredIp: "192.168.137.1", available: [{ ip: "192.168.1.20", unsafe: false }] });
  assert.equal(moved.ip, "192.168.1.20");
  assert.ok(!moved.url.includes("192.168.137.1"));
  // Saved LAN turned off: no address and no URL, even though the user had picked one.
  assert.deepEqual(phoneSetupState({ ...two, preferredIp: "192.168.137.1", lanEnabled: false }), { kind: "blocked", blockers: ["lan"], addresses: [] });
  // A saved .255 host address is a valid bootstrap target.
  const edge = phoneSetupState({ ...base, listenIps: ["192.168.1.255"], available: [{ ip: "192.168.1.255", unsafe: false }], proxyEndpoints: ["192.168.1.255:3128"] });
  assert.equal(edge.kind, "ready");
});

test("the QR path covers exactly the dark modules inside the quiet zone", () => {
  const dark = new Set(["0,0", "0,1", "0,2", "1,1", "2,0", "2,2"]);
  const path = qrModulePath(3, (row, col) => dark.has(`${row},${col}`), 4);
  assert.equal(path, "M4 4h3v1h-3zM5 5h1v1h-1zM4 6h1v1h-1zM6 6h1v1h-1z");
  assert.equal(qrModulePath(2, () => false), "");
});

test("a worst-case setup URL produces a compact, scannable QR code", () => {
  const url = buildPhoneSetupUrl("192.168.100.100", 65535, "cs", "f".repeat(64));
  assert.equal(url.length, 120);
  const qr = qrcode(0, "M");
  qr.addData(url, "Byte");
  qr.make();
  const count = qr.getModuleCount();
  // Version 7 (45 modules) plus a quiet zone of 4 stays above 4 CSS px per module at 220 px.
  assert.ok(count <= 45, `module count ${count}`);
  assert.ok(220 / (count + 8) >= 4);
  let darkModules = 0;
  for (let row = 0; row < count; row += 1) for (let col = 0; col < count; col += 1) if (qr.isDark(row, col)) darkModules += 1;
  const path = qrModulePath(count, (row, col) => qr.isDark(row, col));
  const painted = [...path.matchAll(/h(\d+)/g)].reduce((sum, match) => sum + Number(match[1]), 0);
  assert.equal(painted, darkModules);
  // Finder pattern corners must be dark at the expected positions.
  for (const [row, col] of [[0, 0], [0, count - 1], [count - 1, 0]]) assert.equal(qr.isDark(row, col), true);
});

// Execute the real renderer and state adapter in a small DOM harness: this covers
// wiring beyond the pure helpers without claiming a browser or native OS test.
const mainSource = await readFile(new URL("./main.ts", import.meta.url), "utf8");
const mainAst = ts.createSourceFile("main.ts", mainSource, ts.ScriptTarget.ES2022, true);
const adapterFunctions = ["currentDeviceSetupState", "deviceSetupBlockerText", "renderDeviceSetup"];
const rendererSource = mainAst.statements
  .filter((node) => ts.isFunctionDeclaration(node) && adapterFunctions.includes(node.name?.text))
  .map((node) => node.getText(mainAst)).join("\n");
assert.equal(rendererSource.match(/function /g).length, adapterFunctions.length);
const harnessSource = `
  let snapshot = null;
  let tlsStatus = { prepared: true, sha256Fingerprint: "f".repeat(64) };
  let locale = "cs", busy = false, guideSelectedIp = null;
  let deviceSetupPreferredIp = null, deviceSetupState = null, deviceSetupRenderSignature = null;
  const DEVICE_SETUP_QUIET_ZONE = 4;
  const selectedLanIps = settings => settings.listenIps;
  const classifyLanAddress = address => address.unsafe ? "vpn" : "home";
  const isUnsafeGuideAddress = kind => kind === "vpn" || kind === "internal";
  const inspectionSupported = () => snapshot?.supportsHttpsInspection ?? true;
  const t = (key, params) => key + JSON.stringify(params ?? {});
  class Element {
    textContent = ""; hidden = false; disabled = false; value = "";
    dataset = {}; attributes = new Map(); children = []; replacements = 0;
    get options() { return this.children; }
    replaceChildren(...children) { this.children = children; this.replacements++; }
    setAttribute(key, value) { this.attributes.set(key, value); }
    removeAttribute(key) { this.attributes.delete(key); }
    toggleAttribute(key, force) {
      const present = force ?? !this.attributes.has(key);
      if (present) this.attributes.set(key, "");
      else this.attributes.delete(key);
      return present;
    }
    closest() { return byId("figure"); }
  }
  const elements = new Map();
  const byId = id => {
    if (!elements.has(id)) {
      const node = new Element();
      // Like the initial SVG markup: hidden is an attribute. Assigning a JS
      // hidden property on SVG must not remove it, unlike an HTMLElement.
      if (id === "phone-setup-qr") node.setAttribute("hidden", "");
      elements.set(id, node);
    }
    return elements.get(id);
  };
  const document = { createElement: () => new Element() };
  ${rendererSource}
  return {
    byId,
    update(next) { snapshot = next; renderDeviceSetup(); },
    choose(ip) { deviceSetupPreferredIp = ip; renderDeviceSetup(); },
    get state() { return deviceSetupState; },
  };
`;
const harnessJs = ts.transpileModule(harnessSource, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const createHarness = () => new Function("phoneSetupState", "phoneSetupSignature", "qrModulePath", "qrcode", harnessJs)(phoneSetupState, phoneSetupSignature, qrModulePath, qrcode);
const liveSnapshot = () => ({
  running: true,
  settings: { lanEnabled: true, listenIps: ["192.168.1.20", "192.168.1.30"], proxyPort: 3128, httpsMode: "tunnel", httpsClientTrustAcknowledged: false },
  availableAddresses: [{ ip: "192.168.1.20", unsafe: false }, { ip: "192.168.1.30", unsafe: false }],
  proxyAddresses: ["192.168.1.20:3128", "192.168.1.30:3128"],
  httpsAuthority: { capability: true, prepared: true, sha256Fingerprint: HEX },
  tlsInspectionReady: false,
});

test("the real state adapter uses authoritative CA removal and replacement, independent of stale TLS status", () => {
  const view = createHarness();
  const next = liveSnapshot();
  view.update(next);
  assert.equal(view.state.fingerprint, HEX, "authoritative snapshot beats the old cached fingerprint");
  assert.equal(view.byId("phone-setup-qr").attributes.has("hidden"), false, "ready QR must remove its actual hidden attribute");
  const oldPath = view.byId("device-setup-qr-path").attributes.get("d");
  next.httpsAuthority.sha256Fingerprint = "a".repeat(64);
  view.update(next);
  assert.equal(view.state.fingerprint, "a".repeat(64));
  assert.notEqual(view.byId("device-setup-qr-path").attributes.get("d"), oldPath);
  next.httpsAuthority.prepared = false;
  view.update(next);
  assert.equal(view.state, null);
  assert.equal(view.byId("device-setup-qr-path").attributes.get("d"), "");
  assert.equal(view.byId("phone-setup-qr").attributes.has("hidden"), true);
  assert.equal(view.byId("phone-setup-url").textContent, "");
  assert.equal(view.byId("phone-setup-ready").hidden, true);
});

test("the real renderer retains QR and dropdown DOM during stable polls and CA changes", () => {
  const view = createHarness();
  const next = liveSnapshot();
  view.update(next);
  const select = view.byId("device-setup-address-select");
  const options = select.children;
  const qr = view.byId("phone-setup-qr");
  const oldPath = view.byId("device-setup-qr-path").attributes.get("d");
  view.update(structuredClone(next));
  assert.equal(select.children, options);
  assert.equal(select.replacements, 1);
  assert.equal(view.byId("phone-setup-qr"), qr);
  assert.equal(view.byId("device-setup-qr-path").attributes.get("d"), oldPath);
  next.httpsAuthority.sha256Fingerprint = "a".repeat(64);
  view.update(next);
  assert.equal(select.children, options, "CA changes do not rebuild a focused address menu");
  view.choose("192.168.1.30");
  assert.equal(select.children, options, "selection changes do not rebuild the address menu");
  assert.equal(select.value, "192.168.1.30");
  assert.match(view.byId("phone-setup-url").textContent, /^http:\/\/192\.168\.1\.30:3128/);
  next.proxyAddresses = ["192.168.1.20:3128"];
  view.update(next);
  assert.equal(view.state.ip, "192.168.1.20");
  assert.notEqual(select.children, options, "a vanished listener does replace its obsolete option");
  next.running = false;
  view.update(next);
  assert.equal(view.state, null);
  assert.equal(view.byId("device-setup-qr-path").attributes.get("d"), "");
  assert.equal(view.byId("phone-setup-url").textContent, "");
});
