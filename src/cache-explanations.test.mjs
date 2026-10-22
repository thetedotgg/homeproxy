import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { cacheProfileLabel, httpsInspectionActive, topCacheBypassReasons } from "../target/ui-tests/cache-controls.js";
import { cacheBypassReasonLabel, createTranslator } from "../target/ui-tests/i18n.js";

const tunnel = { cacheEnabled: true, cacheLimitGib: 8, compressionPreset: "balanced", responseBufferLimitMib: 8,
  responseBufferBudgetMib: 64, httpsMode: "tunnel", httpsClientTrustAcknowledged: false, httpsInspectHosts: [] };
const selected = { ...tunnel, httpsMode: "inspect", httpsClientTrustAcknowledged: true,
  httpsInspectionScope: "selectedHosts", httpsInspectHosts: ["example.org"] };
const all = { ...selected, httpsInspectionScope: "allSupportedHosts", httpsInspectHosts: [] };

test("home cache label says HTTP only unless saved settings really inspect HTTPS", () => {
  const cs = createTranslator("cs");
  const en = createTranslator("en");
  const render = (settings, supported = true) => {
    const label = cacheProfileLabel(settings, supported);
    return [cs(label.key, { size: label.size }), en(label.key, { size: label.size })];
  };
  assert.deepEqual(render(tunnel), ["Veřejná · 8 GiB · jen HTTP", "Public · 8 GiB · HTTP only"]);
  assert.deepEqual(render(selected), ["Veřejná · 8 GiB", "Public · 8 GiB"]);
  assert.deepEqual(render(all), ["Veřejná · 8 GiB", "Public · 8 GiB"]);
  for (const notActive of [
    { ...selected, httpsClientTrustAcknowledged: false },
    { ...selected, httpsInspectHosts: [] },
    { ...selected, httpsInspectionScope: undefined, httpsInspectHosts: [] },
    { ...all, httpsMode: "tunnel" },
    { ...all, httpsClientTrustAcknowledged: false },
  ]) {
    assert.equal(cacheProfileLabel(notActive, true).key, "publicWithSizeHttpOnly");
    assert.equal(httpsInspectionActive(notActive), false);
  }
  // A platform without inspection support never claims HTTPS caching.
  assert.equal(cacheProfileLabel(all, false).key, "publicWithSizeHttpOnly");
  assert.deepEqual(render({ ...all, cacheEnabled: false }), [cs("off"), en("off")]);
  assert.equal(render({ ...tunnel, cacheLimitGib: 32 })[0], "Veřejná · 32 GiB · jen HTTP");
});

test("home renders the cache label from the saved service snapshot, not the draft", async () => {
  const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");
  assert.match(source, /cacheProfileLabel\(snapshot\.settings, inspectionSupported\(\)\)/);
  assert.doesNotMatch(source, /cacheProfileLabel\(draft/);
  assert.match(source, /topCacheBypassReasons\(snapshot\.stats\.cacheBypassReasons\)/);
  assert.match(source, /<p id="cache-bypass-reasons" class="field-help" hidden><\/p>/);
});

test("top bypass reasons are ordered by count then code and ignore malformed entries", () => {
  assert.deepEqual(topCacheBypassReasons(undefined), []);
  assert.deepEqual(topCacheBypassReasons(null), []);
  assert.deepEqual(topCacheBypassReasons({}), []);
  assert.deepEqual(topCacheBypassReasons({
    "response-private": 4,
    "request-cookie": 12,
    "request-query": 4,
    "response-set-cookie": 7,
    "cache-disabled": 0,
    broken: "9",
    nan: Number.NaN,
  }), [
    { code: "request-cookie", count: 12 },
    { code: "response-set-cookie", count: 7 },
    { code: "request-query", count: 4 },
  ]);
  assert.deepEqual(topCacheBypassReasons({ a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 }, 5).map(({ code }) => code),
    ["f", "e", "d", "c", "b"]);
});

test("common bypass reasons have Czech and English labels and unknown codes stay visible", () => {
  const codes = ["request-cookie", "request-query", "request-unknown-header", "request-navigation",
    "response-not-public", "response-set-cookie", "response-private", "response-no-store", "response-vary",
    "response-content-coding", "response-unknown-length", "cache-write-failed", "cache-recovery-blocked",
    "cache-disabled", "other", "unspecified"];
  for (const code of codes) {
    const cs = cacheBypassReasonLabel(code, "cs");
    const en = cacheBypassReasonLabel(code, "en");
    assert.notEqual(cs, code, code);
    assert.notEqual(en, code, code);
    assert.notEqual(cs, en, code);
  }
  assert.equal(cacheBypassReasonLabel("request-cookie", "cs"), "Požadavek obsahuje cookies");
  assert.equal(cacheBypassReasonLabel("request-cookie", "en"), "Request contains cookies");
  assert.equal(cacheBypassReasonLabel("future-reason", "cs"), "future-reason");
  assert.equal(cacheBypassReasonLabel("toString", "en"), "toString");
  assert.equal(cacheBypassReasonLabel("__proto__", "en"), "__proto__");
  assert.equal(createTranslator("en")("cacheBypassTopReasons", { reasons: "A (2) · B (1)" }),
    "Top cache bypass reasons: A (2) · B (1)");
  assert.equal(createTranslator("cs")("cacheBypassTopReasons", { reasons: "A (2)" }),
    "Nejčastější důvody vynechání cache: A (2)");
});
