import assert from "node:assert/strict";
import test from "node:test";
import { canLimitDevice, parseDeviceLimitKib } from "../target/ui-tests/setup.js";

test("device limits accept only private LAN IPv4 peers supported by the core", () => {
  for (const ip of ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.9"]) assert.equal(canLimitDevice(ip), true, ip);
  for (const ip of ["127.0.0.1", "::1", "169.254.1.2", "0.0.0.0", "8.8.8.8", "172.15.1.1", "172.32.0.1", "192.168.256.1", "192.168.1", "192.168.1.1:80"]) assert.equal(canLimitDevice(ip), false, ip);
});

test("device KiB limits convert without exceeding the core's one billion byte ceiling", () => {
  assert.equal(parseDeviceLimitKib("0"), 0);
  assert.equal(parseDeviceLimitKib("64"), 65536);
  assert.equal(parseDeviceLimitKib("976562"), 999999488);
  for (const value of ["976563", "1000000000", "-1", "0.5", "", " ", "NaN", "Infinity"]) assert.equal(parseDeviceLimitKib(value), null, value);
});

import { translateActivityValue } from "../target/ui-tests/i18n.js";
test("activity maps stable status, cache and safe error tokens in both locales", () => {
  for (const locale of ["cs", "en"]) {
    for (const token of ["active", "completed", "error", "bypass", "cache-disabled", "request-private-or-ineligible", "response-private-or-ineligible", "device-denied", "authentication-required", "TLS-handshake-timeout", "TLS-handshake-rejected", "SOCKS5 UDP ASSOCIATE/BIND unsupported; TCP only"]) {
      assert.notEqual(translateActivityValue(token, locale), token);
    }
    assert.match(translateActivityValue("HIT", locale), /HIT/);
    assert.match(translateActivityValue("MISS", locale), /MISS/);
  }
  assert.equal(translateActivityValue("unknown-safe-code", "en"), "unknown-safe-code");
  assert.equal(translateActivityValue("Proxy se nedokázala spojit se sítí.", "en"), "The proxy could not connect to the network.");
});
