import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_PROXY_PORT,
  DEFAULT_SOCKS5_PORT,
  parseServicePort,
  serviceEndpoint,
  validateServicePorts,
} from "../target/ui-tests/service-ports.js";

test("service port defaults and common proxy ports are valid", () => {
  assert.equal(DEFAULT_PROXY_PORT, 17891);
  assert.equal(DEFAULT_SOCKS5_PORT, 1080);
  for (const proxyPort of [80, 3128, 17891]) {
    assert.equal(validateServicePorts({
      proxyPort,
      socks5Enabled: true,
      socks5Port: 1080,
    }), null);
  }
});

test("invalid and equal active service ports are rejected", () => {
  assert.equal(parseServicePort("0"), null);
  assert.equal(parseServicePort("65536"), null);
  assert.equal(parseServicePort("3128.5"), null);
  assert.equal(parseServicePort("3128"), 3128);
  assert.equal(validateServicePorts({ proxyPort: 0, socks5Enabled: false, socks5Port: 1080 }), "proxyInvalid");
  assert.equal(validateServicePorts({ proxyPort: 3128, socks5Enabled: true, socks5Port: 0 }), "socks5Invalid");
  assert.equal(validateServicePorts({ proxyPort: 1080, socks5Enabled: true, socks5Port: 1080 }), "portsEqual");
  assert.equal(validateServicePorts({ proxyPort: 1080, socks5Enabled: false, socks5Port: 1080 }), null);
});

test("endpoint copy uses the selected address and port", () => {
  assert.equal(serviceEndpoint("127.0.0.1", 3128), "127.0.0.1:3128");
  assert.equal(serviceEndpoint("192.168.68.52", 1080), "192.168.68.52:1080");
});
