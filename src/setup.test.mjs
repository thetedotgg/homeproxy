import assert from "node:assert/strict";
import test from "node:test";

import {
  availableGuideSelection,
  classifyLanAddress,
  connectionVerified,
  guideLanAddresses,
  recommendedLanAddress,
} from "../target/ui-tests/setup.js";

const addresses = [
  { interfaceName: "NordLynx", ip: "10.5.0.2" },
  { interfaceName: "vEthernet (WSL (Hyper-V firewall))", ip: "172.23.176.1" },
  { interfaceName: "Wi-Fi 3", ip: "192.168.68.52" },
];

test("classifies physical, VPN, internal, and hotspot adapters", () => {
  assert.equal(classifyLanAddress(addresses[0]), "vpn");
  assert.equal(classifyLanAddress(addresses[1]), "internal");
  assert.equal(classifyLanAddress(addresses[2]), "home");
  assert.equal(
    classifyLanAddress({ interfaceName: "PANGP Virtual Ethernet Adapter", ip: "10.10.10.10" }),
    "vpn",
  );
  assert.equal(
    classifyLanAddress({ interfaceName: "GlobalProtect", ip: "10.10.10.10" }),
    "vpn",
  );
  assert.equal(
    classifyLanAddress({ interfaceName: "Local Area Connection* 12", ip: "192.168.137.1" }),
    "hotspot",
  );
});

test("recommends the physical adapter for devices on the same Wi-Fi", () => {
  assert.deepEqual(recommendedLanAddress(addresses, "sameWifi"), addresses[2]);
});

test("does not automatically recommend an unrecognized adapter", () => {
  const unrecognized = [{ interfaceName: "Network 12", ip: "192.168.50.20" }];
  assert.equal(recommendedLanAddress(unrecognized, "sameWifi"), null);
});

test("does not silently substitute a home or virtual adapter for a missing hotspot", () => {
  assert.equal(recommendedLanAddress(addresses, "hotspot"), null);
  const hotspot = { interfaceName: "Local Area Connection* 12", ip: "192.168.137.1" };
  assert.deepEqual(recommendedLanAddress([...addresses, hotspot], "hotspot"), hotspot);
});

test("shows only hotspot candidates in the hotspot address step", () => {
  const hotspot = { interfaceName: "Local Area Connection* 12", ip: "192.168.137.1" };
  const unknown = { interfaceName: "Sitove pripojeni 12", ip: "192.168.137.50" };

  assert.deepEqual(guideLanAddresses([...addresses, hotspot, unknown], "hotspot"), [
    hotspot,
    unknown,
  ]);
  assert.deepEqual(guideLanAddresses(addresses, "sameWifi"), addresses);
});

test("marks setup verified only after a new successful external request", () => {
  assert.equal(connectionVerified(0, null), false);
  assert.equal(connectionVerified(3, 3), false);
  assert.equal(connectionVerified(4, 3), true);
  assert.equal(connectionVerified(1, null), false);
});


test("adapter changes replace a vanished guide address without selecting WSL or VPN", () => {
  const current = [...addresses.slice(0, 2), { interfaceName: "Wi-Fi 3", ip: "192.168.68.51" }];
  assert.equal(availableGuideSelection(current, "192.168.68.52", "sameWifi"), "192.168.68.51");
  assert.equal(availableGuideSelection(current, "192.168.68.51", "sameWifi"), "192.168.68.51");
  assert.equal(availableGuideSelection(current.slice(0, 2), "192.168.68.51", "sameWifi"), null);
  assert.equal(availableGuideSelection(current, "192.168.137.1", "hotspot"), null);
});
