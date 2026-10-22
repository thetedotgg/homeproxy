import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator } from "../target/ui-tests/i18n.js";

const mainSource = await readFile(new URL("./main.ts", import.meta.url), "utf8");
const i18nSource = await readFile(new URL("./i18n.ts", import.meta.url), "utf8");
const installerHooks = await readFile(new URL("../src-tauri/windows/hooks.nsh", import.meta.url), "utf8");

test("LAN credentials are editable and authentication can be disabled in Settings and the guide", () => {
  assert.doesNotMatch(mainSource, /id="proxy-user"[^>]*readonly/);
  assert.doesNotMatch(mainSource, /id="proxy-password"[^>]*readonly/);
  assert.match(mainSource, /id="lan-auth-enabled"/);
  for (const id of [
    "guide-lan-auth-enabled",
    "guide-proxy-user-input",
    "guide-proxy-password-input",
    "guide-edit-reveal-key",
    "guide-edit-access",
  ]) {
    assert.match(mainSource, new RegExp(`id="${id}"`));
  }
  assert.doesNotMatch(mainSource, /id="guide-proxy-user-input"[^>]*readonly/);
  assert.doesNotMatch(mainSource, /id="guide-proxy-password-input"[^>]*readonly/);
  assert.match(mainSource, /proxyUsername\s*=/);
  assert.match(mainSource, /proxyPassword\s*=/);

  const handlerStart = mainSource.indexOf('lanAuthCheckbox.addEventListener("change"');
  const handlerEnd = mainSource.indexOf('proxyUserInput.addEventListener("input"', handlerStart);
  assert.ok(handlerStart >= 0 && handlerEnd > handlerStart, "LAN login toggle handler is missing");
  const handler = mainSource.slice(handlerStart, handlerEnd);
  assert.doesNotMatch(handler, /confirm\(|showModal\(|invoke\(|runBusy\(|applyDirtyDraft\(/);
  assert.match(mainSource, /guideLanAuthCheckbox\.addEventListener\("change"/);
  assert.match(mainSource, /guideProxyUserInput\.addEventListener\("input"/);
  assert.match(mainSource, /guideProxyPasswordInput\.addEventListener\("input"/);
});

test("settings render a device list with allow and deny actions", () => {
  assert.match(mainSource, /id="device-list"/);
  assert.match(mainSource, /set_device_allowed/);
  assert.match(mainSource, /lastSeenUnixMs/);
});

test("CZ and EN explain open LAN access, device controls, and scoped mobile WhatsApp behavior", () => {
  for (const locale of ["cs", "en"]) {
    const translate = createTranslator(locale);
    for (const key of [
      "requireLanLogin",
      "openLanWarning",
      "changeOrDisableAccess",
      "knownDevicesTitle",
      "knownDevicesCopy",
      "allowDevice",
      "denyDevice",
      "lastActive",
      "noKnownDevices",
    ]) {
      assert.ok(translate(key).trim(), `${locale} is missing ${key}`);
    }
    const whatsapp = translate("whatsappMessengerCopy", { port: 1080 });
    assert.match(whatsapp, /phone|telefon/);
    assert.match(whatsapp, /Super Proxy/);
    assert.match(whatsapp, /restart|restartujte|znovu spusťte|open it again|reopen/);
    assert.match(whatsapp, /UDP|QUIC/);
    assert.doesNotMatch(whatsapp, /Desktop|web\.whatsapp\.com/);
    const oldShortcut = `${translate("useHomeProxyTitle")} ${translate("useHomeProxyCopy")}`;
    assert.match(oldShortcut, /HomeProxy/);
    assert.match(oldShortcut, /Klidná síť/);
  }
});

test("service ports are editable in Settings and the guided setup", () => {
  for (const id of [
    "proxy-port",
    "socks5-enabled",
    "socks5-udp-enabled",
    "socks5-port",
    "guide-proxy-port",
    "guide-socks5-enabled",
    "guide-socks5-udp-enabled",
    "guide-socks5-port",
  ]) {
    assert.match(mainSource, new RegExp(`id="${id}"`));
  }
  assert.match(mainSource, /validateServicePorts/);
  assert.match(mainSource, /socks5Addresses/);
  assert.match(mainSource, /socks5Connections/);
});

test("guided setup has four steps and a single service-port editor", () => {
  const steps = [...mainSource.matchAll(/<li id="guide-step-[^"]+">/g)].map((match) => match[0]);
  assert.equal(steps.length, 4);
  assert.doesNotMatch(mainSource, /guide-step-device|guide-recipe-/);
  assert.doesNotMatch(i18nSource, /fiveStepsAria|recipePorts|step5(?:Label|Title|Copy)/);

  const prepareStart = mainSource.indexOf('<li id="guide-step-prepare">');
  const verifyStart = mainSource.indexOf('<li id="guide-step-verify">');
  assert.ok(prepareStart >= 0 && verifyStart > prepareStart, "combined setup step is missing");
  const prepare = mainSource.slice(prepareStart, verifyStart);
  for (const id of [
    "guide-proxy-port",
    "guide-socks5-enabled",
    "guide-socks5-udp-enabled",
    "guide-socks5-port",
    "guide-cache-enabled",
    "guide-lan-auth-enabled",
    "guide-proxy-user-input",
    "guide-proxy-password-input",
    "guide-prepare",
    "guide-prepared-instructions",
    "guide-host-proxy-port",
    "guide-proxy-address",
    "guide-copy-ca",
    "guide-copy-socks5",
  ]) {
    assert.match(prepare, new RegExp(`id="${id}"`));
  }
  for (const port of [80, 3128, 17891]) {
    assert.match(prepare, new RegExp(`data-guide-proxy-port-preset="${port}"`));
  }

  const instructionsStart = prepare.indexOf('id="guide-prepared-instructions"');
  assert.ok(instructionsStart >= 0, "copy-only instructions are missing");
  assert.ok(
    prepare.indexOf('id="guide-access-controls"') < instructionsStart,
    "the credential editor must stay in the single setup editor",
  );
  assert.doesNotMatch(prepare.slice(instructionsStart), /type="(?:number|checkbox)"/);
  assert.doesNotMatch(mainSource, /byId\("guide-setup-controls"\)\.hidden/);
  assert.match(mainSource, /byId\("guide-prepared-instructions"\)\.hidden = !instructionsReady/);
  assert.doesNotMatch(i18nSource, /setupChangePortsLater/);
  assert.match(mainSource, /<span class="route-number" aria-hidden="true">4<\/span>[\s\S]*step4Label/);
});

test("the installer firewall rule follows the app on private local networks without a fixed port", () => {
  const addRule = installerHooks.split("firewall add rule")[1]?.split("'\n")[0] ?? "";
  assert.match(addRule, /program="\$INSTDIR\\klidna-sit\.exe"/);
  assert.match(addRule, /profile=private/);
  assert.match(addRule, /protocol=TCP/);
  assert.match(addRule, /remoteip=localsubnet/);
  assert.doesNotMatch(addRule, /localport=/);
  assert.doesNotMatch(addRule, /profile=(?:public|domain|any)/i);
});

test("runtime copy derives ports instead of embedding the former default", () => {
  assert.equal(i18nSource.match(/17891/g)?.length ?? 0, 0);
  const linesWithFormerDefault = mainSource.split("\n").filter((line) => line.includes("17891"));
  assert.equal(linesWithFormerDefault.length, 2);
  assert.ok(
    linesWithFormerDefault.every((line) => /data-(?:guide-)?proxy-port-preset="17891">17891</.test(line)),
    "only the Settings and single guide preset buttons may contain 17891",
  );
  assert.match(mainSource, /snapshot\.settings\.proxyPort/);
  assert.match(mainSource, /snapshot\.settings\.socks5Port/);
});
