import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator, translateActivityValue, translateBackendMessage } from "../target/ui-tests/i18n.js";

test("service port denials expose the same allowed ports in Czech and English notices and activity", () => {
  const cases = [
    ["CONNECT ze sítě LAN je povolený jen na porty 80, 443, 5060 a 8080.", "LAN CONNECT is allowed only to ports 80, 443, 5060 and 8080."],
    ["CONNECT ze sítě LAN je povolený jen na porty 443, 5060 a 8080.", "LAN CONNECT is allowed only to ports 443, 5060 and 8080."],
    ["Nešifrované HTTP je povolené jen na porty 80, 5060 a 8080.", "Plain HTTP is allowed only to ports 80, 5060 and 8080."],
  ];
  for (const translate of [translateActivityValue, translateBackendMessage]) {
    for (const [cs, en] of cases) {
      assert.equal(translate(cs, "cs"), cs);
      assert.equal(translate(cs, "en"), en);
    }
  }
});

test("CZ and EN guides contain the same host, device, certificate, and safety steps", () => {
  const cs = createTranslator("cs");
  const en = createTranslator("en");
  const sharedKeys = [
    "fourStepsAria",
    "step3Title",
    "step3Copy",
    "applyAndStart",
    "setupSaving",
    "step4Label",
    "step4Title",
    "step4Copy",
    "hostProxyNoteTitle",
    "hostProxyNoteCopy",
    "hostProxyLocalCopy",
    "secondDeviceTitle",
    "secondDeviceCopy",
    "caInstallTitle",
    "caInstallCopy",
    "chatAppsTitle",
    "chatAppsLead",
    "whatsappMessengerTitle",
    "whatsappMessengerCopy",
    "telegramTitle",
    "telegramCopy",
    "chatCacheNote",
    "certificateProblem",
    "certificateProblemCopy",
    "chatAppProblem",
    "chatAppProblemCopy",
  ];

  for (const key of sharedKeys) {
    assert.ok(cs(key).trim(), `missing Czech copy for ${key}`);
    assert.ok(en(key).trim(), `missing English copy for ${key}`);
  }
  assert.equal(cs("step3Title"), "Zapněte službu a tento počítač");
  assert.equal(en("step3Title"), "Turn on the service and this computer");
  assert.match(cs("fourStepsAria"), /čtyřech/);
  assert.match(en("fourStepsAria"), /four/);
  assert.match(cs("guideInvite"), /Čtyři/);
  assert.match(en("guideInvite"), /Four/);
  assert.equal(cs("applyAndStart"), "Uložit");
  assert.equal(en("applyAndStart"), "Save");
  assert.match(cs("proxyPromptHelp"), /výše.*kroku/i);
  assert.match(en("proxyPromptHelp"), /above.*step/i);
  assert.match(cs("step3Copy"), /kdykoli.*tady/i);
  assert.match(en("step3Copy"), /here.*any time/i);
  assert.match(cs("socks5DisabledHelp"), /kroku 3.*Nastavení/);
  assert.match(en("socks5DisabledHelp"), /step 3.*Settings/);
  for (const translate of [cs, en]) {
    assert.match(translate("hostProxyLocalCopy", { port: 3128 }), /127\.0\.0\.1/);
    assert.match(translate("hostProxyLocalCopy", { port: 3128 }), /3128/);
    assert.match(translate("caInstallCopy"), /Current User|Aktuální uživatel/);
    assert.match(
      translate("caInstallCopy"),
      /Trusted Root Certification Authorities|Důvěryhodné kořenové certifikační autority/,
    );
    assert.match(
      translate("certificateProblemCopy"),
      /certificate-pinned|připnutým certifikátem/,
    );
    const whatsapp = translate("whatsappMessengerCopy", { port: 1080 });
    assert.match(whatsapp, /phone|telefon/);
    assert.match(whatsapp, /Super Proxy/);
    assert.match(whatsapp, /restart|restartujte|znovu spusťte|open it again|reopen/);
    assert.match(whatsapp, /UDP/);
    assert.match(whatsapp, /experiment/);
    assert.match(whatsapp, /1080/);
    assert.doesNotMatch(whatsapp, /Desktop|web\.whatsapp\.com/);
    const telegram = translate("telegramCopy", { port: 1080 });
    assert.match(telegram, /SOCKS5/);
    assert.match(telegram, /127\.0\.0\.1/);
    assert.match(telegram, /1080/);
    assert.match(translate("chatCacheNote"), /never|nikdy/);
  }
});

test("the product copy no longer contains the superseded HTTPS and host-proxy claims", async () => {
  const source = await readFile(new URL("./i18n.ts", import.meta.url), "utf8");
  for (const forbidden of [
    ["Na tomto počítači proxy nastavovat", "nemusíte"].join(" "),
    ["You do not need to set a proxy on", "this computer"].join(" "),
    ["nečte", "HTTPS"].join(" "),
    ["does not modify", "HTTPS content"].join(" "),
    ["unchanged encrypted", "tunnel"].join(" "),
    ["note", "book"].join(""),
    ["lap", "top"].join(""),
  ]) {
    assert.ok(!source.toLowerCase().includes(forbidden.toLowerCase()), `forbidden copy: ${forbidden}`);
  }
});

test("UDP diagnostics are localized in both activity and notices without exposing internal keys", () => {
  const keys = ["socks5-udp-disabled", "socks5-bind-unsupported", "socks5-command-unsupported", "socks5-udp-client-mismatch", "socks5-udp-association-limit", "socks5-udp-destination-denied", "socks5-udp-endpoint-limit", "socks5-udp-send-failed"];
  for (const key of keys) {
    for (const locale of ["cs", "en"]) {
      const activity = translateActivityValue(key, locale);
      assert.notEqual(activity, key);
      assert.equal(translateBackendMessage(key, locale), activity);
    }
    assert.notEqual(translateActivityValue(key, "cs"), translateActivityValue(key, "en"));
  }
});


test("failed Stop persistence explains the stopped runtime and possible restart in both locales", () => {
  const message = "Proxy je zastavená, ale vypnutý stav se nepodařilo uložit. Při příštím spuštění aplikace se může znovu zapnout.";
  assert.equal(translateBackendMessage(message, "cs"), message);
  assert.equal(translateBackendMessage(message, "en"), "The proxy is stopped, but its off state could not be saved. It may start again the next time you open the app.");
});


test("busy cache clear explains logical invalidation and pending disk cleanup in both locales", () => {
  const message = "Cache nelze změnit: Cache se právě používá. Položky jsou zneplatněné; soubory se odstraní po dokončení přenosu při dalším přístupu do cache.";
  assert.equal(translateBackendMessage(message, "cs"), message);
  assert.equal(translateBackendMessage(message, "en"), "Could not update the cache: The cache is in use. Entries are invalidated; files will be removed on the next cache access after the transfer finishes.");
});
