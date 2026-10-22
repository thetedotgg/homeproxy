import assert from "node:assert/strict";
import { chmod, copyFile, mkdtemp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { createTranslator, isServiceConflict, translateServiceError } from "../target/ui-tests/i18n.js";
import { availableGuideSelection, classifyLanAddress, guideLanAddresses, recommendedLanAddress } from "../target/ui-tests/setup.js";
import { detectHostPlatform } from "../target/ui-tests/snapshot.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");
const main = await read("./main.ts");
const linuxRust = await read("../src-tauri/src/linux.rs");
const libRust = await read("../src-tauri/src/lib.rs");
const linuxConfig = JSON.parse(await read("../src-tauri/tauri.linux.conf.json"));
const tauriConfig = JSON.parse(await read("../src-tauri/tauri.conf.json"));
const desktopTemplate = await read("../src-tauri/linux/homeproxy.desktop");
const desktopBuild = await read("../scripts/build-linux-desktop.sh");
const repoRoot = fileURLToPath(new URL("../", import.meta.url));

test("host platform is derived from the webview without asking the service", () => {
  assert.equal(detectHostPlatform("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15"), "linux");
  assert.equal(detectHostPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/140"), "windows");
  assert.equal(detectHostPlatform(""), "windows");
});

test("Linux adapters: physical names are home, virtual and tunnel names never are", () => {
  const kind = (interfaceName) => classifyLanAddress({ interfaceName, ip: "192.168.1.20" }, "linux");
  for (const name of ["enp3s0", "eno1", "ens33", "enx001122334455", "eth0", "wlp2s0", "wlo1", "wls1", "wlan0", "wl0"]) {
    assert.equal(kind(name), "home", name);
  }
  for (const name of ["docker0", "br-1a2b3c", "veth12ab", "virbr0", "lxcbr0", "lo"]) assert.equal(kind(name), "internal", name);
  for (const name of ["tun0", "tap1", "wg0", "tailscale0", "zt5u4abc", "ppp0"]) assert.equal(kind(name), "vpn", name);
  assert.equal(kind("usb0"), "unknown");
  // The Windows Mobile Hotspot address rule must not leak into Linux.
  assert.equal(classifyLanAddress({ interfaceName: "enp3s0", ip: "192.168.137.1" }, "linux"), "home");
  assert.equal(classifyLanAddress({ interfaceName: "Wi-Fi", ip: "192.168.137.1" }), "hotspot");
});

test("Linux recommends the physical adapter and never a Docker or VPN one", () => {
  const addresses = [
    { interfaceName: "docker0", ip: "172.17.0.1" },
    { interfaceName: "tun0", ip: "10.8.0.2" },
    { interfaceName: "wlp2s0", ip: "192.168.1.20" },
  ];
  assert.equal(recommendedLanAddress(addresses, "sameWifi", "linux")?.ip, "192.168.1.20");
  assert.equal(recommendedLanAddress(addresses.slice(0, 2), "sameWifi", "linux"), null);
  assert.equal(recommendedLanAddress(addresses, "hotspot", "linux"), null);
  assert.deepEqual(guideLanAddresses(addresses, "hotspot", "linux"), []);
  assert.equal(availableGuideSelection(addresses, "10.9.9.9", "sameWifi", "linux"), "192.168.1.20");
});

test("Windows adapter classification is unchanged by the platform parameter", () => {
  assert.equal(classifyLanAddress({ interfaceName: "vEthernet (WSL)", ip: "172.20.0.1" }), "internal");
  assert.equal(classifyLanAddress({ interfaceName: "Ethernet", ip: "192.168.1.5" }), "home");
});

test("service failures are localized with actionable Ubuntu guidance in CZ and EN", () => {
  const cases = {
    unavailable: /Exportovat diagnostiku|Export diagnostics/,
    permission_denied: /homeproxy-admin/,
    version_mismatch: /(verze|version)/i,
    conflict: /(Zahodit změny|Discard changes)/,
    revision_required: /(Zahodit změny|Discard changes)/,
    applied_refresh_failed: /(byla použita|was applied)[\s\S]*(neopakujte|do not repeat)/,
    timeout: /(neodpověděla|did not answer)/,
    unsafe_socket: /(oprávnění|permissions)/,
    inspection_unsupported: /(tunel|tunnel)/,
    listener_in_use: /port/i,
    listener_access_denied: /1023/,
    listener_address_unavailable: /(adresa|address)/,
    listener_start_failed: /(diagnostice|diagnostics)/,
  };
  for (const [code, pattern] of Object.entries(cases)) {
    for (const locale of ["cs", "en"]) {
      const text = translateServiceError(`HOMEPROXY_SERVICE:${code}:raw daemon text`, locale, "linux");
      assert.match(text, pattern, `${locale}/${code}`);
      assert.doesNotMatch(text, /HOMEPROXY_SERVICE|raw daemon text/);
    }
  }
  assert.equal(translateServiceError("Proxy nelze otevřít: x", "cs", "linux"), null);
  assert.match(translateServiceError("HOMEPROXY_SERVICE:invalid_config:Port is invalid", "en", "linux"), /Port is invalid/);
  assert.match(translateServiceError("HOMEPROXY_SERVICE:strange:boom", "en", "linux"), /strange.*boom/);
  assert.equal(isServiceConflict("HOMEPROXY_SERVICE:conflict:x"), true);
  assert.equal(isServiceConflict("HOMEPROXY_SERVICE:busy:x"), false);
});

test("the conflict message keeps the draft and tells the user how to reload", () => {
  for (const locale of ["cs", "en"]) {
    const text = translateServiceError("HOMEPROXY_SERVICE:conflict:x", locale, "linux");
    assert.match(text, /(zůstávají v návrhu|stay in the draft)/);
  }
});

test("Ubuntu copy replaces Windows-only advice while Windows copy is preserved", () => {
  for (const locale of ["cs", "en"]) {
    const windows = createTranslator(locale);
    const linux = createTranslator(locale, "linux");
    for (const key of ["stoppedExplanation", "step1Copy", "useHomeProxyTitle", "hostProxyNoteCopy", "port80Warning", "privateNetworkOnly", "dnsSystemCopy", "secondDeviceCopy", "pagesSlowCopy"]) {
      assert.doesNotMatch(linux(key), /Windows|UAC|Start\b|Mobil|Mobile/, `${locale}/${key}`);
    }
    assert.match(windows("step1Copy"), /Windows/);
    assert.match(windows("hostProxyNoteCopy"), /Windows/);
    assert.match(linux("hostProxyNoteCopy"), /Ubuntu/);
    assert.match(linux("stoppedExplanation"), /Ubuntu/);
    assert.match(linux("step1Copy"), /(nevypne|does not stop)/);
    assert.match(windows("httpsInspectCopy"), /(certifikát|certificate)/);
  }
});

test("Ubuntu explains selective HTTPS inspection with client trust and privacy boundaries", () => {
  for (const locale of ["cs", "en"]) {
    const linux = createTranslator(locale, "linux");
    assert.doesNotMatch(linux("httpsInspect"), /(nedostupné|unavailable)/);
    assert.match(linux("httpsInspectCopy"), /(certifik|certificate)/);
    assert.match(linux("tlsInstallHelp"), /(klíč|key)/);
    assert.match(linux("sharedCacheCopy"), /HTTPS/);
    assert.match(linux("sharedCacheCopy"), /(cookies)/);
  }
});

test("Linux UI uses service inspection capability while keeping tray and hotspot hidden", () => {
  assert.match(main, /option\.disabled = !inspectionSupported\(\)/);
  assert.match(main, /id="hide-to-tray"[^>]*\$\{isLinux \? " hidden" : ""\}/);
  assert.match(main, /connection-choice is-amber"\$\{isLinux \? " hidden" : ""\}/);
  assert.match(main, /function inspectionSupported\(\): boolean \{\s*return snapshot\?\.supportsHttpsInspection \?\? !isLinux;/);
  assert.match(main, /const inspecting = inspectionSupported\(\) && /);
});

test("saves pass the revision the draft was cloned from, never a freshly fetched one", () => {
  assert.match(main, /invoke<AppSnapshot>\("apply_settings", \{ settings: draft, expectedRevision: draftRevision \}\)/);
  assert.match(main, /const revisionAtPrepare = draftRevision;/);
  assert.match(main, /expectedRevision: revisionAtPrepare,/);
  assert.match(main, /draftRevision = next\.revision;/);
  const save = main.split("async function applyDirtyDraft")[1].split("\nlanCheckbox.addEventListener")[0];
  assert.ok(!save.includes("get_snapshot"), "save must not fetch a fresh revision");
});

test("a refresh started before a successful save cannot overwrite the saved state", async () => {
  const refreshBody = main.split("async function refresh(): Promise<void> {")[1].split("\n}\n")[0].replace("invoke<AppSnapshot>", "invoke");
  const runBusyBody = main.split("async function runBusy(action: () => Promise<void>): Promise<void> {")[1].split("\n}\n\nasync function copyText")[0];
  for (const mutate of [true, false]) {
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    const harness = new Function("load", `
      let snapshot = { revision: "old" }, busy = false, refreshing = false, activitySnapshotGeneration = 0;
      const loadSnapshotWhenReady = load;
      const refreshTlsStatus = async () => {};
      const invoke = async () => {};
      const syncFromSnapshot = next => { snapshot = next; };
      const render = () => {};
      const showNotice = () => {};
      const translateBackendMessage = message => message;
      const locale = "en";
      const byId = () => ({ dataset: {} });
      async function runBusy(action) {${runBusyBody}}
      return {
        refresh: async () => {${refreshBody}},
        save: () => runBusy(async () => { syncFromSnapshot({ revision: "saved" }); }),
        read: () => snapshot,
      };
    `)(() => pending);
    const stale = harness.refresh();
    if (mutate) await harness.save();
    release({ revision: "stale" });
    await stale;
    assert.equal(harness.read().revision, mutate ? "saved" : "stale");
  }
});

test("Linux backend is a thin service client: no Engine, no daemon start, no tray", () => {
  assert.doesNotMatch(linuxRust, /Engine|TrayIcon|systemctl|Command::new/);
  assert.match(linuxRust, /FilterFeed::parse/);
  assert.match(linuxRust, /call\(socket, command\)/);
  assert.match(linuxRust, /Command::DesktopSnapshot/);
  assert.match(linuxRust, /default_socket\(\)/);
  assert.match(linuxRust, /require_revision/);
  assert.match(libRust, /#\[cfg\(target_os = "linux"\)\]\s*\{[\s\S]*linux::run\(\);/);
  assert.match(libRust, /#\[cfg\(not\(target_os = "linux"\)\)\]\s*embedded::run\(\);/);
  for (const name of ["get_snapshot", "set_running", "apply_settings", "configure_lan_and_start", "rotate_proxy_password", "set_device_allowed", "clear_cache", "clear_activity", "reset_transfer_stats", "hide_to_tray"]) {
    assert.match(linuxRust, new RegExp(`fn ${name}\\(`), name);
  }
});

test("Linux bundle config targets a deb that depends on the matching service package", () => {
  assert.deepEqual(linuxConfig.bundle.targets, ["deb"]);
  assert.equal(linuxConfig.bundle.category, "Utility");
  assert.match(linuxConfig.bundle.longDescription, /Ubuntu/);
  assert.deepEqual(linuxConfig.bundle.linux.deb.depends, [`homeproxy (= ${tauriConfig.version})`]);
});

test("launcher, GTK application and X11 window share the existing app identity", () => {
  assert.equal(linuxConfig.app.enableGTKAppId, true);
  assert.equal(linuxConfig.bundle.linux.deb.desktopTemplate, "linux/homeproxy.desktop");
  assert.ok(desktopTemplate.includes(`StartupWMClass=${tauriConfig.identifier}\n`));
  assert.ok(libRust.includes(`gtk::gdk::set_program_class("${tauriConfig.identifier}");`));
  assert.ok(libRust.indexOf("gtk::init()") < libRust.indexOf("gtk::gdk::set_program_class"));
  assert.ok(libRust.indexOf("gtk::gdk::set_program_class") < libRust.indexOf("linux::run()"));
});

test("desktop icons and web favicon reuse the existing HomeProxy artwork", async () => {
  for (const file of ["icon.png", "32x32.png", "64x64.png", "128x128.png", "128x128@2x.png", "icon.ico", "icon.icns"]) {
    assert.ok(tauriConfig.bundle.icon.includes(`icons/${file}`), file);
    assert.ok((await readFile(new URL(`../src-tauri/icons/${file}`, import.meta.url))).length > 0);
  }
  assert.match(await read("../index.html"), /<link rel="icon" type="image\/png" href="\/favicon\.png"/);
  assert.deepEqual(await readFile(new URL("../public/favicon.png", import.meta.url)), await readFile(new URL("../src-tauri/icons/32x32.png", import.meta.url)));
});

test("final DEB validation rejects missing icons and launcher identity regressions", { skip: process.platform !== "linux" }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), "homeproxy-icon-test-"));
  const stage = join(temporary, "stage");
  const run = (command, args, input) => spawnSync(command, args, { cwd: repoRoot, input, encoding: "utf8" });
  const normalize = desktopBuild.match(/python3 - "\$package_stage" <<'PY'\n([\s\S]*?)\nPY/)[1];
  const validate = desktopBuild.match(/python3 - "\$built_package" <<'PY'\n([\s\S]*?)\nPY/)[1];
  try {
    await mkdir(join(stage, "DEBIAN"), { recursive: true });
    await writeFile(join(stage, "DEBIAN/control"), "Package: homeproxy-desktop\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: HomeProxy\nDescription: Icon regression fixture\n");
    await mkdir(join(stage, "usr/bin"), { recursive: true });
    await writeFile(join(stage, "usr/bin/klidna-sit"), "#!/bin/sh\nexit 0\n");
    await chmod(join(stage, "usr/bin/klidna-sit"), 0o755);
    await mkdir(join(stage, "usr/share/applications"), { recursive: true });
    const entry = desktopTemplate.replace("{{comment}}", "HomeProxy").replace("{{exec}}", "klidna-sit").replace("{{icon}}", "klidna-sit").replace("{{categories}}", "Utility;");
    const original = join(stage, "usr/share/applications", `${linuxConfig.productName}.desktop`);
    const launcher = join(stage, "usr/share/applications", `${tauriConfig.identifier}.desktop`);
    await writeFile(original, entry);
    await writeFile(join(stage, "DEBIAN/md5sums"), "stale integrity metadata\n");
    const normalized = run("python3", ["-", stage], normalize);
    assert.equal(normalized.status, 0, normalized.stderr);
    assert.equal(await readFile(launcher, "utf8"), entry);
    const checksum = createHash("md5").update(entry).digest("hex");
    assert.ok((await readFile(join(stage, "DEBIAN/md5sums"), "utf8")).includes(`${checksum}  usr/share/applications/${tauriConfig.identifier}.desktop\n`));
    const icons = new Map();
    for (const size of [32, 64, 128, 512]) {
      const destination = join(stage, `usr/share/icons/hicolor/${size}x${size}/apps/klidna-sit.png`);
      await mkdir(join(destination, ".."), { recursive: true });
      await copyFile(join(repoRoot, `src-tauri/icons/${size === 512 ? "icon" : `${size}x${size}`}.png`), destination);
      icons.set(size, destination);
    }
    const archive = join(temporary, "desktop.deb");
    const check = () => {
      const built = run("dpkg-deb", ["--build", "--root-owner-group", stage, archive]);
      assert.equal(built.status, 0, built.stderr);
      return run("python3", ["-", archive], validate);
    };
    assert.equal(check().status, 0);
    const icon = icons.get(128);
    const png = await readFile(icon);
    await rm(icon);
    assert.match(check().stderr, /missing its 128px launcher icon/);
    await writeFile(icon, "not a PNG");
    assert.match(check().stderr, /invalid 128px launcher icon/);
    await writeFile(icon, Buffer.concat([png, Buffer.from("outdated artwork")]));
    assert.match(check().stderr, /current 128px artwork/);
    await writeFile(icon, png);
    for (const [oldText, newText, error] of [
      [`StartupWMClass=${tauriConfig.identifier}`, "StartupWMClass=unrelated", /native window identity/],
      ["Icon=klidna-sit", "Icon=missing", /missing its 32px launcher icon/],
      ["Exec=klidna-sit", "Exec=missing", /packaged executable/],
    ]) {
      await writeFile(launcher, entry.replace(oldText, newText));
      assert.match(check().stderr, error);
    }
    await writeFile(launcher, entry);
    await writeFile(original, entry);
    assert.match(check().stderr, /exactly the GTK-identity launcher/);
    await rm(original);
    await rename(launcher, original);
    assert.match(check().stderr, /exactly the GTK-identity launcher/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
