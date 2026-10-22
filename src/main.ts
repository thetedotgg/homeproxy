import { invoke } from "@tauri-apps/api/core";
import { cacheBypassReasonLabel, createTranslator, persistLocale, resolveLocale, translateBackendMessage as translateCoreMessage, translateActivityValue, translateServiceError, type Locale } from "./i18n";
import {
  availableGuideSelection as availableGuideSelectionFor,
  canLimitDevice,
  selectedGuideEndpoint,
  MAX_DEVICE_LIMIT_KIB,
  parseDeviceLimitKib,
  classifyLanAddress as classifyLanAddressFor,
  connectionVerified,
  guideLanAddresses as guideLanAddressesFor,
  recommendedLanAddress as recommendedLanAddressFor,
  type ConnectionMode,
  type LanAddress,
  type LanAddressKind,
} from "./setup";
import {
  CACHE_BOUNDS,
  CACHE_FIELDS,
  cacheFieldsWithErrors,
  cacheProfileLabel,
  cacheSettingsDiffer,
  cacheUsageState,
  savingsStatus,
  topCacheBypassReasons,
  parseCacheInteger,
  validateCacheInputs,
  type CacheField,
  type CacheRawInput,
  type CacheSnapshotInfo,
  type CacheValidation,
} from "./cache-controls";
import { detectHostPlatform, loadSnapshotWhenReady } from "./snapshot";
import { parseHostRules, showInspectHostEditor, validateOfflineInputs, type OfflineSettings, type OfflineRaw } from "./offline-controls";
import {createProfile,renderProfileEditors,validProfiles,type PolicySettings} from "./profile-controls";
import {preparationInput,preparationReason,escapePreparationText,updatePreparationJobs,type PreparationStatus,type PreparationJobRenderState} from "./offline-preparation";
import {
  DEFAULT_PROXY_PORT,
  DEFAULT_SOCKS5_PORT,
  parseServicePort,
  serviceEndpoint,
  validateServicePorts,
  type ServicePortError,
} from "./service-ports";
import qrcode from "qrcode-generator";
import {
  phoneSetupSignature,
  phoneSetupState,
  qrModulePath,
  type PhoneSetupBlocker,
  type PhoneSetupState,
} from "./device-setup";
import { diagnosticStateKey, parseDiagnosticsStatus, parseDiagnosticExport, diagnosticExportErrorKey,
  type DiagnosticsStatus, type DiagnosticExport } from "./diagnostics";
import { aboutVersions, PROJECT_SOURCE, PROJECT_WEBSITE } from "./about";
import "./styles.css";

type AdblockMode = "off" | "mild" | "strict";
type CompressionPreset = "off" | "sharper" | "balanced" | "maximum";

interface Settings extends OfflineSettings, PolicySettings {
  filterFeeds:{id:string;name:string;domainsSortedExact:string[];domainsSortedWildcard:string[]}[];
  pacEnabled:boolean;pacDirectFallback:boolean;
  upstreamProxies:{host:string;port:number;username:string|null;password:string|null}[];
  upstreamDirectFallback:boolean;
  lanDnsEnabled:boolean;lanDnsPort:number;lanDnsUpstream:string;
  version: number;
  enabled: boolean;
  automaticRecovery: boolean;
  lanEnabled: boolean;
  listenIp: string | null;
  listenIps: string[];
  deviceLimits: DeviceLimit[];
  proxyPort: number;
  socks5Enabled: boolean;
  socks5UdpEnabled: boolean;
  socks5Port: number;
  lanAuthEnabled: boolean;
  proxyUsername: string;
  proxyPassword: string;
  deniedClientIps: string[];
  adblockMode: AdblockMode;
  compressionPreset: CompressionPreset;
  httpsMode: "tunnel" | "inspect";
  dnsMode: "system" | "cloudflare";
  cacheEnabled: boolean;
  cacheLimitGib: number;
  cacheMaxObjectMib: number;
  responseBufferLimitMib: number;
  responseBufferBudgetMib: number;
}

interface DeviceLimit {
  ip: string;
  uploadBytesPerSecond: number;
  downloadBytesPerSecond: number;
}
interface Activity {
  id: number; peerIp: string; listenerIp: string; host: string; protocol: string;
  startedUnixMs: number; endedUnixMs: number | null; status: string;
  uploadBytes: number; downloadBytes: number; uploadBytesPerSecond: number; downloadBytesPerSecond: number;
  error: string | null; cacheStatus: string; cacheBypassReason: string | null;
  originBytes: number; deliveredBytes: number;
}
interface ConnectionRejection {
  peerIp: string;
  listenerIp: string;
  unixMs: number;
  reason: "peer-limit" | "global-limit";
  limit: number;
}
interface Stats {
  transferStatsResetUnixMs?: number | null;
  rejectedConnections?: number;
  latestConnectionRejection?: ConnectionRejection | null;
  uploadBytes: number;
  downloadBytes: number;
  uploadBytesPerSecond: number;
  downloadBytesPerSecond: number;
  originBytes: number;
  deliveredBytes: number;
  cacheMisses: number;
  cacheBypasses: number;
  /** Additive fields; older services omit them. */
  cacheBypassReasons?: Record<string, number>;
  inspectionFailOpenRemembered?: number;
  activity: Activity[];
  totalRequests: number;
  blockedRequests: number;
  cacheHits: number;
  cacheBytesSaved: number;
  compressedImages: number;
  compressionBytesSaved: number;
  connectTunnels: number;
  socks5Connections: number;
  authenticatedExternalRequests: number;
  successfulExternalRequests: number;
  uniqueClients: number;
  clients: Array<{
    ip: string;
    lastSeenUnixMs: number;
    uploadBytes: number; downloadBytes: number; uploadBytesPerSecond: number; downloadBytesPerSecond: number;
  }>;
  savedBytes: number;
}

interface ListenerBindFailure {
  service: "http" | "socks5" | "dns";
  endpoint: string;
  reason: "inUse" | "accessDenied" | "addressUnavailable" | "other";
}

interface AppSnapshot {
  offlinePreparation?: PreparationStatus;
  quotaStatuses?:{profileId:string;dailyBytes:number;monthlyBytes:number;dailyQuotaMib:number;monthlyQuotaMib:number;warningPercent:number;warning:boolean;blocked:boolean;historyHealthy:boolean}[];
  running: boolean;
  settings: Settings;
  stats: Stats;
  availableAddresses: LanAddress[];
  proxyAddresses: string[];
  socks5Addresses: string[];
  lastError: string | null;
  cache?: CacheSnapshotInfo;
  listenerError: ListenerBindFailure | null;
  tlsInspectionReady: boolean;
  /** Linux service only: optimistic-concurrency token echoed back as expectedRevision. */
  revision?: string;
  platform?: "linux";
  serviceVersion?: string;
  supportsHttpsInspection?: boolean;
  httpsAuthority?: { capability: boolean; prepared: boolean; sha256Fingerprint?: string | null };
}

const locale = resolveLocale();
const hostPlatform = detectHostPlatform(navigator.userAgent);
const isLinux = hostPlatform === "linux";
const t = createTranslator(locale, hostPlatform);
// Linux service failures arrive as coded strings; everything else is a core message.
const translateBackendMessage = (message: string, messageLocale: Locale): string =>
  translateServiceError(message, messageLocale, hostPlatform) ?? translateCoreMessage(message, messageLocale);
const classifyLanAddress = (address: LanAddress) => classifyLanAddressFor(address, hostPlatform);
const recommendedLanAddress = (addresses: readonly LanAddress[], mode: ConnectionMode) => recommendedLanAddressFor(addresses, mode, hostPlatform);
const guideLanAddresses = (addresses: readonly LanAddress[], mode: ConnectionMode) => guideLanAddressesFor(addresses, mode, hostPlatform);
const availableGuideSelection = (addresses: readonly LanAddress[], selectedIp: string | null, mode: ConnectionMode) => availableGuideSelectionFor(addresses, selectedIp, mode, hostPlatform);
const numberLocale = locale === "cs" ? "cs-CZ" : "en-US";

document.documentElement.lang = locale;
document.title = t("documentTitle");

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error(t("rootMissing"));

app.innerHTML = `
  <div class="app-shell">
    <header class="topbar">
      <div class="brand" aria-label="${t("brandAria")}">
        <span class="brand-mark" aria-hidden="true"></span>
        <span>${t("brand")}</span>
      </div>
      <nav class="nav" aria-label="${t("navAria")}">
        <button class="nav-link is-active" type="button" data-page="home">${t("navHome")}</button>
        <button class="nav-link" type="button" data-page="settings">${t("navSettings")}</button>
        <button class="nav-link" type="button" data-page="guide">${t("navGuide")}</button>
      </nav>
      <div class="locale-switch" role="group" aria-label="${t("languageAria")}">
        <button type="button" data-locale="cs" aria-label="${t("switchToCzech")}" aria-pressed="${locale === "cs"}">CZ</button>
        <button type="button" data-locale="en" aria-label="${t("switchToEnglish")}" aria-pressed="${locale === "en"}">EN</button>
      </div>
      <button id="hide-to-tray" class="text-action" type="button" title="${t("trayHint")}"${isLinux ? " hidden" : ""}>${t("hideToTray")}</button>
      <button id="service-toggle" class="service-toggle" type="button" aria-pressed="false">
        <span class="status-dot" aria-hidden="true"></span>
        <span id="service-label">${t("loading")}</span>
      </button>
    </header>

    <div id="notice" class="notice" role="status" aria-live="polite" hidden></div>

    <main id="home-page" class="page is-active">
      <section class="traffic-summary" aria-labelledby="traffic-title">
        <div class="traffic-heading"><h2 id="traffic-title">${t("trafficTitle")}</h2><small id="traffic-period">${t("trafficSinceStart")}</small></div>
        <p><span>↑ ${t("upload")}</span><strong id="upload-total">0 B</strong><small id="upload-rate">0 B/s</small></p>
        <p><span>↓ ${t("download")}</span><strong id="download-total">0 B</strong><small id="download-rate">0 B/s</small></p>
        <button id="traffic-reset" class="traffic-reset" type="button" title="${t("trafficResetLabel")}" aria-label="${t("trafficResetLabel")}" aria-expanded="false" aria-controls="traffic-reset-confirmation" disabled>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 10a9 9 0 1 1 2.7 8.4M3 4v6h6"/></svg>
        </button>
        <div id="traffic-reset-confirmation" class="traffic-reset-confirmation" role="group" aria-labelledby="traffic-reset-question" hidden>
          <div><b id="traffic-reset-question">${t("trafficResetQuestion")}</b><small>${t("trafficResetHelp")}</small></div>
          <button id="traffic-reset-cancel" class="secondary-button" type="button">${t("trafficResetCancel")}</button>
          <button id="traffic-reset-confirm" class="secondary-button traffic-reset-confirm" type="button">${t("trafficResetConfirm")}</button>
        </div>
        <div id="connection-rejections" class="connection-rejections" role="status" hidden>
          <span id="connection-rejection-total"></span>
          <small id="connection-rejection-latest"></small>
        </div>
      </section>
      <div class="hero-grid">
        <section class="savings" aria-labelledby="savings-title">
          <p class="eyebrow" id="savings-title">${t("savedEyebrow")}</p>
          <p class="saving-number" id="saved-total">0 <em>B</em></p>
          <p class="hero-copy" id="hero-copy">${t("savedExplanation")}</p>
          <p class="fine-print" id="savings-status" role="status"></p>

          <div class="metric-list" aria-label="${t("layersAria")}">
            <div class="metric-row">
              <span class="metric-icon ads" aria-hidden="true"></span>
              <span><strong>${t("adHosts")}</strong><small>${t("insideProxy")}</small></span>
              <b id="blocked-count">0 ${t("blockedSuffix")}</b>
            </div>
            <div class="metric-row">
              <span class="metric-icon images" aria-hidden="true"></span>
              <span><strong>${t("images")}</strong><small>${t("originalFallback")}</small></span>
              <b id="image-saving">0 B</b>
            </div>
            <div class="metric-row">
              <span class="metric-icon cache" aria-hidden="true"></span>
              <span><strong>${t("publicCache")}</strong><small>${t("noCookies")}</small></span>
              <b id="cache-saving">0 B</b>
            </div>
          </div>
        </section>

        <aside class="panel live-panel" aria-labelledby="live-title">
          <p class="eyebrow">${t("firstVertical")}</p>
          <h1 id="live-title">${t("runningTitle")}</h1>
          <dl class="profile-list">
            <div><dt>${t("ads")}</dt><dd id="profile-ads">${t("mild")}</dd></div>
            <div><dt>${t("images")}</dt><dd id="profile-images">${t("savings")}</dd></div>
            <div><dt>${t("cache")}</dt><dd id="profile-cache">${t("publicWithSize", { size: 8 })}</dd></div>
          </dl>

          <div class="proxy-card">
            <span>${t("deviceAddress")}</span>
            <strong id="proxy-address">${t("turnOnFirst")}</strong>
            <button id="copy-address" class="text-action" type="button" disabled>${t("copyAddress")}</button>
          </div>
          <p id="https-summary" class="fine-print">${t("httpsTunnelCopy")}</p>
        </aside>
      </div>

      <section id="diagnostics-card" class="panel diagnostics-card" aria-labelledby="diagnostics-title">
        <div class="diagnostics-heading">
          <div><h2 id="diagnostics-title">${t("diagnosticsTitle")}</h2><p class="field-help">${t("diagnosticsBoundary")}</p></div>
          <button id="export-diagnostics" class="primary-button" type="button">${t("diagnosticsExport")}</button>
        </div>
        <p class="field-help">${t("diagnosticsPrivacy")}</p>
        <div class="diagnostics-health">
          <strong>${t("diagnosticsLocalLabel")}</strong>
          <span id="diagnostics-health-state" class="diagnostics-state" role="status" aria-live="polite">${t("diagnosticsLoading")}</span>
        </div>
        <div id="diagnostics-details" class="diagnostics-details" hidden>
          <span id="diagnostics-recovery-count"></span><span id="diagnostics-last-incident"></span><span id="diagnostics-storage"></span>
        </div>
        <label class="switch-row" for="automatic-recovery">
          <span><strong>${t("diagnosticsRecovery")}</strong><small>${t("diagnosticsRecoveryHelp")}</small></span>
          <input id="automatic-recovery" type="checkbox" disabled />
          <span class="switch" aria-hidden="true"></span>
        </label>
        <div class="diagnostics-setting-status"><p id="diagnostics-recovery-pending" class="field-help" role="status">${t("diagnosticsRecoveryUnavailable")}</p><button id="diagnostics-save-settings" class="secondary-button" type="button" hidden>${t("saveChanges")}</button></div>
        <p id="diagnostics-export-result" class="field-help" role="status" aria-live="polite" hidden></p>
        <div id="diagnostics-saved-file" hidden><label class="field-label" for="diagnostics-export-path">${t("diagnosticsPath")}</label><textarea id="diagnostics-export-path" class="text-area diagnostics-export-path" rows="2" readonly spellcheck="false"></textarea></div>
      </section>

      <div class="household-row">
        <span class="house-chip">${t("devicesSinceStart")}: <b id="client-count">0</b></span>
        <span class="house-chip">${t("requests")}: <b id="request-count">0</b></span>
        <span class="house-chip warning">${t("hostAwake")}</span>
      </div>

      <section class="traffic-panel" aria-labelledby="traffic-title">
        <h2>${t("optimizationEvidence")}</h2>
        <p class="field-help">${t("trafficCopy")}</p>
        <p id="body-evidence" class="field-help"></p>
        <p id="cache-evidence" class="field-help"></p>
        <p id="cache-bypass-reasons" class="field-help" hidden></p>
        <p class="field-help">${t("optimizationBoundary")}</p>
      </section>
      <section class="traffic-panel" aria-labelledby="activity-title">
        <h2 id="activity-title">${t("activityTitle")}</h2>
        <p class="field-help">${t("activityCopy")}</p>
        <div class="activity-controls"><label>${t("activityFilter")} <input id="activity-filter" type="search" class="text-field" /></label><button id="activity-reset-filter" class="secondary-button" type="button" hidden>${t("clearFilter")}</button><button id="activity-pause" class="secondary-button" type="button" aria-pressed="false">${t("pauseActivity")}</button><button id="activity-clear" class="secondary-button" type="button">${t("clearActivity")}</button></div>
        <div id="activity-list" class="activity-list"></div>
      </section>
      <button id="home-guide" class="guide-invite" type="button">
        <span class="guide-invite-mark" aria-hidden="true">?</span>
        <span><strong>${t("firstTime")}</strong><small>${t("guideInvite")}</small></span>
        <span class="guide-invite-action">${t("openGuide")}</span>
      </button>
    </main>

    <main id="settings-page" class="page settings-page">
      <div class="settings-heading">
        <div>
          <p class="eyebrow">${t("settingsEyebrow")}</p>
          <h1>${t("settingsTitle")}</h1>
          <p class="lead">${t("settingsLead")}</p>
        </div>

      </div>

      <section class="settings-section" aria-labelledby="network-title">
        <div class="section-copy">
          <h2 id="network-title">${t("householdDevices")}</h2>
          <p>${t("householdDevicesCopy")}</p>
        </div>
        <div class="section-control stacked-control">
          <label class="switch-row" for="lan-enabled">
            <span><strong>${t("allowDevices")}</strong><small>${t("privateNetworkOnly")}</small></span>
            <input id="lan-enabled" type="checkbox" />
            <span class="switch" aria-hidden="true"></span>
          </label>
          <label class="field-label" for="listen-ip">${t("hostAddress")}</label>
          <select id="listen-ip" class="select-field" multiple size="4"></select>
          <p class="field-help">${t("multiLanCopy")}</p>
          <p class="field-help"${isLinux ? " hidden" : ""}>${t("hotspotAddressHelp")}</p>
        </div>
      </section>

      <section class="settings-section" aria-labelledby="service-ports-title">
        <div class="section-copy">
          <h2 id="service-ports-title">${t("servicePortsTitle")}</h2>
          <p>${t("servicePortsCopy")}</p>
        </div>
        <div class="section-control stacked-control service-port-controls">
          <label class="field-label" for="proxy-port">${t("httpProxyPort")}</label>
          <input id="proxy-port" class="number-field" type="number" min="1" max="65535" inputmode="numeric" />
          <div class="port-presets" role="group" aria-label="${t("proxyPortPresetsAria")}">
            <button type="button" data-proxy-port-preset="80">80</button>
            <button type="button" data-proxy-port-preset="3128">3128</button>
            <button type="button" data-proxy-port-preset="17891">17891</button>
          </div>
          <p id="port-80-warning" class="field-help access-warning" hidden>${t("port80Warning")}</p>

          <label class="switch-row" for="socks5-enabled">
            <span><strong>${t("socks5Service")}</strong><small>${t("socks5ServiceHelp")}</small></span>
            <input id="socks5-enabled" type="checkbox" />
            <span class="switch" aria-hidden="true"></span>
          </label>
          <label class="switch-row" for="socks5-udp-enabled">
            <span><strong>${t("socks5UdpTitle")}</strong><small>${t("socks5UdpHelp")}</small></span>
            <input id="socks5-udp-enabled" type="checkbox" />
            <span class="switch" aria-hidden="true"></span>
          </label>
          <label class="field-label" for="socks5-port">${t("socks5Port")}</label>
          <input id="socks5-port" class="number-field" type="number" min="1" max="65535" inputmode="numeric" />
          <p class="field-help">${t("socks5CredentialWarning")}</p>
          <p id="service-port-error" class="setup-inline-state" data-state="error" role="status"></p>
          <p id="service-restart-note" class="field-help" hidden>${t("serviceRestartNote")}</p>
          <div class="service-endpoint-list" aria-live="polite">
            <p id="endpoint-state" class="field-help"></p>
            <p id="active-endpoints" class="field-help"></p>
            <div><span>${t("httpEndpoint")}</span><code id="http-endpoint-preview">127.0.0.1:${DEFAULT_PROXY_PORT}</code><button id="copy-http-endpoint" type="button">${t("copy")}</button></div>
            <div id="socks5-endpoint-row"><span>${t("socks5Endpoint")}</span><code id="socks5-endpoint-preview">127.0.0.1:${DEFAULT_SOCKS5_PORT}</code><button id="copy-socks5-endpoint" type="button">${t("copy")}</button></div>
          </div>
          <p id="socks5-connection-count" class="field-help"></p>
        </div>
      </section>

      <section class="settings-section" aria-labelledby="access-title">
        <div class="section-copy">
          <h2 id="access-title">${t("deviceAccess")}</h2>
          <p>${t("deviceAccessCopy")}</p>
        </div>
        <div class="section-control credential-grid">
          <label class="switch-row" for="lan-auth-enabled">
            <span><strong>${t("requireLanLogin")}</strong><small>${t("requireLanLoginHelp")}</small></span>
            <input id="lan-auth-enabled" type="checkbox" />
            <span class="switch" aria-hidden="true"></span>
          </label>
          <p id="open-lan-warning" class="access-warning" role="status" hidden>${t("openLanWarning")}</p>
          <label class="field-label" for="proxy-user">${t("username")}</label>
          <div class="copy-field"><input id="proxy-user" maxlength="32" autocomplete="off" spellcheck="false" /><button type="button" data-copy="proxy-user">${t("copy")}</button></div>
          <label class="field-label" for="proxy-password">${t("accessKey")}</label>
          <div class="copy-field"><input id="proxy-password" type="password" maxlength="128" autocomplete="new-password" spellcheck="false" /><button id="reveal-password" type="button">${t("show")}</button><button type="button" data-copy="proxy-password">${t("copy")}</button></div>
          <p class="field-help">${t("credentialRules")}</p>
          <button id="rotate-password" class="secondary-button" type="button">${t("newKey")}</button>
        </div>
      </section>

      <section class="settings-section" aria-labelledby="known-devices-title">
        <div class="section-copy">
          <h2 id="known-devices-title">${t("knownDevicesTitle")}</h2>
          <p>${t("knownDevicesCopy")}</p>
        </div>
        <div id="device-list" class="device-list" aria-live="polite"></div>
      </section>

      <section class="settings-section" aria-labelledby="https-mode-title">
        <div class="section-copy"><h2 id="https-mode-title">${t("httpsModeTitle")}</h2><p>${t("httpsModeCopy")}</p></div>
        <div class="section-control stacked-control">
          <label class="field-label" for="https-mode">${t("httpsModeTitle")}</label>
          <select id="https-mode" class="select-field"><option value="tunnel">${t("httpsTunnel")}</option><option value="inspect"${isLinux ? " disabled" : ""}>${t("httpsInspect")}</option></select>
          <p id="https-inspect-unavailable" class="field-help" role="note"${isLinux ? "" : " hidden"}>${t("httpsInspectUnavailable")}</p>
          <p id="https-mode-help" class="field-help"></p>
          <div class="certificate-setup">
            <p id="tls-authority-state" class="field-help" aria-live="polite">${t("tlsNotPrepared")}</p>
            <p id="tls-fingerprint" class="certificate-fingerprint"></p>
            <div class="button-row"><button id="prepare-tls" class="secondary-button" type="button">${t("tlsPrepare")}</button><button id="export-tls" class="secondary-button" type="button">${t("tlsExport")}</button></div>
            <p class="field-help">${t("tlsInstallHelp")}</p>
            <button id="open-phone-setup" class="text-action device-setup-link-button" type="button">${t("settingsDeviceSetupLink")} →</button>
          </div>
          <label class="field-label" for="https-inspection-scope">${t("httpsScopeTitle")}</label>
          <select id="https-inspection-scope" class="select-field" aria-describedby="https-scope-help"><option value="selectedHosts">${t("httpsScopeSelected")}</option><option value="allSupportedHosts">${t("httpsScopeAll")}</option></select>
          <p id="https-scope-help" class="field-help"></p>
          <div id="https-selected-hosts" class="stacked-control">
          <label class="field-label" for="https-inspect-hosts">${t("inspectHosts")}</label>
          <textarea id="https-inspect-hosts" class="text-area" spellcheck="false" placeholder="example.org\n*.example.org" aria-describedby="inspect-hosts-help offline-settings-error"></textarea>
          <small id="inspect-hosts-help" class="field-help">${t("inspectHostsHelp")}</small>
          </div>
          <label class="field-label" for="https-bypass-hosts">${t("bypassHosts")}</label>
          <textarea id="https-bypass-hosts" class="text-area" spellcheck="false" aria-describedby="offline-settings-error"></textarea>
          <label class="check-row" for="https-trust-ack"><input id="https-trust-ack" type="checkbox" /><span>${t("tlsTrustAck")}</span></label>
          <label class="field-label" for="dns-mode">${t("dnsModeTitle")}</label>
          <select id="dns-mode" class="select-field"><option value="system">${t("dnsSystem")}</option><option value="cloudflare">${t("dnsCloudflare")}</option></select>
          <p id="dns-mode-help" class="field-help"></p>
          <p class="field-help">${t("dnsClientBoundary")}</p>
          <p class="field-help">${t("httpsRestart")}</p>
        </div>
      </section>
      <section class="settings-section" aria-labelledby="offline-title">
        <div class="section-copy"><h2 id="offline-title">${t("offlineTitle")}</h2><p>${t("offlineCopy")}</p></div>
        <div class="section-control stacked-control">
          <label class="field-label" for="cache-mode">${t("offlineModeLabel")}</label>
          <select id="cache-mode" class="select-field"><option value="online">${t("cacheOnline")}</option><option value="offline">${t("cacheOffline")}</option></select>
          <p id="offline-mode-note" class="field-help" role="note"></p>
          <label class="field-label" for="offline-stale-hours">${t("offlineStaleHours")}</label>
          <input id="offline-stale-hours" class="number-field" type="text" inputmode="numeric" aria-describedby="offline-stale-help offline-settings-error" />
          <small id="offline-stale-help" class="field-help">${t("offlineStaleHelp")}</small>
          <label class="field-label" for="public-cache-endpoints">${t("publicEndpoints")}</label>
          <textarea id="public-cache-endpoints" class="text-area" spellcheck="false" placeholder="example.org/docs/\ncdn.example.org/assets/" aria-describedby="public-endpoints-help offline-settings-error"></textarea>
          <small id="public-endpoints-help" class="field-help">${t("publicEndpointsHelp")}</small>
          <p id="offline-settings-error" class="field-error" role="status" aria-live="polite"></p>
        </div>
      </section>
      <section class="settings-section preparation-section" aria-labelledby="preparation-title">
        <div class="section-copy"><h2 id="preparation-title">${t("preparationTitle")}</h2><p>${t("preparationCopy")}</p></div>
        <div class="section-control stacked-control">
          <label class="field-label" for="preparation-urls">${t("preparationUrls")}</label>
          <textarea id="preparation-urls" class="text-area" spellcheck="false" placeholder="https://example.org/files/manual.pdf" aria-describedby="preparation-error"></textarea>
          <div class="preparation-options"><div><label class="field-label" for="preparation-budget">${t("preparationBudget")}</label><input id="preparation-budget" class="number-field" type="text" inputmode="numeric" value="64" aria-describedby="preparation-error" /></div><label class="preparation-pin-option"><input id="preparation-pin" type="checkbox" checked /> ${t("preparationPin")}</label></div>
          <p id="preparation-quota" class="field-help"></p>
          <div class="button-row"><button id="prepare-offline" type="button" class="primary-button" disabled>${t("preparationStart")}</button><button id="cancel-preparation" type="button" class="secondary-button" hidden>${t("preparationCancel")}</button></div>
          <p id="preparation-error" class="field-error" role="status" aria-live="polite"></p>
          <div id="preparation-jobs" class="preparation-jobs"></div>
          <div id="preparation-pins" class="preparation-pins"></div>
        </div>
      </section>
      <section class="settings-section" aria-labelledby="ads-title">
        <div class="section-copy">
          <h2 id="ads-title">${t("ads")}</h2>
          <p>${t("adsCopy")}</p>
        </div>
        <div class="section-control segmented" data-setting="adblockMode" role="group" aria-label="${t("adblockStrength")}">
          <button type="button" data-value="off">${t("off")}</button>
          <button type="button" data-value="mild">${t("mild")}</button>
          <button type="button" data-value="strict">${t("strict")}</button>
        </div>
      </section>
      <section class="settings-section" aria-labelledby="policy-title">
        <div class="section-copy"><h2 id="policy-title">${t("policyTitle")}</h2><p>${t("policyCopy")}</p></div>
        <div class="section-control stacked-control">
          <label class="field-label" for="policy-allow">${t("policyAllow")}</label><textarea id="policy-allow" class="text-area" spellcheck="false"></textarea>
          <label class="field-label" for="policy-block">${t("policyBlock")}</label><textarea id="policy-block" class="text-area" spellcheck="false"></textarea>
          <label class="field-label" for="policy-no-cache">${t("policyNoCache")}</label><textarea id="policy-no-cache" class="text-area" spellcheck="false"></textarea>
          <label class="field-label" for="history-retention">${t("historyRetention")}</label><input id="history-retention" class="number-field" type="text" inputmode="numeric" />
          <label class="field-label" for="schedule-utc-offset">${t("scheduleOffset")}</label><input id="schedule-utc-offset" class="number-field" type="text" inputmode="numeric" />
          <p id="policy-settings-error" class="field-error" role="status" aria-live="polite"></p>
          <label class="field-label" for="feed-name">${t("feedName")}</label><input id="feed-name" class="number-field" type="text" maxlength="80" />
          <label class="field-label" for="feed-file">${t("feedFile")}</label><input id="feed-file" type="file" accept=".txt,.hosts,text/plain" />
          <button id="import-feed" class="secondary-button" type="button">${t("feedImport")}</button><p class="field-help">${t("feedHelp")}</p><div id="feed-list"></div>
        </div>
      </section>
      <section class="settings-section profile-section" aria-labelledby="profiles-title">
        <div class="section-copy"><h2 id="profiles-title">${t("profilesTitle")}</h2><p>${t("profilesCopy")}</p><p class="field-help">${t("profileLimitsHelp")}</p><button id="add-profile" class="secondary-button" type="button">${t("addProfile")}</button></div>
        <div id="profile-editors" class="profile-editors"></div>
      </section>
      <section class="settings-section" aria-labelledby="history-title">
        <div class="section-copy"><h2 id="history-title">${t("historyTitle")}</h2><p>${t("historyCopy")}</p></div>
        <div class="section-control stacked-control"><div id="quota-alerts" role="status" aria-live="polite"></div><div class="button-row"><button id="refresh-history" class="secondary-button" type="button">${t("historyRefresh")}</button><button data-history-export="csv" class="secondary-button" type="button">CSV</button><button data-history-export="json" class="secondary-button" type="button">JSON</button></div><p id="history-state" class="field-help" aria-live="polite">${t("historyNotLoaded")}</p><div id="history-rows" class="history-rows"></div></div>
      </section>
      <section class="settings-section" aria-labelledby="routing-title">
        <div class="section-copy"><h2 id="routing-title">${t("routingTitle")}</h2><p>${t("routingCopy")}</p></div>
        <div class="section-control stacked-control">
          <label class="check-row"><input id="pac-enabled" type="checkbox" /><span>${t("pacEnabled")}</span></label>
          <label class="check-row"><input id="pac-direct-fallback" type="checkbox" /><span>${t("pacFallback")}</span></label>
          <p id="pac-url" class="field-help"></p>
          <label class="check-row"><input id="lan-dns-enabled" type="checkbox" /><span>${t("lanDnsEnabled")}</span></label>
          <label class="field-label" for="lan-dns-port">${t("lanDnsPort")}</label><input id="lan-dns-port" class="number-field" type="text" inputmode="numeric" />
          <label class="field-label" for="lan-dns-upstream">${t("lanDnsUpstream")}</label><input id="lan-dns-upstream" class="number-field" type="text" spellcheck="false" />
          <p class="field-help">${t("lanDnsHelp")}</p>
          <div id="upstream-editors"></div><button id="add-upstream" class="secondary-button" type="button">${t("addUpstream")}</button>
          <label class="check-row"><input id="upstream-direct-fallback" type="checkbox" /><span>${t("upstreamFallback")}</span></label>
          <p class="field-help">${t("upstreamHelp")}</p><p id="routing-settings-error" class="field-error" role="status"></p>
        </div>
      </section>

      <section class="settings-section" aria-labelledby="images-title">
        <div class="section-copy">
          <h2 id="images-title">${t("imageCompression")}</h2>
          <p>${t("imagesCopy")}</p>
        </div>
        <div class="section-control segmented" data-setting="compressionPreset" role="group" aria-label="${t("compressionStrength")}">
          <button type="button" data-value="off">${t("off")}</button>
          <button type="button" data-value="sharper">${t("sharper")}</button>
          <button type="button" data-value="balanced">${t("balanced")}</button>
          <button type="button" data-value="maximum">${t("maximum")}</button>
        </div>
      </section>

      <section class="settings-section" aria-labelledby="cache-title">
        <div class="section-copy">
          <h2 id="cache-title">${t("publicCache")}</h2>
          <p>${t("cacheCopy")}</p>
        </div>
        <div class="section-control stacked-control">
          <label class="switch-row" for="cache-enabled">
            <span><strong>${t("sharePublic")}</strong><small>${t("optInPool")}</small></span>
            <input id="cache-enabled" type="checkbox" />
            <span class="switch" aria-hidden="true"></span>
          </label>
          <div class="cache-limits">
            <div class="cache-limit-field">
              <label class="field-label" for="cache-limit-gib">${t("cacheDiskLimitLabel")}</label>
              <input id="cache-limit-gib" class="number-field" type="text" inputmode="numeric" autocomplete="off" aria-describedby="cache-limit-gib-help cache-settings-error" />
              <small id="cache-limit-gib-help" class="field-help">${t("cacheDiskLimitHelp")}</small>
              <div class="segmented" role="group" aria-label="${t("cacheSize")}">
                <button type="button" data-cache-preset="2">2 GiB</button>
                <button type="button" data-cache-preset="8">8 GiB</button>
                <button type="button" data-cache-preset="20">20 GiB</button>
              </div>
            </div>
            <div class="cache-limit-field">
              <label class="field-label" for="cache-max-object-mib">${t("cacheMaxObjectLabel")}</label>
              <input id="cache-max-object-mib" class="number-field" type="text" inputmode="numeric" autocomplete="off" aria-describedby="cache-max-object-mib-help cache-settings-error" />
              <small id="cache-max-object-mib-help" class="field-help">${t("cacheMaxObjectHelp")}</small>
            </div>
            <div class="cache-limit-field">
              <label class="field-label" for="buffer-limit-mib">${t("bufferLimitLabel")}</label>
              <input id="buffer-limit-mib" class="number-field" type="text" inputmode="numeric" autocomplete="off" aria-describedby="buffer-limit-mib-help cache-settings-error" />
              <small id="buffer-limit-mib-help" class="field-help">${t("bufferLimitHelp")}</small>
            </div>
            <div class="cache-limit-field">
              <label class="field-label" for="buffer-budget-mib">${t("bufferBudgetLabel")}</label>
              <input id="buffer-budget-mib" class="number-field" type="text" inputmode="numeric" autocomplete="off" aria-describedby="buffer-budget-mib-help cache-settings-error" />
              <small id="buffer-budget-mib-help" class="field-help">${t("bufferBudgetHelp")}</small>
            </div>
          </div>
          <p id="cache-settings-error" class="setup-inline-state" data-state="error" role="status"></p>
          <p class="field-help">${t("cacheBoundaryHelp")}</p>
          <p id="cache-restart-note" class="field-help">${t("cacheRestartNote")}</p>
          <dl id="cache-overview" class="cache-overview" aria-label="${t("cacheOverviewTitle")}">
            <div><dt>${t("cacheSavedLimits")}</dt><dd id="cache-saved-limits"></dd></div>
            <div><dt>${t("cacheDraftLimits")}</dt><dd id="cache-draft-limits"></dd></div>
            <div><dt>${t("cacheDiskUsed")}</dt><dd id="cache-used"></dd></div>
            <div><dt>${t("cacheEntries")}</dt><dd id="cache-entries"></dd></div>
          </dl>
          <p id="cache-usage-note" class="field-help" role="status"></p>
          <button id="clear-cache" class="secondary-button" type="button">${t("clearCache")}</button>
        </div>
      </section>

      <section class="settings-section" aria-labelledby="about-title">
        <div class="section-copy">
          <h2 id="about-title">${t("aboutTitle")}</h2>
          <p>${t("aboutCopy")}</p>
        </div>
        <div class="section-control stacked-control">
          <dl class="cache-overview about-overview">
            <div><dt>${t("aboutAppVersion")}</dt><dd id="about-app-version"></dd></div>
            <div id="about-service-row" hidden><dt>${t("aboutServiceVersion")}</dt><dd id="about-service-version"></dd></div>
            <div><dt>${t("aboutWebsite")}</dt><dd class="about-link">${PROJECT_WEBSITE}</dd></div>
            <div><dt>${t("aboutSource")}</dt><dd class="about-link">${PROJECT_SOURCE}</dd></div>
          </dl>
          <p id="about-version-mismatch" class="setup-inline-state" data-state="error" role="status" hidden></p>
        </div>
      </section>

      <section class="truth-card">
        <strong>${t("stageLimitsTitle")}</strong>
        <p>${t("stageLimits")}</p>
      </section>
    </main>

    <main id="guide-page" class="page guide-page">
      <header class="guide-heading">
        <div>
          <p class="eyebrow">${t("firstRun")}</p>
          <h1>${t("guideTitle")}</h1>
          <p class="lead">${t("guideLead")}</p>
        </div>
        <div class="guide-state" aria-label="${t("readinessAria")}" aria-live="polite">
          <div><span>${t("service")}</span><strong id="guide-service-state">${t("loading")}</strong></div>
          <div><span>${t("otherDevices")}</span><strong id="guide-lan-state">${t("loading")}</strong></div>
          <div><span>${t("address")}</span><strong id="guide-address-state">${t("loading")}</strong></div>
        </div>
      </header>

      <ol class="setup-route" aria-label="${t("fourStepsAria")}">
        <li id="guide-step-connection">
          <span class="route-number" aria-hidden="true">1</span>
          <article class="route-card">
            <p class="route-label">${t("step1Label")}</p>
            <h2>${t("step1Title")}</h2>
            <p>${t("step1Copy")}</p>
            <p class="route-callout guide-brand-warning"><strong>${t("useHomeProxyTitle")}</strong> ${t("useHomeProxyCopy")}</p>
            <fieldset class="connection-fieldset">
              <legend class="visually-hidden">${t("connectionChoiceAria")}</legend>
              <div class="connection-choices">
                <label class="connection-choice">
                  <input type="radio" name="guide-connection" value="sameWifi" checked />
                  <span>
                    <strong>${t("sameWifi")}</strong>
                    <small>${t("sameWifiCopy")}</small>
                  </span>
                </label>
                <label class="connection-choice is-amber"${isLinux ? " hidden" : ""}>
                  <input type="radio" name="guide-connection" value="hotspot" />
                  <span>
                    <strong>${t("hostWifi")}</strong>
                    <small>${t("hostWifiCopy")}</small>
                    <code class="choice-path">${t("hotspotPath")}</code>
                  </span>
                </label>
              </div>
            </fieldset>
            <div class="route-actions">
              <button id="guide-refresh-addresses" class="secondary-button" type="button">${t("checkAddresses")}</button>
            </div>
          </article>
        </li>

        <li id="guide-step-address">
          <span class="route-number" aria-hidden="true">2</span>
          <article class="route-card">
            <p id="guide-address-label" class="route-label">${t("step2Label")}</p>
            <h2 id="guide-address-title">${t("step2Title")}</h2>
            <p id="guide-address-copy">${t("step2Copy")}</p>
            <fieldset id="guide-address-fieldset" class="address-fieldset">
              <legend id="guide-address-legend" class="visually-hidden">${t("addressOptionsAria")}</legend>
              <div id="guide-address-options" class="address-choices"></div>
            </fieldset>
            <p id="guide-address-help" class="setup-inline-state" aria-live="polite"></p>
            <div id="guide-hotspot-actions" class="route-actions" hidden>
              <button id="guide-hotspot-fallback" class="secondary-button" type="button">${t("hotspotFallbackShow")}</button>
            </div>
          </article>
        </li>

        <li id="guide-step-prepare">
          <span class="route-number" aria-hidden="true">3</span>
          <article class="route-card">
            <p class="route-label">${t("step3Label")}</p>
            <h2>${t("step3Title")}</h2>
            <p>${t("step3Copy")}</p>
            <div id="guide-setup-controls">
              <div class="guide-service-ports">
              <label class="field-label" for="guide-proxy-port">${t("httpProxyPort")}</label>
              <input id="guide-proxy-port" class="number-field" type="number" min="1" max="65535" inputmode="numeric" />
              <div class="port-presets" role="group" aria-label="${t("proxyPortPresetsAria")}">
                <button type="button" data-guide-proxy-port-preset="80">80</button>
                <button type="button" data-guide-proxy-port-preset="3128">3128</button>
                <button type="button" data-guide-proxy-port-preset="17891">17891</button>
              </div>
              <p id="guide-port-80-warning" class="field-help access-warning" hidden>${t("port80Warning")}</p>
              <label class="switch-row" for="guide-socks5-enabled">
                <span><strong>${t("enablePhoneSocks5")}</strong><small>${t("enablePhoneSocks5Help")}</small></span>
                <input id="guide-socks5-enabled" type="checkbox" />
                <span class="switch" aria-hidden="true"></span>
              </label>
              <label class="switch-row" for="guide-socks5-udp-enabled">
            <span><strong>${t("socks5UdpTitle")}</strong><small>${t("socks5UdpHelp")}</small></span>
            <input id="guide-socks5-udp-enabled" type="checkbox" />
            <span class="switch" aria-hidden="true"></span>
          </label>
          <label class="field-label" for="guide-socks5-port">${t("socks5Port")}</label>
              <input id="guide-socks5-port" class="number-field" type="number" min="1" max="65535" inputmode="numeric" />
              <p id="guide-service-port-error" class="setup-inline-state" data-state="error" role="status"></p>
              </div>
              <label class="field-label" for="guide-https-mode">${t("httpsModeTitle")}</label>
              <select id="guide-https-mode" class="select-field"><option value="tunnel">${t("httpsTunnel")}</option><option value="inspect"${isLinux ? " disabled" : ""}>${t("httpsInspect")}</option></select>
              <p id="guide-https-mode-help" class="field-help"></p>
              <label class="field-label" for="guide-https-inspection-scope">${t("httpsScopeTitle")}</label>
              <select id="guide-https-inspection-scope" class="select-field" aria-describedby="guide-https-scope-help"><option value="selectedHosts">${t("httpsScopeSelected")}</option><option value="allSupportedHosts">${t("httpsScopeAll")}</option></select>
              <p id="guide-https-scope-help" class="field-help"></p>
              <label class="switch-row setup-cache-toggle" for="guide-cache-enabled">
                <span><strong>${t("enablePublicCache")}</strong><small>${t("enablePublicCacheHelp")}</small></span>
                <input id="guide-cache-enabled" type="checkbox" />
                <span class="switch" aria-hidden="true"></span>
              </label>
              <section id="guide-access-controls" class="guide-access-controls" aria-labelledby="guide-access-title">
                <div class="guide-access-heading">
                  <h3 id="guide-access-title">${t("deviceAccess")}</h3>
                  <p>${t("deviceAccessCopy")}</p>
                </div>
                <label class="switch-row" for="guide-lan-auth-enabled">
                  <span><strong>${t("requireLanLogin")}</strong><small>${t("requireLanLoginHelp")}</small></span>
                  <input id="guide-lan-auth-enabled" type="checkbox" />
                  <span class="switch" aria-hidden="true"></span>
                </label>
                <p id="guide-open-lan-warning" class="access-warning" role="status" hidden>${t("openLanWarning")}</p>
                <div class="guide-access-fields">
                  <div>
                    <label class="field-label" for="guide-proxy-user-input">${t("username")}</label>
                    <div class="copy-field"><input id="guide-proxy-user-input" maxlength="32" autocomplete="off" spellcheck="false" /></div>
                  </div>
                  <div>
                    <label class="field-label" for="guide-proxy-password-input">${t("accessKey")}</label>
                    <div class="copy-field">
                      <input id="guide-proxy-password-input" type="password" maxlength="128" autocomplete="new-password" spellcheck="false" />
                      <button id="guide-edit-reveal-key" type="button">${t("show")}</button>
                    </div>
                  </div>
                </div>
                <p class="field-help">${t("credentialRules")}</p>
              </section>
              <div class="route-actions">
                <button id="guide-prepare" class="primary-button" type="button" disabled>${t("prepareAndStart")}</button>
              </div>
              <aside class="public-cache-note">
                <span class="cache-lock" aria-hidden="true"></span>
                <div>
                  <strong>${t("sharedCacheTitle")}</strong>
                  <p>${t("sharedCacheCopy")}</p>
                </div>
              </aside>
            </div>
            <p id="guide-prepare-state" class="setup-inline-state" role="status"></p>
            <section id="guide-prepared-instructions" class="guide-prepared-instructions" hidden>
              <aside class="host-proxy-note" aria-labelledby="host-proxy-note-title">
                <strong id="host-proxy-note-title">${t("hostProxyNoteTitle")}</strong>
                <p>${t("hostProxyNoteCopy")}</p>
                <small id="host-proxy-local-copy">${t("hostProxyLocalCopy", { port: DEFAULT_PROXY_PORT })}</small>
                <span id="guide-host-certificate-state" class="setup-inline-state"></span>
              </aside>
              <div class="proxy-recipe setup-proxy-recipe host-proxy-recipe" aria-label="${t("hostProxyDataAria")}">
              <div>
                <span>${t("proxyAddressLabel")}</span>
                <strong>127.0.0.1</strong>
                <button type="button" data-guide-host-copy="address" aria-label="${t("copyProxyAddress")}">${t("copy")}</button>
              </div>
              <div>
                <span>${t("port")}</span>
                <strong id="guide-host-proxy-port">${DEFAULT_PROXY_PORT}</strong>
                <button type="button" data-guide-host-copy="port" aria-label="${t("copyProxyPort")}">${t("copy")}</button>
              </div>
              </div>
              <h3 class="route-subheading">${t("secondDeviceTitle")}</h3>
              <p>${t("secondDeviceCopy")}</p>
              <div class="proxy-recipe setup-proxy-recipe" aria-label="${t("proxyDataAria")}">
              <div>
                <span>${t("proxyAddressLabel")}</span>
                <strong id="guide-proxy-address">${t("configureFirst")}</strong>
                <button type="button" data-guide-copy="address" aria-label="${t("copyProxyAddress")}">${t("copy")}</button>
              </div>
              <div>
                <span>${t("port")}</span>
                <strong id="guide-device-proxy-port">${DEFAULT_PROXY_PORT}</strong>
                <button type="button" data-guide-copy="port" aria-label="${t("copyProxyPort")}">${t("copy")}</button>
              </div>
              <div>
                <span>${t("username")}</span>
                <strong id="guide-proxy-user">—</strong>
                <button type="button" data-guide-copy="username" aria-label="${t("copyProxyUsername")}">${t("copy")}</button>
              </div>
              <div>
                <span>${t("accessKey")}</span>
                <strong id="guide-proxy-key">••••••••••••••••</strong>
                <button id="guide-reveal-key" type="button">${t("show")}</button>
                <button type="button" data-guide-copy="key" aria-label="${t("copyProxyKey")}">${t("copy")}</button>
              </div>
              <p>${t("proxyPromptHelp")}</p>
              </div>
              <div class="route-actions">
                <button id="guide-edit-access" class="secondary-button" type="button">${t("changeOrDisableAccess")}</button>
                <button id="guide-copy-all" class="secondary-button" type="button" disabled>${t("copyAllProxyDetails")}</button>
              </div>
              <aside id="guide-certificate-note" class="certificate-note">
              <strong>${t("caInstallTitle")}</strong>
              <p>${t("caInstallCopy")}</p>
              <div class="certificate-address">
                <span>${t("caDownloadAddress")}</span>
                <code>http://homeproxy.test/ca.cer</code>
                <button id="guide-copy-ca" type="button" aria-label="${t("copyCaDownloadAddress")}" disabled>${t("copy")}</button>
              </div>
              </aside>
              <aside class="chat-app-note">
              <strong>${t("chatAppsTitle")}</strong>
              <p>${t("chatAppsLead")}</p>
              <div class="chat-app-grid">
                <section>
                  <h3>${t("smarttubeTitle")}</h3>
                  <p id="smarttube-copy">${t("smarttubeCopy", { port: DEFAULT_SOCKS5_PORT })}</p>
                </section>
                <section>
                  <h3>${t("whatsappMessengerTitle")}</h3>
                  <p id="whatsapp-messenger-copy">${t("whatsappMessengerCopy", { port: DEFAULT_SOCKS5_PORT })}</p>
                  <div class="chat-proxy-values" aria-label="${t("phoneSocksDataAria")}">
                    <code>SOCKS5</code>
                    <code id="guide-socks5-address">${t("configureFirst")}</code>
                    <code id="guide-socks5-port-value">${DEFAULT_SOCKS5_PORT}</code>
                  </div>
                  <button id="guide-copy-socks5" class="secondary-button" type="button" disabled>${t("copyPhoneSocksDetails")}</button>
                </section>
                <section>
                  <h3>${t("telegramTitle")}</h3>
                  <p id="telegram-copy">${t("telegramCopy", { port: DEFAULT_SOCKS5_PORT })}</p>
                  <div class="chat-proxy-values" aria-label="${t("hostProxyDataAria")}">
                    <code>SOCKS5</code>
                    <code>127.0.0.1</code>
                    <code id="guide-telegram-port">${DEFAULT_SOCKS5_PORT}</code>
                  </div>
                </section>
              </div>
              <small id="chat-cache-note">${t("chatCacheNote")}</small>
              <small id="guide-socks5-activity"></small>
              </aside>
            </section>
          </article>
        </li>

        <li id="guide-step-verify">
          <span class="route-number" aria-hidden="true">4</span>
          <article class="route-card">
            <p class="route-label">${t("step4Label")}</p>
            <h2>${t("step4Title")}</h2>
            <p id="guide-verify-copy">${t("step4Copy")}</p>
            <div id="guide-verification" class="verification-card" data-state="pending" role="status" aria-live="polite">
              <span class="verification-mark" aria-hidden="true"></span>
              <div>
                <strong id="guide-verification-title">${t("setupWaiting")}</strong>
                <p id="guide-verification-copy">${t("setupWaitingCopy")}</p>
              </div>
            </div>
            <div class="route-actions">
              <button id="guide-verify" class="secondary-button" type="button" disabled>${t("verifyConnection")}</button>
            </div>
          </article>
        </li>
      </ol>

      <section id="device-setup-card" class="device-setup-card" aria-labelledby="device-setup-title">
        <header class="device-setup-heading">
          <p class="eyebrow">${t("deviceSetupEyebrow")}</p>
          <h2 id="device-setup-title" tabindex="-1">${t("deviceSetupTitle")}</h2>
          <p>${t("deviceSetupLead")}</p>
        </header>
        <div class="device-setup-grid">
          <div class="device-setup-main">
            <ol class="device-setup-steps" aria-label="${t("deviceSetupStepsAria")}">
              <li>${t("deviceSetupStep1")}</li>
              <li>${t("deviceSetupStep2")}</li>
              <li>${t("deviceSetupStep3")}</li>
              <li>${t("deviceSetupStep4")}</li>
            </ol>
            <div class="device-setup-status" role="status" aria-live="polite">
              <ul id="device-setup-blockers" class="device-setup-blockers"></ul>
              <p id="device-setup-ready-state" class="setup-inline-state" data-state="ready" hidden></p>
            </div>
            <div id="device-setup-actions" class="route-actions" hidden>
              <button id="device-setup-prepare-ca" class="secondary-button" type="button" hidden>${t("tlsPrepare")}</button>
              <button id="device-setup-start" class="secondary-button" type="button" hidden>${t("deviceSetupStart")}</button>
              <button id="device-setup-open-settings" class="secondary-button" type="button" hidden>${t("deviceSetupOpenSettings")}</button>
            </div>
            <div id="phone-setup-ready" class="device-setup-details" hidden>
              <div id="device-setup-address-choice" hidden>
                <label class="field-label" for="device-setup-address-select">${t("deviceSetupAddressSelect")}</label>
                <select id="device-setup-address-select" class="select-field"></select>
              </div>
              <div class="device-setup-value">
                <span>${t("deviceSetupAddressLabel")}</span>
                <code id="device-setup-address"></code>
                <button id="device-setup-copy-address" type="button">${t("deviceSetupCopyAddress")}</button>
              </div>
              <div class="device-setup-value">
                <span>${t("deviceSetupLinkLabel")}</span>
                <code id="phone-setup-url" class="device-setup-link"></code>
                <button id="phone-setup-copy-url" type="button">${t("deviceSetupCopyLink")}</button>
              </div>
              <div class="device-setup-value">
                <span>${t("deviceSetupFingerprintLabel")}</span>
                <code id="device-setup-fingerprint" class="certificate-fingerprint"></code>
                <button id="device-setup-copy-fingerprint" type="button">${t("deviceSetupCopyFingerprint")}</button>
              </div>
            </div>
          </div>
          <figure class="device-setup-qr" data-state="blocked">
            <svg id="phone-setup-qr" role="img" hidden xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path id="device-setup-qr-path" fill="#000" d=""/></svg>
            <figcaption id="device-setup-qr-placeholder">${t("deviceSetupQrPlaceholder")}</figcaption>
          </figure>
        </div>
        <p class="device-setup-warning">${t("deviceSetupTrustWarning")}</p>
        <details class="device-setup-trust">
          <summary>${t("deviceSetupTrustTitle")}</summary>
          <p>${t("deviceSetupTrust1")}</p>
          <p>${t("deviceSetupTrust2")}</p>
          <p>${t("deviceSetupTrust3")}</p>
          <p>${t("deviceSetupTrust4")}</p>
          <p>${t("deviceSetupTrust5")}</p>
        </details>
      </section>

      <section class="troubleshooting" aria-labelledby="troubleshooting-title">
        <div class="troubleshooting-heading">
          <p class="eyebrow">${t("quickHelp")}</p>
          <h2 id="troubleshooting-title">${t("troubleTitle")}</h2>
        </div>
        <div class="troubleshooting-list">
          <details${isLinux ? " hidden" : ""}>
            <summary>${t("noHotspotAddress")}</summary>
            <p>${t("noHotspotAddressCopy")}</p>
          </details>
          <details>
            <summary>${t("proxy407")}</summary>
            <p>${t("proxy407CopyBefore")} <code>http://</code>${t("proxy407CopyAfter")} <code id="troubleshooting-proxy-port">${DEFAULT_PROXY_PORT}</code>.</p>
          </details>
          <details>
            <summary>${t("proxyNoResponse")}</summary>
            <p>${t("proxyNoResponseCopy")}</p>
          </details>
          <details>
            <summary>${t("certificateProblem")}</summary>
            <p>${t("certificateProblemCopy")}</p>
          </details>
          <details>
            <summary>${t("chatAppProblem")}</summary>
            <p id="chat-app-problem-copy">${t("chatAppProblemCopy", { port: DEFAULT_SOCKS5_PORT })}</p>
          </details>
          <details>
            <summary>${t("pagesSlow")}</summary>
            <p>${t("pagesSlowCopy")}</p>
          </details>
        </div>
      </section>

      <div class="guide-finish">
        <button id="guide-finish" class="primary-button" type="button" disabled>${t("finishGuide")}</button>
        <span id="guide-finish-help">${t("finishBlocked")}</span>
      </div>
    </main>
    <aside id="settings-savebar" class="settings-savebar" aria-label="${t("pendingChanges")}" hidden>
      <span id="settings-save-state" role="status">${t("pendingChanges")}</span>
      <button id="discard-settings" class="secondary-button" type="button">${t("discardChanges")}</button>
      <button id="save-settings" class="primary-button" type="button" disabled>${t("saveChanges")}</button>
    </aside>
  </div>
`;

let diagnosticsStatus: DiagnosticsStatus | null = null;
let diagnosticsLoading = true;
let diagnosticsRefreshing = false;
let diagnosticsExporting = false;
let diagnosticsExported: DiagnosticExport | null = null;
let diagnosticsExportError: ReturnType<typeof diagnosticExportErrorKey> | null = null;
let snapshotUnavailable = true;
let startupErrorShown = false;
let snapshot: AppSnapshot | null = null;
let draft: Settings | null = null;
// Service revision the draft was cloned from. Saves send this, never a fresher revision,
// so a concurrent change surfaces as a conflict instead of being silently overwritten.
let draftRevision: string | undefined;
let dirty = false;
let busy = false;
let activitySnapshotGeneration = 0;
let activityPaused = false;
let displayedActivity: Activity[] = [];
let deviceRenderSignature = "";
let refreshing = false;
let noticeTimer: number | undefined;
let guideConnectionMode: ConnectionMode = "sameWifi";
let guideSelectedIp: string | null = null;
let guideHotspotFallbackVisible = false;
let guideSelectionInitialized = false;
let guideCacheEnabled = false;
let guidePasswordRevealed = false;
let guideBaselineAuthenticatedRequests: number | null = null;
let guideBaselineSuccessfulRequests: number | null = null;
let guideBaselineTotalRequests: number | null = null;
let guideVerificationStartedAt: number | null = null;
let guideAddressRenderSignature = "";
let settingsAddressRenderSignature = "";
const DEVICE_SETUP_QUIET_ZONE = 4;
let deviceSetupPreferredIp: string | null = null;
let deviceSetupState: Extract<PhoneSetupState, { kind: "ready" }> | null = null;
let deviceSetupRenderSignature: string | null = null;
let tlsStatusCheckedAt = 0;
const guideSeenKey = "homeproxy-guide-seen-v3";

const byId = <T extends Element = HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(t("elementMissing", { id }));
  return element as unknown as T;
};

const serviceToggle = byId<HTMLButtonElement>("service-toggle");
const saveButton = byId<HTMLButtonElement>("save-settings");
const lanCheckbox = byId<HTMLInputElement>("lan-enabled");
const lanAuthCheckbox = byId<HTMLInputElement>("lan-auth-enabled");
const listenSelect = byId<HTMLSelectElement>("listen-ip");
const proxyPortInput = byId<HTMLInputElement>("proxy-port");
const socks5EnabledCheckbox = byId<HTMLInputElement>("socks5-enabled");
const socks5UdpEnabledCheckbox = byId<HTMLInputElement>("socks5-udp-enabled");
const socks5PortInput = byId<HTMLInputElement>("socks5-port");
const proxyUserInput = byId<HTMLInputElement>("proxy-user");
const proxyPasswordInput = byId<HTMLInputElement>("proxy-password");
const cacheCheckbox = byId<HTMLInputElement>("cache-enabled");
const cacheInputs: Record<CacheField, HTMLInputElement> = {
  cacheLimitGib: byId<HTMLInputElement>("cache-limit-gib"),
  cacheMaxObjectMib: byId<HTMLInputElement>("cache-max-object-mib"),
  responseBufferLimitMib: byId<HTMLInputElement>("buffer-limit-mib"),
  responseBufferBudgetMib: byId<HTMLInputElement>("buffer-budget-mib"),
};
let cacheInputsNeedReset = true;
let offlineInputsNeedReset = true;
let policyInputsNeedReset = true;
let profileEditorSignature = "";
let routingInputsNeedReset=true;
let upstreamEditorSignature="";
let feedRenderSignature="";
const upstreamEditorOwners=new WeakMap<object,number>();
let nextUpstreamEditorOwner=0;
for(const [id,field] of [["pac-enabled","pacEnabled"],["pac-direct-fallback","pacDirectFallback"],["lan-dns-enabled","lanDnsEnabled"],["upstream-direct-fallback","upstreamDirectFallback"]] as const){
  byId<HTMLInputElement>(id).addEventListener("change",()=>{if(!draft)return;draft[field]=byId<HTMLInputElement>(id).checked;markDirty();renderSettings();});
}
for(const id of ["lan-dns-port","lan-dns-upstream"])byId(id).addEventListener("input",()=>{markDirty();renderSettings();});
byId("add-upstream").addEventListener("click",()=>{if(!draft||busy)return;draft.upstreamProxies.push({host:"",port:3128,username:null,password:null});upstreamEditorSignature="";markDirty();renderSettings();});
byId("import-feed").addEventListener("click",()=>void runBusy(async()=>{
  const file=byId<HTMLInputElement>("feed-file").files?.[0];const name=byId<HTMLInputElement>("feed-name").value.trim();
  if(!file||!name||file.size>2*1024*1024){showNotice(t("feedInvalid"),"error");return;}
  if(dirty&&!await applyDirtyDraft())return;
  const next=await invoke<AppSnapshot>("import_filter_feed",{name,content:await file.text(),expectedRevision:draftRevision});
  syncFromSnapshot(next,true);byId<HTMLInputElement>("feed-file").value="";showNotice(t("feedImported"),"success");
}));
const policyInputs = {
  allowDomains: byId<HTMLTextAreaElement>("policy-allow"),
  blockDomains: byId<HTMLTextAreaElement>("policy-block"),
  noCacheDomains: byId<HTMLTextAreaElement>("policy-no-cache"),
};
for (const input of Object.values(policyInputs)) input.addEventListener("input",()=>{markDirty();renderSettings();});
for (const id of ["history-retention","schedule-utc-offset"]) byId(id).addEventListener("input",()=>{markDirty();renderSettings();});
byId("add-profile").addEventListener("click",()=>{
  if(!draft||busy)return; draft.deviceProfiles.push(createProfile()); profileEditorSignature="";markDirty();renderSettings();
});
interface HistoryReport {healthy:boolean;error:string|null;rows:{identity:string;day:number;counters:{uploadBytes:number;downloadBytes:number;savedBytes:number;requests:number}}[]}
byId("refresh-history").addEventListener("click",()=>void runBusy(async()=>{
  const report=await invoke<HistoryReport>("get_usage_history");
  byId("history-state").textContent=report.healthy?t("historyLoaded"):t("historyUnavailable");
  const rows=byId("history-rows");rows.replaceChildren();
  for(const row of report.rows.slice(-60).reverse()){
    const line=document.createElement("p");
    const profile=draft?.deviceProfiles.find(p=>`profile:${p.id}`===row.identity);
    line.textContent=`${new Date(row.day*86400000).toLocaleDateString(numberLocale)} · ${profile?.name||row.identity} · ↑ ${formatBytes(row.counters.uploadBytes)} · ↓ ${formatBytes(row.counters.downloadBytes)} · ${formatCount(row.counters.requests)} ${t("requests")}`;
    rows.append(line);
  }
}));
document.querySelectorAll<HTMLButtonElement>("[data-history-export]").forEach(button=>button.addEventListener("click",()=>void runBusy(async()=>{
  const format=button.dataset.historyExport!;
  const exported=await invoke<{format:string;content:string}>("export_usage_history",{format});
  const url=URL.createObjectURL(new Blob([exported.content],{type:format==="csv"?"text/csv;charset=utf-8":"application/json"}));
  const anchor=document.createElement("a");anchor.href=url;anchor.download=`homeproxy-history.${format}`;anchor.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  showNotice(t("historyExported"),"success");
})));
interface TlsStatus { prepared: boolean; capability?: boolean; certificatePem?: string; sha256Fingerprint?: string | null; inspectionEnabled?: boolean; clientTrustAcknowledged?: boolean }
let tlsStatus: TlsStatus | null = null;
const offlineInputs = {
  inspectHosts: byId<HTMLTextAreaElement>("https-inspect-hosts"),
  bypassHosts: byId<HTMLTextAreaElement>("https-bypass-hosts"),
  endpoints: byId<HTMLTextAreaElement>("public-cache-endpoints"),
  staleHours: byId<HTMLInputElement>("offline-stale-hours"),
};
for (const input of Object.values(offlineInputs)) input.addEventListener("input", () => { markDirty(); renderSettings(); });
offlineInputs.inspectHosts.addEventListener("blur", () => renderOfflineControls());
byId<HTMLInputElement>("https-trust-ack").addEventListener("change", () => {
  if (!draft) return;
  draft.httpsClientTrustAcknowledged = byId<HTMLInputElement>("https-trust-ack").checked;
  markDirty(); renderSettings();
});
for (const id of ["https-inspection-scope", "guide-https-inspection-scope"]) {
  byId<HTMLSelectElement>(id).addEventListener("change", (event) => {
    if (!draft || busy) return;
    draft.httpsInspectionScope = (event.target as HTMLSelectElement).value as Settings["httpsInspectionScope"];
    markDirty(); renderSettings(); renderGuide();
  });
}
byId<HTMLSelectElement>("cache-mode").addEventListener("change", () => {
  if (!draft) return;
  draft.cacheMode = byId<HTMLSelectElement>("cache-mode").value as Settings["cacheMode"];
  markDirty(); renderSettings();
});
const prepareTlsAuthority = () => void runBusy(async () => {
  tlsStatus = await invoke<TlsStatus>("prepare_tls_authority");
  if (!tlsStatus.prepared) throw new Error(t("tlsExportFailed"));
  if (snapshot?.httpsAuthority) {
    snapshot.httpsAuthority = { ...snapshot.httpsAuthority, prepared: tlsStatus.prepared, sha256Fingerprint: tlsStatus.sha256Fingerprint };
  }
  showNotice(t("tlsPrepared"), "success");
});
byId("prepare-tls").addEventListener("click", prepareTlsAuthority);
byId("device-setup-prepare-ca").addEventListener("click", prepareTlsAuthority);
byId("device-setup-start").addEventListener("click", () => {
  if (snapshot && !snapshot.running) void toggleService();
});
byId("device-setup-open-settings").addEventListener("click", () => {
  showPage("settings");
  byId("network-title").scrollIntoView({ block: "start" });
  lanCheckbox.focus({ preventScroll: true });
});
byId("open-phone-setup").addEventListener("click", () => focusDeviceSetup());
byId<HTMLSelectElement>("device-setup-address-select").addEventListener("change", (event) => {
  deviceSetupPreferredIp = (event.target as HTMLSelectElement).value || null;
  renderDeviceSetup();
});
byId("device-setup-copy-address").addEventListener("click", () => {
  if (deviceSetupState) void copyText(deviceSetupState.ip, t("deviceSetupAddressCopied"));
});
byId("phone-setup-copy-url").addEventListener("click", () => {
  if (deviceSetupState) void copyText(deviceSetupState.url, t("deviceSetupLinkCopied"));
});
byId("device-setup-copy-fingerprint").addEventListener("click", () => {
  if (deviceSetupState) void copyText(deviceSetupState.fingerprint, t("deviceSetupFingerprintCopied"));
});
byId("export-tls").addEventListener("click", () => void runBusy(async () => {
  const exported = await invoke<{certificatePem: string; sha256Fingerprint: string}>("export_tls_certificate");
  if (!exported.certificatePem?.startsWith("-----BEGIN CERTIFICATE-----")) throw new Error(t("tlsExportFailed"));
  const url = URL.createObjectURL(new Blob([exported.certificatePem], {type:"application/x-pem-file"}));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = "HomeProxy-CA.pem"; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  showNotice(t("tlsExported"), "success");
}));
const guidePrepareButton = byId<HTMLButtonElement>("guide-prepare");
const guideVerifyButton = byId<HTMLButtonElement>("guide-verify");
const guideFinishButton = byId<HTMLButtonElement>("guide-finish");
for (const id of ["https-mode", "guide-https-mode"]) {
  byId<HTMLSelectElement>(id).addEventListener("change", (event) => {
    if (!draft || busy) return;
    draft.httpsMode = (event.target as HTMLSelectElement).value as Settings["httpsMode"];
    markDirty();
    renderSettings();
    renderGuide();
  });
}
byId<HTMLSelectElement>("dns-mode").addEventListener("change", () => {
  if (!draft || busy) return;
  draft.dnsMode = byId<HTMLSelectElement>("dns-mode").value as Settings["dnsMode"];
  markDirty();
  renderSettings();
  renderGuide();
});
const guideCacheCheckbox = byId<HTMLInputElement>("guide-cache-enabled");
const guideProxyPortInput = byId<HTMLInputElement>("guide-proxy-port");
const guideSocks5EnabledCheckbox = byId<HTMLInputElement>("guide-socks5-enabled");
const guideSocks5UdpEnabledCheckbox = byId<HTMLInputElement>("guide-socks5-udp-enabled");
const guideSocks5PortInput = byId<HTMLInputElement>("guide-socks5-port");
const guideLanAuthCheckbox = byId<HTMLInputElement>("guide-lan-auth-enabled");
const guideProxyUserInput = byId<HTMLInputElement>("guide-proxy-user-input");
const guideProxyPasswordInput = byId<HTMLInputElement>("guide-proxy-password-input");

document.querySelectorAll<HTMLButtonElement>("[data-locale]").forEach((button) => {
  button.addEventListener("click", () => {
    const nextLocale = button.dataset.locale as Locale | undefined;
    if (!nextLocale || nextLocale === locale) return;
    if (dirty && !window.confirm(t("unsavedLocaleChange"))) return;
    persistLocale(nextLocale);
    window.location.reload();
  });
});

document.querySelectorAll<HTMLButtonElement>(".nav-link").forEach((button) => {
  button.addEventListener("click", () => showPage(button.dataset.page ?? "home"));
});

serviceToggle.addEventListener("click", () => void toggleService());

async function toggleService(): Promise<void> {
  if (!snapshot || busy) return;
  const running = !snapshot.running;
  if (!running) {
    await runBusy(async () => {
      snapshot = await invoke<AppSnapshot>("set_running", { running: false });
      syncFromSnapshot(snapshot);
    });
    return;
  }
  // In the guide both start buttons must save and start the visible selection.
  if (running && byId("guide-page").classList.contains("is-active")) {
    await prepareGuidedSetup();
    return;
  }
  await runBusy(async () => {
    if (!(await applyDirtyDraft())) return;
    snapshot = await invoke<AppSnapshot>("set_running", { running });
    syncFromSnapshot(snapshot, true);
  });
}

byId<HTMLButtonElement>("home-guide").addEventListener("click", () => showPage("guide"));
document.querySelectorAll<HTMLInputElement>('input[name="guide-connection"]').forEach((input) => {
  input.addEventListener("change", () => {
    if (!input.checked || !snapshot) return;
    guideConnectionMode = input.value as ConnectionMode;
    guideHotspotFallbackVisible = false;
    guideSelectedIp = recommendedLanAddress(snapshot.availableAddresses, guideConnectionMode)?.ip ?? null;
    renderGuide();
    focusGuideStep("guide-step-address");
  });
});

byId<HTMLButtonElement>("guide-refresh-addresses").addEventListener("click", async () => {
  await refresh();
  if (!snapshot) return;
  const currentAvailable = snapshot.availableAddresses.some((address) => address.ip === guideSelectedIp);
  if (!currentAvailable) {
    guideSelectedIp = recommendedLanAddress(snapshot.availableAddresses, guideConnectionMode)?.ip ?? null;
  }
  renderGuide();
});

byId<HTMLButtonElement>("guide-hotspot-fallback").addEventListener("click", () => {
  if (!snapshot || guideConnectionMode !== "hotspot") return;
  guideHotspotFallbackVisible = !guideHotspotFallbackVisible;
  if (!guideHotspotFallbackVisible) {
    const selected = snapshot.availableAddresses.find((address) => address.ip === guideSelectedIp);
    if (selected && classifyLanAddress(selected) === "unknown") guideSelectedIp = null;
  }
  guideAddressRenderSignature = "";
  renderGuide();
});

guidePrepareButton.addEventListener("click", () => void prepareGuidedSetup());

guideCacheCheckbox.addEventListener("change", () => {
  guideCacheEnabled = guideCacheCheckbox.checked;
});

guideProxyPortInput.addEventListener("input", () => updateDraftPort("proxyPort", guideProxyPortInput));
guideSocks5PortInput.addEventListener("input", () => updateDraftPort("socks5Port", guideSocks5PortInput));
guideSocks5UdpEnabledCheckbox.addEventListener("change", () => {
  if (!draft || !draft.socks5Enabled) return;
  draft.socks5UdpEnabled = guideSocks5UdpEnabledCheckbox.checked;
  markDirty();
  renderSettings();
  renderGuide();
});
guideSocks5EnabledCheckbox.addEventListener("change", () => {
  if (!draft) return;
  draft.socks5Enabled = guideSocks5EnabledCheckbox.checked;
  markDirty();
  renderSettings();
  renderGuide();
});
document.querySelectorAll<HTMLButtonElement>("button[data-guide-proxy-port-preset]").forEach((button) => {
  button.addEventListener("click", () => {
    if (!draft) return;
    draft.proxyPort = Number(button.dataset.guideProxyPortPreset);
    markDirty();
    renderSettings();
    renderGuide();
  });
});

guideLanAuthCheckbox.addEventListener("change", () => {
  if (!draft) return;
  draft.lanAuthEnabled = guideLanAuthCheckbox.checked;
  markDirty();
  renderSettings();
  renderGuide();
});

guideProxyUserInput.addEventListener("input", () => {
  if (!draft) return;
  draft.proxyUsername = guideProxyUserInput.value;
  markDirty();
  renderSettings();
  renderGuide();
});

guideProxyPasswordInput.addEventListener("input", () => {
  if (!draft) return;
  draft.proxyPassword = guideProxyPasswordInput.value;
  markDirty();
  renderSettings();
  renderGuide();
});

guideVerifyButton.addEventListener("click", () => void beginGuideVerification());

const toggleGuidePasswordReveal = (): void => {
  guidePasswordRevealed = !guidePasswordRevealed;
  renderGuide();
};

byId<HTMLButtonElement>("guide-edit-reveal-key").addEventListener("click", toggleGuidePasswordReveal);
byId<HTMLButtonElement>("guide-reveal-key").addEventListener("click", toggleGuidePasswordReveal);
byId<HTMLButtonElement>("guide-edit-access").addEventListener("click", focusGuideAccessEditor);

document.querySelectorAll<HTMLButtonElement>("button[data-guide-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const details = guideProxyDetails();
    const field = button.dataset.guideCopy as keyof typeof details | undefined;
    if (!field || !details[field]) return;
    await copyText(details[field], t("copied"));
  });
});

document.querySelectorAll<HTMLButtonElement>("button[data-guide-host-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = button.dataset.guideHostCopy === "port"
      ? String(snapshot?.settings.proxyPort ?? DEFAULT_PROXY_PORT)
      : "127.0.0.1";
    await copyText(value, t("copied"));
  });
});

byId<HTMLButtonElement>("guide-copy-socks5").addEventListener("click", async () => {
  const details = guideSocks5Details();
  if (!details.address || !details.port) return;
  const lines = [
    "SOCKS5",
    `${t("proxyAddressLabel")}: ${details.address}`,
    `${t("port")}: ${details.port}`,
  ];
  if (snapshot?.settings.lanAuthEnabled) {
    lines.push(
      `${t("username")}: ${snapshot.settings.proxyUsername}`,
      `${t("accessKey")}: ${snapshot.settings.proxyPassword}`,
    );
  } else {
    lines.push(t("loginNotRequired"));
  }
  await copyText(lines.join("\n"), t("phoneSocksDetailsCopied"));
});

byId<HTMLButtonElement>("guide-copy-ca").addEventListener("click", async () => {
  await copyText("http://homeproxy.test/ca.cer", t("caDownloadCopied"));
});

byId<HTMLButtonElement>("guide-copy-all").addEventListener("click", async () => {
  const details = guideProxyDetails();
  if (!details.address) return;
  const lines = [
    `${t("proxyAddressLabel")}: ${details.address}`,
    `${t("port")}: ${details.port}`,
  ];
  if (snapshot?.settings.lanAuthEnabled) {
    lines.push(
      `${t("username")}: ${details.username}`,
      `${t("accessKey")}: ${details.key}`,
    );
  } else {
    lines.push(t("loginNotRequired"));
  }
  await copyText(lines.join("\n"), t("proxyDetailsCopied"));
});

guideFinishButton.addEventListener("click", () => {
  if (!guideIsVerified()) return;
  markGuideSeen();
  showPage("home");
  window.setTimeout(() => serviceToggle.focus(), 0);
});

byId<HTMLButtonElement>("hide-to-tray").addEventListener("click", async () => {
  try {
    await invoke("hide_to_tray");
  } catch {
    showNotice(t("trayUnavailable"), "error");
  }
});

byId("discard-settings").addEventListener("click", async () => {
  if (!snapshot || busy) return;
  await runBusy(async () => {
    // A conflict can arrive before the polling loop sees the new revision.
    const latest = isLinux ? await invoke<AppSnapshot>("get_snapshot") : snapshot;
    if (!latest) return;
    byId("notice").hidden = true;
    (document.activeElement as HTMLElement | null)?.blur();
    byId("device-list").replaceChildren();
    deviceRenderSignature = "";
    guideCacheEnabled = latest.settings.cacheEnabled;
    syncFromSnapshot(latest, true);
  });
});
saveButton.addEventListener("click", async () => {
  if (!draft || busy || !dirty) return;
  await runBusy(async () => {
    await applyDirtyDraft();
  });
});

async function applyDirtyDraft(): Promise<boolean> {
  if (hasInvalidDeviceLimits()) { showNotice(t("invalidLimit"), "error"); return false; }
  const cacheValidation = currentCacheValidation();
  if (!cacheValidation.ok) { showNotice(cacheErrorText(cacheValidation), "error"); return false; }
  const offlineValidation = currentOfflineValidation();
  if (offlineValidation.error) { showNotice(offlineErrorText(offlineValidation.error), "error"); return false; }
  if(hasInvalidPolicy()){showNotice(t("policyInvalid"),"error");return false;}
  if(hasInvalidRouting()){showNotice(t("routingInvalid"),"error");return false;}
  if (!draft || !dirty) return true;
  const portError = validateServicePorts(draft);
  if (portError) {
    showNotice(servicePortErrorMessage(portError), "error");
    return false;
  }
  Object.assign(draft, cacheValidation.values);
  Object.assign(draft, offlineValidation.values);
  applyPolicyDraft();
  applyRoutingDraft();
  snapshot = await invoke<AppSnapshot>("apply_settings", { settings: draft, expectedRevision: draftRevision });
  syncFromSnapshot(snapshot, true);
  showNotice(t("settingsSaved"), "success");
  return true;
}

lanCheckbox.addEventListener("change", () => {
  if (!draft) return;
  draft.lanEnabled = lanCheckbox.checked;
  if (draft.lanEnabled && !draft.listenIp) {
    draft.listenIp = recommendedLanAddress(snapshot?.availableAddresses ?? [], "sameWifi")?.ip ?? null;
  }
  markDirty();
  renderSettings();
});

proxyPortInput.addEventListener("input", () => updateDraftPort("proxyPort", proxyPortInput));
socks5PortInput.addEventListener("input", () => updateDraftPort("socks5Port", socks5PortInput));
socks5UdpEnabledCheckbox.addEventListener("change", () => {
  if (!draft || !draft.socks5Enabled) return;
  draft.socks5UdpEnabled = socks5UdpEnabledCheckbox.checked;
  markDirty();
  renderSettings();
  renderGuide();
});
socks5EnabledCheckbox.addEventListener("change", () => {
  if (!draft) return;
  draft.socks5Enabled = socks5EnabledCheckbox.checked;
  markDirty();
  renderSettings();
  renderGuide();
});
document.querySelectorAll<HTMLButtonElement>("button[data-proxy-port-preset]").forEach((button) => {
  button.addEventListener("click", () => {
    if (!draft) return;
    draft.proxyPort = Number(button.dataset.proxyPortPreset);
    markDirty();
    renderSettings();
    renderGuide();
  });
});

lanAuthCheckbox.addEventListener("change", () => {
  if (!draft) return;
  draft.lanAuthEnabled = lanAuthCheckbox.checked;
  markDirty();
  renderSettings();
  renderGuide();
});

proxyUserInput.addEventListener("input", () => {
  if (!draft) return;
  draft.proxyUsername = proxyUserInput.value;
  markDirty();
});

proxyPasswordInput.addEventListener("input", () => {
  if (!draft) return;
  draft.proxyPassword = proxyPasswordInput.value;
  markDirty();
});

listenSelect.addEventListener("change", () => {
  if (!draft) return;
  draft.listenIps = Array.from(listenSelect.selectedOptions).map((option) => option.value).filter(Boolean);
  draft.listenIp = draft.listenIps[0] ?? null;
  markDirty();
});

cacheCheckbox.addEventListener("change", () => {
  if (!draft) return;
  draft.cacheEnabled = cacheCheckbox.checked;
  markDirty();
  renderSettings();
});

for (const field of CACHE_FIELDS) {
  cacheInputs[field].addEventListener("input", () => {
    if (!draft) return;
    const { min, max } = CACHE_BOUNDS[field];
    // An invalid entry leaves the last valid draft value untouched; saving stays blocked meanwhile.
    const parsed = parseCacheInteger(cacheInputs[field].value, min, max);
    if (parsed !== null) draft[field] = parsed;
    markDirty();
    renderSettings();
  });
}
document.querySelectorAll<HTMLButtonElement>("button[data-cache-preset]").forEach((button) => {
  button.addEventListener("click", () => {
    if (!draft || busy) return;
    draft.cacheLimitGib = Number(button.dataset.cachePreset);
    cacheInputs.cacheLimitGib.value = String(draft.cacheLimitGib);
    markDirty();
    renderSettings();
  });
});

document.querySelectorAll<HTMLDivElement>(".segmented[data-setting]").forEach((group) => {
  group.querySelectorAll<HTMLButtonElement>("button[data-value]").forEach((button) => {
    button.addEventListener("click", () => {
      if (!draft) return;
      const setting = group.dataset.setting;
      const value = button.dataset.value;
      if (!setting || value === undefined) return;
      if (setting === "adblockMode") draft.adblockMode = value as AdblockMode;
      if (setting === "compressionPreset") draft.compressionPreset = value as CompressionPreset;
      markDirty();
      renderSettings();
    });
  });
});

document.querySelectorAll<HTMLButtonElement>("button[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = button.dataset.copy;
    if (!target) return;
    await copyText(byId<HTMLInputElement>(target).value, t("copied"));
  });
});

byId<HTMLButtonElement>("reveal-password").addEventListener("click", () => {
  const input = byId<HTMLInputElement>("proxy-password");
  const reveal = byId<HTMLButtonElement>("reveal-password");
  input.type = input.type === "password" ? "text" : "password";
  reveal.textContent = input.type === "password" ? t("show") : t("hide");
});

byId<HTMLButtonElement>("rotate-password").addEventListener("click", async () => {
  if (busy) return;
  await runBusy(async () => {
    if (!(await applyDirtyDraft())) return;
    snapshot = await invoke<AppSnapshot>("rotate_proxy_password");
    syncFromSnapshot(snapshot, true);
    showNotice(t("newKeyActive"), "warning");
  });
});

let preparationError: string | null = null;
let preparationJobRenderState: PreparationJobRenderState | undefined;
let preparationPinsMarkup: string | undefined;
for (const id of ["preparation-urls", "preparation-budget", "preparation-pin"]) {
  byId(id).addEventListener("input", () => { preparationError = null; renderPreparationControls(); });
}
byId("prepare-offline").addEventListener("click", async () => {
  if (busy || !snapshot || dirty || snapshot.offlinePreparation?.activeJob) return;
  const requestData = preparationInput(byId<HTMLTextAreaElement>("preparation-urls").value, byId<HTMLInputElement>("preparation-budget").value, byId<HTMLInputElement>("preparation-pin").checked);
  if (!requestData) { preparationError = preparationReason("invalid-input", locale); renderPreparationControls(); return; }
  await runBusy(async () => {
    try {
      await invoke("prepare_offline", {requestData});
      snapshot = await invoke<AppSnapshot>("get_snapshot");
      syncFromSnapshot(snapshot);
      showNotice(t("preparationQueued"), "success");
    } catch (error) { preparationError = preparationFailure(error); renderPreparationControls(); }
  });
});
byId("cancel-preparation").addEventListener("click", async () => {
  const id = snapshot?.offlinePreparation?.activeJob;
  if (busy || !id) return;
  await runBusy(async () => {
    try { await invoke("cancel_offline_preparation", {id}); snapshot = await invoke<AppSnapshot>("get_snapshot"); syncFromSnapshot(snapshot); }
    catch (error) { preparationError = preparationFailure(error); renderPreparationControls(); }
  });
});
byId("preparation-pins").addEventListener("click", async (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-pin-key]");
  if (busy || !button?.dataset.pinKey) return;
  await runBusy(async () => {
    try { await invoke("release_offline_pin", {key: button.dataset.pinKey}); snapshot = await invoke<AppSnapshot>("get_snapshot"); syncFromSnapshot(snapshot); }
    catch (error) { preparationError = preparationFailure(error); renderPreparationControls(); }
  });
});

byId<HTMLButtonElement>("clear-cache").addEventListener("click", async () => {
  if (busy) return;
  await runBusy(async () => {
    await invoke("clear_cache");
    showNotice(t("cacheCleared"), "success");
  });
});

byId<HTMLButtonElement>("copy-address").addEventListener("click", async () => {
  const address = preferredProxyAddress();
  if (address) await copyText(address, t("addressCopied"));
});

byId<HTMLButtonElement>("copy-http-endpoint").addEventListener("click", async () => {
  if (!draft || dirty || !snapshot?.running) return;
  await copyText(serviceEndpoint(settingsPreviewHost(), draft.proxyPort), t("copied"));
});

byId<HTMLButtonElement>("copy-socks5-endpoint").addEventListener("click", async () => {
  if (!draft?.socks5Enabled || dirty || !snapshot?.running) return;
  await copyText(serviceEndpoint(settingsPreviewHost(), draft.socks5Port), t("copied"));
});


function selectedLanIps(settings: Settings): string[] {
  return settings.listenIps?.length ? settings.listenIps : settings.listenIp ? [settings.listenIp] : [];
}

function closeTransferReset(): void {
  byId("traffic-reset-confirmation").hidden = true;
  byId("traffic-reset").setAttribute("aria-expanded", "false");
  byId("traffic-reset").focus();
}

function renderTransferReset(): void {
  const unavailable = busy || !snapshot || snapshotUnavailable;
  byId<HTMLButtonElement>("traffic-reset").disabled = unavailable;
  byId<HTMLButtonElement>("traffic-reset-confirm").disabled = unavailable;
  byId<HTMLButtonElement>("traffic-reset-cancel").disabled = busy;
  byId("traffic-reset-confirmation").setAttribute("aria-busy", String(busy));
  setTextIfChanged(byId("traffic-reset-confirm"), t(busy ? "trafficResetWorking" : "trafficResetConfirm"));
}

byId("traffic-reset").addEventListener("click", () => {
  if (busy || !snapshot || snapshotUnavailable) return;
  const panel = byId("traffic-reset-confirmation");
  if (!panel.hidden) {
    closeTransferReset();
    return;
  }
  panel.hidden = false;
  byId("traffic-reset").setAttribute("aria-expanded", "true");
  byId("traffic-reset-cancel").focus();
});
byId("traffic-reset-cancel").addEventListener("click", closeTransferReset);
byId("traffic-reset-confirmation").addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !busy) {
    event.preventDefault();
    closeTransferReset();
  }
});
byId("traffic-reset-confirm").addEventListener("click", () => {
  if (!snapshot || snapshotUnavailable) return;
  void runBusy(async () => {
    const stats = await invoke<Stats>("reset_transfer_stats");
    // Use the actual reply: ongoing transfers may already have added new bytes.
    if (snapshot) snapshot.stats = stats;
    byId("traffic-reset-confirmation").hidden = true;
    byId("traffic-reset").setAttribute("aria-expanded", "false");
    showNotice(t("trafficResetDone"), "success");
  }).finally(() => {
    // Disabling a focused button can move focus to the document. Restore it
    // after success or failure so retry and Escape remain keyboard-accessible.
    byId(byId("traffic-reset-confirmation").hidden ? "traffic-reset" : "traffic-reset-confirm").focus();
  });
});

byId("activity-pause").addEventListener("click", () => {
  activityPaused = !activityPaused;
  byId("activity-pause").setAttribute("aria-pressed", String(activityPaused));
  byId("activity-pause").textContent = t(activityPaused ? "resumeActivity" : "pauseActivity");
  renderActivity();
});
byId("activity-filter").addEventListener("input", () => renderActivity());
byId("activity-reset-filter").addEventListener("click", () => {
  byId<HTMLInputElement>("activity-filter").value = "";
  renderActivity();
  byId<HTMLInputElement>("activity-filter").focus();
});
byId("activity-clear").addEventListener("click", () => void runBusy(async () => {
  activitySnapshotGeneration += 1;
  await invoke("clear_activity");
  displayedActivity = [];
  if (snapshot) {
    snapshot.stats.activity = [];
    snapshot.stats.latestConnectionRejection = null;
  }
  renderConnectionRejections();
  renderActivity();
}));
function renderConnectionRejections(): void {
  const count = snapshot?.stats.rejectedConnections ?? 0;
  const latest = snapshot?.stats.latestConnectionRejection ?? null;
  byId("connection-rejections").hidden = count === 0 && !latest;
  setTextIfChanged(byId("connection-rejection-total"), t("rejectedConnectionsHistory", { count: formatCount(count) }));
  setTextIfChanged(byId("connection-rejection-latest"), latest ? t("lastConnectionRejection", {
    time: formatActivityTime(latest.unixMs),
    peer: latest.peerIp,
    listener: latest.listenerIp,
    reason: t(latest.reason === "peer-limit" ? "connectionPeerLimit" : "connectionGlobalLimit", { limit: formatCount(latest.limit) }),
  }) : "");
  byId("connection-rejection-latest").hidden = !latest;
}

function renderActivity(): void {
  if (!activityPaused) displayedActivity = (snapshot?.stats.activity ?? []).slice(-256);
  const filter = byId<HTMLInputElement>("activity-filter").value.toLocaleLowerCase();
  const container = byId("activity-list");
  const rows = displayedActivity.filter((entry) => [entry.peerIp, entry.listenerIp, entry.host, entry.protocol, entry.status, entry.cacheStatus, translateActivityValue(entry.status, locale), translateActivityValue(entry.cacheStatus, locale)].some((value) => value.toLocaleLowerCase().includes(filter))).slice().reverse();
  container.replaceChildren();
  byId<HTMLButtonElement>("activity-clear").disabled = busy;
  byId("activity-reset-filter").hidden = !filter;
  if (!rows.length) { const empty = document.createElement("p"); empty.textContent = t(filter && displayedActivity.length ? "noMatchingActivity" : "noActivity"); container.append(empty); }
  for (const entry of rows) {
    const row = document.createElement("article"); row.className = "activity-row";
    const title = document.createElement("strong");
    title.textContent = `${entry.protocol} · ${entry.host || "—"} · ${translateActivityValue(entry.status, locale)}`;
    const meta = document.createElement("small");
    meta.textContent = `${formatActivityTime(entry.startedUnixMs)}${entry.endedUnixMs ? ` → ${formatActivityTime(entry.endedUnixMs)}` : ""} · ${entry.peerIp} → ${entry.listenerIp}`;
    const bytes = document.createElement("small");
    bytes.textContent = `↑ ${formatBytes(entry.uploadBytes)} (${formatBytes(entry.uploadBytesPerSecond)}/s) · ↓ ${formatBytes(entry.downloadBytes)} (${formatBytes(entry.downloadBytesPerSecond)}/s)`;
    const cache = document.createElement("small");
    cache.textContent = `${translateActivityValue(entry.cacheStatus, locale)}${entry.cacheBypassReason ? ` · ${translateActivityValue(entry.cacheBypassReason, locale)}` : ""} · ${t("bodyEvidence", { origin: formatBytes(entry.originBytes), delivered: formatBytes(entry.deliveredBytes) })}`;
    row.append(title, meta, bytes, cache);
    if (entry.error) { const error = document.createElement("small"); error.textContent = translateActivityValue(entry.error, locale); row.append(error); }
    container.append(row);
  }
}

function showPage(page: string): void {
  byId("settings-savebar").hidden = page !== "settings" || !dirty;
  document.querySelectorAll<HTMLButtonElement>(".nav-link").forEach((button) => {
    const active = button.dataset.page === page;
    button.classList.toggle("is-active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  document.querySelectorAll<HTMLElement>(".page").forEach((element) => {
    const active = element.id === `${page}-page`;
    element.classList.toggle("is-active", active);
    if (active) element.scrollTop = 0;
  });
}

function renderAbout(next: AppSnapshot | null): void {
  const versions = aboutVersions(__APP_VERSION__, next?.serviceVersion, isLinux);
  byId<HTMLElement>("about-app-version").textContent = versions.app;
  byId<HTMLElement>("about-service-row").hidden = versions.service === null;
  byId<HTMLElement>("about-service-version").textContent = versions.service ?? "";
  const mismatch = byId<HTMLElement>("about-version-mismatch");
  mismatch.hidden = !versions.mismatch;
  mismatch.textContent = versions.mismatch ? t("aboutVersionMismatch", { app: versions.app, service: versions.service ?? "" }) : "";
}
renderAbout(null);

function syncFromSnapshot(next: AppSnapshot, forceDraft = false): void {
  snapshot = next;
  snapshotUnavailable = false;
  // These public facts are authoritative, including a removed or replaced CA.
  if (next.httpsAuthority) tlsStatus = { ...next.httpsAuthority };
  syncGuideSelection(next);
  const settingsChanged = !draft || JSON.stringify(draft) !== JSON.stringify(next.settings);
  if ((!dirty && settingsChanged) || forceDraft) {
    draft = structuredClone(next.settings);
    draft.automaticRecovery ??= true;
    draft.socks5UdpEnabled ??= false;
    draft.httpsInspectHosts ??= [];
    draft.httpsInspectionScope ??= "selectedHosts";
    draft.httpsBypassHosts ??= [];
    draft.httpsClientTrustAcknowledged ??= false;
    draft.cacheMode ??= "online";
    draft.offlineMaxStaleHours ??= 168;
    draft.publicCacheEndpoints ??= [];
    draft.allowDomains ??= [];draft.blockDomains ??= [];draft.noCacheDomains ??= [];draft.deviceProfiles ??= [];
    draft.historyRetentionDays ??= 90;draft.scheduleUtcOffsetMinutes ??= 0;
    draft.pacEnabled??=false;draft.pacDirectFallback??=false;draft.upstreamProxies??=[];draft.upstreamDirectFallback??=false;
    draft.lanDnsEnabled??=false;draft.lanDnsPort??=5353;draft.lanDnsUpstream??="1.1.1.1:53";
    draft.filterFeeds??=[];
    cacheInputsNeedReset = true;
    offlineInputsNeedReset = true;
    policyInputsNeedReset=true;profileEditorSignature="";
    routingInputsNeedReset=true;upstreamEditorSignature="";
    draftRevision = next.revision;
    dirty = false;
    // Older services may not support inspection; saving must not silently activate it.
    if (!inspectionSupported() && draft.httpsMode === "inspect") {
      draft.httpsMode = "tunnel";
      dirty = true;
    }
  }
  if (!dirty) draftRevision = next.revision;
  render();
}

function syncGuideSelection(next: AppSnapshot): void {
  if (!guideSelectionInitialized) {
    const configured = next.availableAddresses.find((address) => address.ip === next.settings.listenIp);
    const configuredKind = configured ? classifyLanAddress(configured) : null;
    guideConnectionMode = configuredKind === "hotspot" ? "hotspot" : "sameWifi";
    guideSelectedIp = configured && !isUnsafeGuideAddress(configuredKind)
      ? configured.ip
      : recommendedLanAddress(next.availableAddresses, guideConnectionMode)?.ip ?? null;
    guideCacheEnabled = next.settings.cacheEnabled;
    guideSelectionInitialized = true;
    return;
  }

  const recommended = recommendedLanAddress(next.availableAddresses, guideConnectionMode);
  if (guideConnectionMode === "hotspot" && recommended) {
    guideSelectedIp = recommended.ip;
    guideHotspotFallbackVisible = false;
    return;
  }

  guideSelectedIp = availableGuideSelection(next.availableAddresses, guideSelectedIp, guideConnectionMode);
}

function render(): void {
  renderDiagnostics();
  renderTransferReset();
  renderAbout(snapshot);
  if (!snapshot || !draft) return;
  const running = snapshot.running;

  const [savedNumber, savedUnit] = formatBytesParts(snapshot.stats.savedBytes);
  byId("saved-total").innerHTML = `${savedNumber} <em>${savedUnit}</em>`;
  byId("blocked-count").textContent = `${formatCount(snapshot.stats.blockedRequests)} ${t("blockedSuffix")}`;
  byId("image-saving").textContent = formatBytes(snapshot.stats.compressionBytesSaved);
  byId("cache-saving").textContent = formatBytes(snapshot.stats.cacheBytesSaved);
  byId("savings-status").textContent = savingsStatus(snapshot.settings, running)
    .map((key) => t(key)).join(" ")
    + (running && snapshot.stats.savedBytes === 0 ? ` ${t("savingsAwaiting")}` : "");
  byId("client-count").textContent = formatCount(snapshot.stats.uniqueClients);
  byId("request-count").textContent = formatCount(snapshot.stats.totalRequests);
  for (const direction of ["upload", "download"] as const) {
    byId(`${direction}-total`).textContent = formatBytes(snapshot.stats[`${direction}Bytes`] ?? 0);
    byId(`${direction}-rate`).textContent = `${formatBytes(snapshot.stats[`${direction}BytesPerSecond`] ?? 0)}/s`;
  }
  const resetAt = snapshot.stats.transferStatsResetUnixMs;
  byId("traffic-period").textContent = t(resetAt != null ? "trafficSinceReset" : "trafficSinceStart");
  byId("traffic-period").title = resetAt != null ? formatActivityTime(resetAt) : "";
  renderConnectionRejections();
  byId("body-evidence").textContent = t("bodyEvidence", { origin: formatBytes(snapshot.stats.originBytes ?? 0), delivered: formatBytes(snapshot.stats.deliveredBytes ?? 0) });
  byId("cache-evidence").textContent = `HIT ${formatCount(snapshot.stats.cacheHits)} · MISS ${formatCount(snapshot.stats.cacheMisses ?? 0)} · ${translateActivityValue("bypass", locale)} ${formatCount(snapshot.stats.cacheBypasses ?? 0)}`;
  const topBypassReasons = topCacheBypassReasons(snapshot.stats.cacheBypassReasons);
  const bypassReasons = byId("cache-bypass-reasons");
  bypassReasons.hidden = topBypassReasons.length === 0;
  bypassReasons.textContent = topBypassReasons.length === 0 ? "" : t("cacheBypassTopReasons", {
    reasons: topBypassReasons.map(({ code, count }) => `${cacheBypassReasonLabel(code, locale)} (${formatCount(count)})`).join(" · "),
  });
  renderActivity();

  byId("profile-ads").textContent = adblockLabel(snapshot.settings.adblockMode);
  byId("profile-images").textContent = compressionLabel(snapshot.settings.compressionPreset);
  byId("https-summary").textContent = t(!inspectionSupported() || snapshot.settings.httpsMode === "tunnel" ? "httpsTunnelCopy" : "httpsInspectCopy");
  const cacheLabel = cacheProfileLabel(snapshot.settings, inspectionSupported());
  byId("profile-cache").textContent = t(cacheLabel.key, { size: cacheLabel.size });

  const address = preferredProxyAddress();
  byId("proxy-address").textContent = address ?? (running ? t("thisPcOnly") : t("turnOnFirst"));
  byId<HTMLButtonElement>("copy-address").disabled = !address;
  byId("hero-copy").textContent = running
    ? t("savedExplanation")
    : t("stoppedExplanation");

  if (snapshot.listenerError) {
    showNotice(listenerBindFailureMessage(snapshot.listenerError), "error", false);
  } else if (snapshot.lastError) {
    const savedAddress = snapshot.settings.listenIp;
    const staleSavedAddress = snapshot.lastError === "Vybraná adresa teď není na tomto počítači dostupná."
      && savedAddress
      && !snapshot.availableAddresses.some((address) => address.ip === savedAddress);
    showNotice(staleSavedAddress
      ? t("savedAddressUnavailable", { address: savedAddress ?? "" })
      : translateBackendMessage(snapshot.lastError, locale), "error", false);
  } else if (byId("notice").dataset.source === "backend") {
    byId("notice").hidden = true;
  }
  if (snapshot.listenerError || snapshot.lastError) byId("notice").dataset.source = "backend";
  renderSettings();
  renderDevices();
  renderGuide();
}

function renderSettings(): void {
  if (!snapshot || !draft) return;
  lanCheckbox.checked = draft.lanEnabled;
  lanAuthCheckbox.checked = draft.lanAuthEnabled;
  cacheCheckbox.checked = draft.cacheEnabled;
  byId<HTMLSelectElement>("dns-mode").value = draft.dnsMode ?? "system";
  byId<HTMLSelectElement>("dns-mode").disabled = busy;
  byId("dns-mode-help").textContent = t(draft.dnsMode === "cloudflare" ? "dnsCloudflareCopy" : "dnsSystemCopy");
  byId<HTMLSelectElement>("https-mode").value = draft.httpsMode ?? "inspect";
  byId<HTMLSelectElement>("https-mode").disabled = busy;
  byId("https-mode-help").textContent = t(!inspectionSupported() || draft.httpsMode === "tunnel" ? "httpsTunnelCopy" : "httpsInspectCopy");
  syncPortInput(proxyPortInput, draft.proxyPort);
  socks5EnabledCheckbox.checked = draft.socks5Enabled;
  socks5UdpEnabledCheckbox.checked = draft.socks5UdpEnabled ?? false;
  socks5UdpEnabledCheckbox.disabled = busy || !draft.socks5Enabled;
  syncPortInput(socks5PortInput, draft.socks5Port);
  socks5PortInput.disabled = !draft.socks5Enabled;
  listenSelect.disabled = !draft.lanEnabled;
  const addressRenderSignature = JSON.stringify(snapshot.availableAddresses);
  if (addressRenderSignature !== settingsAddressRenderSignature) {
    settingsAddressRenderSignature = addressRenderSignature;
    listenSelect.replaceChildren();
    if (snapshot.availableAddresses.length === 0) {
      listenSelect.add(new Option(t("noPrivateAddress"), ""));
    } else {
      snapshot.availableAddresses.forEach((address) => {
        listenSelect.add(new Option(
          `${address.ip} · ${address.interfaceName} — ${addressKindLabel(classifyLanAddress(address))}`,
          address.ip,
        ));
      });
    }
  }
  const selectedIps = new Set(selectedLanIps(draft));
  Array.from(listenSelect.options).forEach((option) => { option.selected = selectedIps.has(option.value); });
  proxyUserInput.value = draft.proxyUsername;
  proxyPasswordInput.value = draft.proxyPassword;
  byId("open-lan-warning").hidden = draft.lanAuthEnabled;
  byId("port-80-warning").hidden = draft.proxyPort !== 80;
  const portError = validateServicePorts(draft);
  byId("service-port-error").textContent = portError ? servicePortErrorMessage(portError) : "";
  const servicePortsChanged = snapshot.settings.dnsMode !== draft.dnsMode
    || snapshot.settings.httpsMode !== draft.httpsMode
    || (snapshot.settings.httpsInspectionScope ?? "selectedHosts") !== draft.httpsInspectionScope
    || (snapshot.settings.cacheMode ?? "online") !== draft.cacheMode
    || JSON.stringify(snapshot.settings.httpsInspectHosts ?? []) !== JSON.stringify(draft.httpsInspectHosts)
    || JSON.stringify(snapshot.settings.httpsBypassHosts ?? []) !== JSON.stringify(draft.httpsBypassHosts)
    || snapshot.settings.lanEnabled !== draft.lanEnabled
    || JSON.stringify(selectedLanIps(snapshot.settings)) !== JSON.stringify(selectedLanIps(draft))
    || snapshot.settings.proxyPort !== draft.proxyPort
    || snapshot.settings.socks5Enabled !== draft.socks5Enabled
    || (snapshot.settings.socks5UdpEnabled ?? false) !== draft.socks5UdpEnabled
    || snapshot.settings.socks5Port !== draft.socks5Port;
  byId("service-restart-note").hidden = !(snapshot.running && servicePortsChanged);
  const previewHost = settingsPreviewHost();
  byId("http-endpoint-preview").textContent = serviceEndpoint(previewHost, draft.proxyPort);
  byId("socks5-endpoint-preview").textContent = draft.socks5Enabled
    ? serviceEndpoint(previewHost, draft.socks5Port)
    : t("disabledEndpoint");
  byId("socks5-endpoint-row").toggleAttribute("data-disabled", !draft.socks5Enabled);
  byId("endpoint-state").textContent = t(dirty ? "endpointDraft" : snapshot.running ? "endpointSaved" : "endpointStopped");
  const activeAddresses = [...snapshot.proxyAddresses.map((address) => `HTTP ${address}`), ...snapshot.socks5Addresses.map((address) => `SOCKS5 ${address}`)];
  byId("active-endpoints").textContent = snapshot.running && activeAddresses.length ? `${t("activeEndpoints")}: ${activeAddresses.join(" · ")}` : t("endpointStopped");
  byId<HTMLButtonElement>("copy-socks5-endpoint").disabled = dirty || !snapshot.running || !draft.socks5Enabled || Boolean(portError) || !snapshot.socks5Addresses.includes(serviceEndpoint(previewHost, draft.socks5Port));
  byId<HTMLButtonElement>("copy-http-endpoint").disabled = dirty || !snapshot.running || Boolean(portError) || !snapshot.proxyAddresses.includes(serviceEndpoint(previewHost, draft.proxyPort));
  byId("socks5-connection-count").textContent = draft.socks5Enabled
    ? t("socks5ConnectionsSinceStart", { count: formatCount(snapshot.stats.socks5Connections) })
    : "";
  document.querySelectorAll<HTMLButtonElement>("button[data-proxy-port-preset]").forEach((button) => {
    const active = Number(button.dataset.proxyPortPreset) === draft?.proxyPort;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });

  document.querySelectorAll<HTMLDivElement>(".segmented[data-setting]").forEach((group) => {
    const setting = group.dataset.setting;
    const selected = setting === "adblockMode"
      ? draft?.adblockMode
      : setting === "compressionPreset"
        ? draft?.compressionPreset
        : "";
    group.querySelectorAll<HTMLButtonElement>("button[data-value]").forEach((button) => {
      const active = button.dataset.value === String(selected);
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
  });
  renderCacheControls();
  renderOfflineControls();
  renderPreparationControls();
  renderPolicyControls();
  renderRoutingControls();
  const cacheInvalid = !currentCacheValidation().ok;
  const offlineInvalid = Boolean(currentOfflineValidation().error) || hasInvalidPolicy() || hasInvalidRouting();
  byId("settings-savebar").hidden = !dirty || !byId("settings-page").classList.contains("is-active");
  byId<HTMLButtonElement>("discard-settings").disabled = busy;
  byId("settings-save-state").textContent = t(portError || cacheInvalid || offlineInvalid || hasInvalidDeviceLimits() ? "pendingInvalidChanges" : "pendingChanges");
  saveButton.disabled = !dirty || busy || Boolean(portError) || cacheInvalid || offlineInvalid || Boolean(hasInvalidDeviceLimits());
  setTextIfChanged(saveButton, busy
    ? t("working")
    : snapshot.running && servicePortsChanged
      ? t("saveAndRestart")
      : t("saveChanges"));
}

/** The visible inputs are the source of truth, so half-typed text is never replaced by a stale draft value. */
function readCacheRaw(): CacheRawInput {
  return {
    cacheLimitGib: cacheInputs.cacheLimitGib.value,
    cacheMaxObjectMib: cacheInputs.cacheMaxObjectMib.value,
    responseBufferLimitMib: cacheInputs.responseBufferLimitMib.value,
    responseBufferBudgetMib: cacheInputs.responseBufferBudgetMib.value,
  };
}

function currentOfflineValidation() {
  const raw: OfflineRaw = {inspectHosts:offlineInputs.inspectHosts.value,bypassHosts:offlineInputs.bypassHosts.value,endpoints:offlineInputs.endpoints.value,staleHours:offlineInputs.staleHours.value};
  return validateOfflineInputs(raw, draft?.httpsMode ?? "tunnel", draft?.httpsClientTrustAcknowledged ?? false, draft?.httpsInspectionScope ?? "selectedHosts");
}
function offlineErrorText(error: "hosts" | "endpoints" | "staleHours" | "trust"): string {
  return t(({hosts:"offlineHostsError", endpoints:"offlineEndpointsError", staleHours:"offlineStaleError", trust:"offlineTrustError"} as const)[error]);
}
function preparationFailure(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const code = message.match(/offline-preparation:([a-z-]+)/)?.[1];
  return code ? preparationReason(code, locale) : translateBackendMessage(message, locale);
}
function renderPreparationControls(): void {
  if (!snapshot) return;
  const status = snapshot.offlinePreparation;
  const input = preparationInput(byId<HTMLTextAreaElement>("preparation-urls").value, byId<HTMLInputElement>("preparation-budget").value, byId<HTMLInputElement>("preparation-pin").checked);
  const active = Boolean(status?.activeJob);
  byId<HTMLButtonElement>("prepare-offline").disabled = busy || dirty || active || !status || !snapshot.running || !snapshot.settings.cacheEnabled || snapshot.settings.cacheMode !== "online" || !input;
  for (const id of ["preparation-urls", "preparation-budget", "preparation-pin"]) byId<HTMLInputElement>(id).disabled = busy || active || !status;
  const cancel = byId<HTMLButtonElement>("cancel-preparation"); cancel.hidden = !active; cancel.disabled = busy;
  let error = preparationError;
  if (!error && !status) error = t("preparationServiceOld");
  if (!error && dirty) error = t("preparationSaveFirst");
  if (!error && status?.errorCode) error = preparationReason(status.errorCode, locale);
  if (!error && status && !snapshot.running) error = preparationReason("proxy-stopped", locale);
  if (!error && status && snapshot.settings.cacheMode === "offline") error = preparationReason("offline-mode", locale);
  if (!error && status && !snapshot.settings.cacheEnabled) error = preparationReason("cache-disabled", locale);
  if (!error && byId<HTMLTextAreaElement>("preparation-urls").value.trim() && !input) error = preparationReason("invalid-input", locale);
  byId("preparation-error").textContent = error ?? "";
  const usage = status?.pinUsage;
  if (usage?.degraded && !error) {
    byId("preparation-error").textContent = preparationReason("pin-quota", locale);
  }
  byId("preparation-quota").textContent = usage ? t("preparationQuota", {used:formatBinaryBytes(usage.usedBytes),limit:formatBinaryBytes(usage.limitBytes)}) : "";
  const escape = escapePreparationText;
  const jobs = status?.jobs.slice().reverse() ?? [];
  const jobMarkup = jobs.map(job => ({id: job.id, content: `<summary>${escape(preparationReason(job.state,locale))} · ${escape(formatBinaryBytes(job.receivedBytes))} / ${escape(formatBinaryBytes(job.budgetBytes))}</summary><ul>${job.items.map(item=>`<li><span class="preparation-label">${escape(item.label)}</span><span class="preparation-state ${item.offlineReady?"is-ready":""}">${escape(preparationReason(item.state,locale))}${item.storedBytes ? ` · ${escape(t("preparationStored"))} ${escape(formatBinaryBytes(item.storedBytes))}`:""}${item.pinned?` · ${escape(t("preparationPinned"))}`:""} · ${escape(t(item.offlineReady?"preparationReady":"preparationUnavailable"))}</span>${item.errorCode?`<span class="field-error">${escape(preparationReason(item.errorCode,locale))}</span>`:""}</li>`).join("")}</ul>`}));
  const jobsElement = byId("preparation-jobs");
  const focused = document.activeElement as HTMLElement | null;
  const focusedJobId = focused?.tagName === "SUMMARY" && jobsElement.contains(focused)
    ? focused.closest<HTMLElement>("details[data-job-id]")?.dataset.jobId ?? null : null;
  const jobUpdate = updatePreparationJobs(preparationJobRenderState, jobMarkup,
    [...jobsElement.querySelectorAll<HTMLDetailsElement>("details[data-job-id]")].map(job => ({id: job.dataset.jobId!, open: job.open})),
    `<p class="field-help">${escape(t("preparationEmpty"))}</p>`, focusedJobId);
  preparationJobRenderState = jobUpdate.state;
  if (jobUpdate.markup !== null) {
    jobsElement.innerHTML = jobUpdate.markup;
    if (jobUpdate.restoreFocusJobId !== null) {
      [...jobsElement.querySelectorAll<HTMLDetailsElement>("details[data-job-id]")]
        .find(job => job.dataset.jobId === jobUpdate.restoreFocusJobId)?.querySelector<HTMLElement>("summary")?.focus({preventScroll: true});
    }
  }
  const pins = status?.pins ?? [];
  const pinContent = pins.length ? `<h3>${escape(t("preparationPins"))}</h3><ul>${pins.map(pin=>`<li><span class="preparation-label">${escape(pin.label)}</span><span>${escape(formatBinaryBytes(pin.bytes))}</span><button type="button" class="secondary-button" data-pin-key="${escape(pin.key)}" ${busy?"disabled":""} aria-label="${escape(t("preparationUnpin"))}: ${escape(pin.label)}">${escape(t("preparationUnpin"))}</button></li>`).join("")}</ul>` : "";
  const pinsElement = byId("preparation-pins");
  if (preparationPinsMarkup !== pinContent) {
    const focusedPinKey = focused instanceof HTMLButtonElement && pinsElement.contains(focused) ? focused.dataset.pinKey : undefined;
    pinsElement.innerHTML = pinContent;
    preparationPinsMarkup = pinContent;
    if (focusedPinKey !== undefined) [...pinsElement.querySelectorAll<HTMLButtonElement>("button[data-pin-key]")]
      .find(button => button.dataset.pinKey === focusedPinKey)?.focus({preventScroll: true});
  }
}

function renderOfflineControls(): void {
  if (!draft) return;
  if (offlineInputsNeedReset) {
    offlineInputs.inspectHosts.value = draft.httpsInspectHosts.join("\n");
    offlineInputs.bypassHosts.value = draft.httpsBypassHosts.join("\n");
    offlineInputs.endpoints.value = draft.publicCacheEndpoints.map((item) => `${item.host}${item.pathPrefix}`).join("\n");
    offlineInputs.staleHours.value = String(draft.offlineMaxStaleHours);
    offlineInputsNeedReset = false;
  }
  for (const input of Object.values(offlineInputs)) input.disabled = busy;
  const allHosts = draft.httpsInspectionScope === "allSupportedHosts";
  const showHosts = showInspectHostEditor(draft.httpsInspectionScope, offlineInputs.inspectHosts.value,
    document.activeElement === offlineInputs.inspectHosts);
  byId("https-selected-hosts").hidden = !showHosts;
  offlineInputs.inspectHosts.disabled = busy || !showHosts;
  byId<HTMLSelectElement>("https-inspection-scope").value = draft.httpsInspectionScope;
  byId<HTMLSelectElement>("https-inspection-scope").disabled = busy || !inspectionSupported();
  byId("https-scope-help").textContent = t(allHosts ? "httpsScopeAllHelp" : "httpsScopeSelectedHelp");
  byId<HTMLInputElement>("https-trust-ack").checked = draft.httpsClientTrustAcknowledged;
  byId<HTMLInputElement>("https-trust-ack").disabled = busy;
  byId<HTMLSelectElement>("cache-mode").value = draft.cacheMode;
  byId<HTMLSelectElement>("cache-mode").disabled = busy;
  byId("offline-mode-note").textContent = t(draft.cacheMode === "offline" ? "offlineActiveNote" : "offlineOnlineNote");
  const error = currentOfflineValidation().error;
  byId("offline-settings-error").textContent = error ? offlineErrorText(error) : "";
  for (const id of ["https-mode", "guide-https-mode"]) {
    const option = byId<HTMLSelectElement>(id).querySelector<HTMLOptionElement>('option[value="inspect"]');
    if (option) option.disabled = !inspectionSupported();
  }
  byId("https-inspect-unavailable").hidden = inspectionSupported();
  byId("tls-authority-state").textContent = t(tlsStatus?.prepared ? "tlsPrepared" : "tlsNotPrepared");
  byId("tls-fingerprint").textContent = tlsStatus?.sha256Fingerprint ? `SHA-256: ${tlsStatus.sha256Fingerprint}` : "";
  byId<HTMLButtonElement>("prepare-tls").disabled = busy || !inspectionSupported();
  byId<HTMLButtonElement>("export-tls").disabled = busy || !tlsStatus?.prepared;
}

function hasInvalidPolicy(): boolean {
  if(!draft)return false;
  if(Object.values(policyInputs).some(input=>parseHostRules(input.value)===null))return true;
  const retention=byId<HTMLInputElement>("history-retention").value;
  const offset=byId<HTMLInputElement>("schedule-utc-offset").value;
  if(!/^\d+$/.test(retention)||Number(retention)<1||Number(retention)>366||! /^-?\d+$/.test(offset)||Number(offset)<-720||Number(offset)>840)return true;
  const profiles=draft.deviceProfiles;
  if(!validProfiles(profiles,draft.proxyUsername))return true;
  return Boolean(byId("profile-editors").querySelector('[data-invalid="true"]'));
}
function applyPolicyDraft():void {
  if(!draft)return;
  for(const [field,input] of Object.entries(policyInputs)) draft[field as keyof typeof policyInputs]=parseHostRules(input.value)!;
  draft.historyRetentionDays=Number(byId<HTMLInputElement>("history-retention").value);
  draft.scheduleUtcOffsetMinutes=Number(byId<HTMLInputElement>("schedule-utc-offset").value);
}
function renderPolicyControls(): void {
  if(!draft)return;
  if(policyInputsNeedReset){
    for(const [field,input] of Object.entries(policyInputs))input.value=draft[field as keyof typeof policyInputs].join("\n");
    byId<HTMLInputElement>("history-retention").value=String(draft.historyRetentionDays);
    byId<HTMLInputElement>("schedule-utc-offset").value=String(draft.scheduleUtcOffsetMinutes);
    policyInputsNeedReset=false;
  }
  for(const input of Object.values(policyInputs))input.disabled=busy;
  for(const id of ["history-retention","schedule-utc-offset"])byId<HTMLInputElement>(id).disabled=busy;
  const container=byId("profile-editors");
  const signature=JSON.stringify([draft.deviceProfiles,busy]);
  if(signature!==profileEditorSignature&&!container.contains(document.activeElement)&&!container.querySelector('[data-invalid="true"]')){
    renderProfileEditors(container,draft.deviceProfiles,key=>t(key as Parameters<typeof t>[0]),()=>{markDirty();},busy);
    profileEditorSignature=signature;
  }
  container.querySelectorAll<HTMLInputElement|HTMLButtonElement|HTMLSelectElement>("input,button,select").forEach(input=>input.disabled=busy);
  byId<HTMLButtonElement>("add-profile").disabled=busy||draft.deviceProfiles.length>=256;
  byId("policy-settings-error").textContent=hasInvalidPolicy()?t("policyInvalid"):"";
  byId<HTMLButtonElement>("refresh-history").disabled=busy;
  document.querySelectorAll<HTMLButtonElement>("[data-history-export]").forEach(button=>button.disabled=busy);
  byId<HTMLButtonElement>("import-feed").disabled=busy;
  byId<HTMLInputElement>("feed-name").disabled=busy;byId<HTMLInputElement>("feed-file").disabled=busy;
  const feeds=byId("feed-list");
  const feedSignature=JSON.stringify([draft.filterFeeds,busy]);
  if(feedSignature!==feedRenderSignature){
  feeds.replaceChildren();
  for(const feed of draft.filterFeeds){const row=document.createElement("p");row.className="button-row";const name=document.createElement("span");name.textContent=`${feed.name} · ${formatCount(feed.domainsSortedExact.length+feed.domainsSortedWildcard.length)} ${t("feedRules")}`;row.append(name);
    const remove=document.createElement("button");remove.type="button";remove.className="secondary-button";remove.textContent=t("feedRemove");remove.disabled=busy;
    remove.addEventListener("click",()=>void runBusy(async()=>{if(dirty&&!await applyDirtyDraft())return;const next=await invoke<AppSnapshot>("remove_filter_feed",{id:feed.id,expectedRevision:draftRevision});syncFromSnapshot(next,true);showNotice(t("feedRemoved"),"success");}));row.append(remove);feeds.append(row);
  }
  feedRenderSignature=feedSignature;
  }
  const profiles=draft.deviceProfiles;
  const alertLines=(snapshot?.quotaStatuses??[]).filter(quota=>quota.warning||quota.blocked||!quota.historyHealthy).map(quota=>{
    const name=profiles.find(p=>p.id===quota.profileId)?.name??quota.profileId;
    return `${name}: ${t(!quota.historyHealthy?"historyUnavailable":quota.blocked?"quotaBlocked":"quotaWarning")} · ${t("quotaDaily")} ${formatBytes(quota.dailyBytes)} / ${quota.dailyQuotaMib?formatBytes(quota.dailyQuotaMib*1048576):t("quotaUnlimited")} · ${t("quotaMonthly")} ${formatBytes(quota.monthlyBytes)} / ${quota.monthlyQuotaMib?formatBytes(quota.monthlyQuotaMib*1048576):t("quotaUnlimited")}`;
  });
  const alerts=byId("quota-alerts");
  if(alerts.dataset.lines!==JSON.stringify(alertLines)){
    alerts.replaceChildren(...alertLines.map(text=>{const line=document.createElement("p");line.className="field-help";line.textContent=text;return line;}));
    alerts.dataset.lines=JSON.stringify(alertLines);
  }
}
function hasInvalidRouting():boolean {
  if(!draft)return false;
  const port=parseServicePort(byId<HTMLInputElement>("lan-dns-port").value);
  const upstream=byId<HTMLInputElement>("lan-dns-upstream").value;
  if(!port||draft.lanDnsEnabled&&(port===draft.proxyPort||draft.socks5Enabled&&port===draft.socks5Port))return true;
  const socket=/^(\d{1,3}(?:\.\d{1,3}){3}):([1-9]\d{0,4})$/.exec(upstream);
  const ipv6=/^\[([0-9a-f:]+)\]:([1-9]\d{0,4})$/i.exec(upstream);
  if(!socket&&!ipv6||Number((socket??ipv6)?.[2])>65535)return true;
  if(socket){const octets=socket[1].split(".").map(Number);if(octets.some(n=>n>255)||octets[0]===0||octets[0]===127||octets[0]>=224)return true;}
  return draft.upstreamProxies.length>4||draft.upstreamProxies.some(parent=>!parent.host||!parseServicePort(String(parent.port))||Boolean(parent.username)!==Boolean(parent.password)||parent.username&&(!/^[\x21-\x7e]{1,128}$/.test(parent.username)||parent.username.includes(":"))||parent.password&&!/^[\x21-\x7e]{1,128}$/.test(parent.password))||Boolean(byId("upstream-editors").querySelector('[data-invalid="true"]'));
}
function applyRoutingDraft():void {
  if(!draft)return;draft.lanDnsPort=Number(byId<HTMLInputElement>("lan-dns-port").value);draft.lanDnsUpstream=byId<HTMLInputElement>("lan-dns-upstream").value;
}
function renderRoutingControls():void {
  if(!draft)return;
  if(routingInputsNeedReset){byId<HTMLInputElement>("lan-dns-port").value=String(draft.lanDnsPort);byId<HTMLInputElement>("lan-dns-upstream").value=draft.lanDnsUpstream;routingInputsNeedReset=false;}
  for(const [id,field] of [["pac-enabled","pacEnabled"],["pac-direct-fallback","pacDirectFallback"],["lan-dns-enabled","lanDnsEnabled"],["upstream-direct-fallback","upstreamDirectFallback"]] as const){const input=byId<HTMLInputElement>(id);input.checked=draft[field];input.disabled=busy;}
  for(const id of ["lan-dns-port","lan-dns-upstream"])byId<HTMLInputElement>(id).disabled=busy;
  byId("pac-url").textContent=draft.pacEnabled?`PAC: http://${settingsPreviewHost()}:${draft.proxyPort}/proxy.pac`:t("pacDisabled");
  const container=byId("upstream-editors");const signature=JSON.stringify([draft.upstreamProxies,busy]);
  if(signature!==upstreamEditorSignature&&(upstreamEditorSignature===""||!container.contains(document.activeElement)&&!container.querySelector('[data-invalid="true"]'))){
    const rawState=new Map(Array.from(container.querySelectorAll<HTMLInputElement>('input[data-editor-key]')).map(input=>[input.dataset.editorKey!,{value:input.value,invalid:input.dataset.invalid==="true"}]));
    container.replaceChildren();
    for(const parent of draft.upstreamProxies){const card=document.createElement("fieldset");card.className="profile-card";const legend=document.createElement("legend");legend.textContent=t("upstreamProxy");card.append(legend);
      let owner=upstreamEditorOwners.get(parent);if(owner===undefined){owner=++nextUpstreamEditorOwner;upstreamEditorOwners.set(parent,owner);}
      for(const [field,key,type] of [["host","upstreamHost","text"],["port","upstreamPort","text"],["username","profileUser","text"],["password","profileKey","password"]] as const){const label=document.createElement("label");label.className="profile-field";label.textContent=t(key);const input=document.createElement("input");input.type=type;input.value=String(parent[field]??"");input.autocomplete="off";input.dataset.editorKey=`${owner}:${field}`;const raw=rawState.get(input.dataset.editorKey);if(raw){input.value=raw.value;input.dataset.invalid=String(raw.invalid);input.setAttribute("aria-invalid",String(raw.invalid));}input.addEventListener("input",()=>{if(field==="port"){const port=parseServicePort(input.value);input.dataset.invalid=String(!port);input.setAttribute("aria-invalid",String(!port));if(port)parent.port=port;}else if(field==="host")parent.host=input.value;else parent[field]=input.value||null;markDirty();});label.append(input);card.append(label);}
      const remove=document.createElement("button");remove.type="button";remove.className="secondary-button";remove.textContent=t("removeUpstream");remove.addEventListener("click",()=>{if(!draft)return;draft.upstreamProxies.splice(draft.upstreamProxies.indexOf(parent),1);upstreamEditorSignature="";markDirty();renderSettings();});card.append(remove);container.append(card);
    }upstreamEditorSignature=signature;
  }
  container.querySelectorAll<HTMLInputElement|HTMLButtonElement>("input,button").forEach(input=>input.disabled=busy);
  byId<HTMLButtonElement>("add-upstream").disabled=busy||draft.upstreamProxies.length>=4;
  byId("routing-settings-error").textContent=hasInvalidRouting()?t("routingInvalid"):"";
}

function currentCacheValidation(): CacheValidation {
  if (!draft) return { ok: true, values: null, errors: [] };
  return validateCacheInputs(readCacheRaw());
}

function cacheErrorText(validation: CacheValidation): string {
  const error = validation.errors[0];
  if (!error) return "";
  if (error.kind === "limitAboveBudget") return t("cacheErrorLimitAboveBudget");
  if (error.kind === "budgetZeroNeedsLimitZero") return t("cacheErrorBudgetZero");
  const { min, max } = CACHE_BOUNDS[error.field];
  const keys = {
    cacheLimitGib: "cacheErrorDisk",
    cacheMaxObjectMib: "cacheErrorMaxObject",
    responseBufferLimitMib: "cacheErrorBufferLimit",
    responseBufferBudgetMib: "cacheErrorBufferBudget",
  } as const;
  return t(keys[error.field], { min, max });
}

function cacheLimitsSummary(values: Record<CacheField, number>): string {
  return t("cacheLimitsSummary", {
    disk: formatCount(values.cacheLimitGib),
    object: formatCount(values.cacheMaxObjectMib),
    limit: formatCount(values.responseBufferLimitMib),
    budget: formatCount(values.responseBufferBudgetMib),
  });
}

function renderCacheControls(): void {
  if (!snapshot || !draft) return;
  for (const field of CACHE_FIELDS) {
    const input = cacheInputs[field];
    const { min, max } = CACHE_BOUNDS[field];
    const parsed = parseCacheInteger(input.value, min, max);
    // Never overwrite text the user is editing or left invalid: that would silently restore an old value.
    if (cacheInputsNeedReset || (parsed !== null && parsed !== draft[field] && document.activeElement !== input)) {
      input.value = String(draft[field]);
    }
    input.disabled = busy;
  }
  cacheInputsNeedReset = false;
  const validation = currentCacheValidation();
  const badFields = cacheFieldsWithErrors(validation);
  const crossField = validation.errors.some((error) => error.kind !== "range");
  const message = cacheErrorText(validation);
  for (const field of CACHE_FIELDS) {
    const bad = badFields.has(field) || (crossField && (field === "responseBufferLimitMib" || field === "responseBufferBudgetMib"));
    cacheInputs[field].setAttribute("aria-invalid", String(bad));
    cacheInputs[field].setCustomValidity(bad ? message : "");
  }
  byId("cache-settings-error").textContent = message;
  document.querySelectorAll<HTMLButtonElement>("button[data-cache-preset]").forEach((button) => {
    const active = validation.ok && Number(button.dataset.cachePreset) === validation.values?.cacheLimitGib;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = busy;
  });
  const saved = snapshot.settings;
  const differs = validation.values ? cacheSettingsDiffer(validation.values, saved) : true;
  byId("cache-saved-limits").textContent = cacheLimitsSummary(saved);
  byId("cache-draft-limits").textContent = !differs ? t("cacheDraftSame") : validation.values ? cacheLimitsSummary(validation.values) : t("cacheDraftInvalid");
  byId("cache-draft-limits").parentElement?.toggleAttribute("data-pending", differs);
  byId("cache-restart-note").toggleAttribute("data-pending", differs);

  const cache = snapshot.cache;
  const state = cacheUsageState(cache);
  const hasMeasurement = cache && cache.measured !== false;
  const measured = hasMeasurement && state !== "current" ? ` (${t("cacheLastMeasured")})` : "";
  byId("cache-used").textContent = hasMeasurement ? `${formatBinaryBytes(cache.usedBytes)}${measured}` : t("cacheUnknown");
  byId("cache-entries").textContent = hasMeasurement ? `${formatCount(cache.entryCount)}${measured}` : t("cacheUnknown");
  const notes: string[] = [];
  if (state === "unavailable") notes.push(t("cacheUsageUnavailable"));
  if (state === "stale") notes.push(t("cacheUsageStale"));
  if (state === "error") notes.push(t("cacheUsageError"));
  if (cache?.pendingMaintenance) notes.push(t("cacheMaintenancePending"));
  if (cache?.maintenanceError) notes.push(t("cacheMaintenanceError"));
  byId("cache-usage-note").textContent = notes.join(" ");
}

function hasInvalidDeviceLimits(): boolean {
  return Array.from(document.querySelectorAll<HTMLInputElement>(".device-limits input"))
    .some((input) => parseDeviceLimitKib(input.value) === null);
}

function renderDevices(): void {
  if (!snapshot || !draft) return;
  const container = byId("device-list");
  // Preserve keyboard focus and uncommitted input while snapshots refresh.
  const inputs = Array.from(container.querySelectorAll<HTMLInputElement>("input"));
  const preserveEditor = container.contains(document.activeElement) || inputs.some((input) => parseDeviceLimitKib(input.value) === null);
  inputs.forEach((input) => { input.disabled = busy; });
  if (preserveEditor) return;
  const signature = JSON.stringify([snapshot.stats.clients, snapshot.settings.deniedClientIps, draft.deviceLimits, busy]);
  if (signature === deviceRenderSignature) return;
  deviceRenderSignature = signature;
  const denied = new Set(snapshot.settings.deniedClientIps);
  const byAddress = new Map(
    snapshot.stats.clients.map((client) => [client.ip, client.lastSeenUnixMs] as const),
  );
  for (const ip of denied) {
    if (!byAddress.has(ip)) byAddress.set(ip, 0);
  }
  for (const limit of draft.deviceLimits ?? []) {
    if (!byAddress.has(limit.ip)) byAddress.set(limit.ip, 0);
  }
  const devices = [...byAddress.entries()].sort((left, right) => {
    if (left[1] !== right[1]) return right[1] - left[1];
    return left[0].localeCompare(right[0], "en", { numeric: true });
  });

  container.replaceChildren();
  if (devices.length === 0) {
    const empty = document.createElement("p");
    empty.className = "device-empty";
    empty.textContent = t("noKnownDevices");
    container.append(empty);
    return;
  }

  for (const [ip, lastSeenUnixMs] of devices) {
    const blocked = denied.has(ip);
    const row = document.createElement("article");
    row.className = "device-row";
    row.dataset.state = blocked ? "denied" : "allowed";

    const identity = document.createElement("div");
    identity.className = "device-identity";
    const address = document.createElement("strong");
    address.textContent = ip;
    const activity = document.createElement("small");
    activity.textContent = `${t("lastActive")}: ${formatLastActive(lastSeenUnixMs)}`;
    identity.append(address, activity);

    const status = document.createElement("span");
    status.className = "device-status";
    status.textContent = blocked ? t("deviceDenied") : t("deviceAllowed");

    const action = document.createElement("button");
    action.type = "button";
    action.className = "secondary-button device-action";
    action.textContent = blocked ? t("allowDevice") : t("denyDevice");
    action.disabled = busy;
    action.hidden = !canLimitDevice(ip) || snapshot.availableAddresses.some((address) => address.ip === ip);
    action.addEventListener("click", () => void setDeviceAllowed(ip, blocked));

    const client = snapshot.stats.clients.find((entry) => entry.ip === ip);
    const transfer = document.createElement("small");
    transfer.textContent = `↑ ${formatBytes(client?.uploadBytes ?? 0)} (${formatBytes(client?.uploadBytesPerSecond ?? 0)}/s) · ↓ ${formatBytes(client?.downloadBytes ?? 0)} (${formatBytes(client?.downloadBytesPerSecond ?? 0)}/s)`;
    identity.append(transfer);
    if (!canLimitDevice(ip)) {
      const note = document.createElement("small");
      note.textContent = t("limitsPrivateOnly");
      identity.append(note);
      row.append(identity, status, action);
      container.append(row);
      continue;
    }
    const limits = document.createElement("div");
    limits.className = "device-limits";
    const help = document.createElement("small");
    help.textContent = t("limitsHelp");
    limits.append(help);
    for (const direction of ["upload", "download"] as const) {
      const label = document.createElement("label");
      label.textContent = `${t(direction)} (KiB/s)`;
      const input = document.createElement("input");
      input.type = "number"; input.min = "0"; input.max = String(MAX_DEVICE_LIMIT_KIB); input.step = "1";
      input.className = "text-field";
      input.setAttribute("aria-label", `${ip}: ${t(direction)} (KiB/s)`);
      const key = `${direction}BytesPerSecond` as const;
      input.value = String((draft.deviceLimits?.find((limit) => limit.ip === ip)?.[key] ?? 0) / 1024);
      input.disabled = busy;
      input.addEventListener("input", () => {
        if (!draft) return;
        const bytesPerSecond = parseDeviceLimitKib(input.value);
        const valid = bytesPerSecond !== null;
        input.setCustomValidity(valid ? "" : t("invalidLimit"));
        markDirty();
        if (!valid) {
          byId("settings-save-state").textContent = t("pendingInvalidChanges");
          saveButton.disabled = true;
          return;
        }
        draft.deviceLimits ??= [];
        let limit = draft.deviceLimits.find((entry) => entry.ip === ip);
        if (!limit) { limit = { ip, uploadBytesPerSecond: 0, downloadBytesPerSecond: 0 }; draft.deviceLimits.push(limit); }
        limit[key] = bytesPerSecond!;
        markDirty();
      });
      label.append(input); limits.append(label);
    }
    row.append(identity, status, action, limits);
    container.append(row);
  }
}

async function setDeviceAllowed(ip: string, allowed: boolean): Promise<void> {
  if (busy) return;
  await runBusy(async () => {
    if (!(await applyDirtyDraft())) return;
    snapshot = await invoke<AppSnapshot>("set_device_allowed", { ip, allowed });
    syncFromSnapshot(snapshot, true);
    showNotice(allowed ? t("deviceAllowedNotice") : t("deviceDeniedNotice"), "success");
  });
}

function renderGuide(): void {
  if (!snapshot || !draft) return;
  renderDeviceSetup();
  const running = snapshot.running;
  const inspecting = inspectionSupported() && snapshot.settings.httpsMode !== "tunnel";
  const httpsReady = !inspecting || snapshot.tlsInspectionReady;
  const lanReady = snapshot.settings.lanEnabled && Boolean(snapshot.settings.listenIp);
  const configuredAddress = lanReady
    ? serviceEndpoint(snapshot.settings.listenIp ?? "", snapshot.settings.proxyPort)
    : null;
  const portError = validateServicePorts(draft);
  const selectedAddress = snapshot.availableAddresses.find((address) => address.ip === guideSelectedIp) ?? null;
  const selectedKind = selectedAddress ? classifyLanAddress(selectedAddress) : null;
  const addressAllowed = selectedKind !== null
    ? isGuideAddressAllowed(selectedKind, guideConnectionMode)
    : false;
  const liveAddress = guideProxyAddress();
  const instructionsReady = Boolean(
    running
    && httpsReady
    && snapshot.settings.lanEnabled
    && liveAddress,
  );
  const prepared = Boolean(
    running
    && httpsReady
    && addressAllowed
    && snapshot.settings.lanEnabled
    && selectedLanIps(snapshot.settings).includes(guideSelectedIp ?? "")
    && snapshot.settings.dnsMode === draft.dnsMode
    && snapshot.settings.httpsMode === draft.httpsMode
    && (snapshot.settings.httpsInspectionScope ?? "selectedHosts") === draft.httpsInspectionScope
    && snapshot.settings.proxyPort === draft.proxyPort
    && snapshot.settings.socks5Enabled === draft.socks5Enabled
    && (snapshot.settings.socks5UdpEnabled ?? false) === draft.socks5UdpEnabled
    && snapshot.settings.socks5Port === draft.socks5Port
    && snapshot.settings.lanAuthEnabled === draft.lanAuthEnabled
    && snapshot.settings.proxyUsername === draft.proxyUsername
    && snapshot.settings.proxyPassword === draft.proxyPassword
    && snapshot.settings.cacheEnabled === guideCacheEnabled
    && (!draft.socks5Enabled || guideSocks5Address())
    && liveAddress,
  );
  const verified = guideIsVerified();

  document.querySelectorAll<HTMLInputElement>('input[name="guide-connection"]').forEach((input) => {
    input.checked = input.value === guideConnectionMode;
  });
  const recommended = recommendedLanAddress(snapshot.availableAddresses, guideConnectionMode);
  const hotspotReady = guideConnectionMode === "hotspot" && Boolean(recommended);
  const hotspotFallback = guideConnectionMode === "hotspot" && guideHotspotFallbackVisible && !recommended;
  setTextIfChanged(
    byId("guide-address-label"),
    guideConnectionMode === "hotspot" ? t("hotspotStep2Label") : t("step2Label"),
  );
  setTextIfChanged(
    byId("guide-address-title"),
    hotspotReady
      ? t("hotspotReadyTitle")
      : hotspotFallback
        ? t("hotspotFallbackTitle")
        : guideConnectionMode === "hotspot"
          ? t("hotspotWaitingTitle")
          : t("step2Title"),
  );
  setTextIfChanged(
    byId("guide-address-copy"),
    hotspotReady && recommended
      ? t("hotspotReadyCopy", { address: recommended.ip })
      : hotspotFallback
        ? t("hotspotFallbackCopy")
        : guideConnectionMode === "hotspot"
          ? t("hotspotWaitingCopy")
          : t("step2Copy"),
  );
  setTextIfChanged(
    byId("guide-address-legend"),
    guideConnectionMode === "hotspot" ? t("hotspotAddressOptionsAria") : t("addressOptionsAria"),
  );
  const hotspotActions = byId("guide-hotspot-actions");
  hotspotActions.hidden = guideConnectionMode !== "hotspot" || hotspotReady;
  setTextIfChanged(
    byId("guide-hotspot-fallback"),
    guideHotspotFallbackVisible ? t("hotspotFallbackHide") : t("hotspotFallbackShow"),
  );
  renderGuideAddressChoices();

  renderServiceStatus();

  const lanState = byId("guide-lan-state");
  setTextIfChanged(lanState, lanReady ? t("lanEnabled") : t("hostOnly"));
  lanState.dataset.state = lanReady ? "ready" : "pending";

  const addressState = byId("guide-address-state");
  setTextIfChanged(addressState, configuredAddress ? t("selected") : t("missing"));
  addressState.dataset.state = configuredAddress ? "ready" : "pending";

  const addressHelp = byId("guide-address-help");
  if (guideSelectedIp && !selectedAddress) {
    setTextIfChanged(addressHelp, t("setupAddressGone"));
    addressHelp.dataset.state = "error";
  } else if (selectedAddress && addressAllowed) {
    if (guideConnectionMode === "hotspot" && selectedKind === "unknown") {
      setTextIfChanged(addressHelp, t("setupHotspotUnknown"));
      addressHelp.dataset.state = "warning";
    } else if (guideConnectionMode === "hotspot") {
      setTextIfChanged(addressHelp, t("setupHotspotDetected"));
      addressHelp.dataset.state = "ready";
    } else {
      setTextIfChanged(addressHelp, `${t("selected")}: ${selectedAddress.ip} · ${selectedAddress.interfaceName}`);
      addressHelp.dataset.state = "ready";
    }
  } else if (hotspotFallback) {
    const fallbackAddresses = guideLanAddresses(snapshot.availableAddresses, "hotspot")
      .filter((address) => classifyLanAddress(address) === "unknown");
    setTextIfChanged(
      addressHelp,
      fallbackAddresses.length > 0 ? t("setupHotspotChooseFallback") : t("setupHotspotFallbackEmpty"),
    );
    addressHelp.dataset.state = "warning";
  } else if (guideConnectionMode === "hotspot" && !recommended) {
    setTextIfChanged(addressHelp, t("setupHotspotWaiting"));
    addressHelp.dataset.state = "warning";
  } else {
    setTextIfChanged(addressHelp, t("setupNoSuitableAddress"));
    addressHelp.dataset.state = "warning";
  }

  syncPortInput(guideProxyPortInput, draft.proxyPort);
  guideSocks5EnabledCheckbox.checked = draft.socks5Enabled;
  guideSocks5UdpEnabledCheckbox.checked = draft.socks5UdpEnabled ?? false;
  guideSocks5UdpEnabledCheckbox.disabled = busy || !draft.socks5Enabled;
  syncPortInput(guideSocks5PortInput, draft.socks5Port);
  guideProxyPortInput.disabled = busy;
  guideSocks5EnabledCheckbox.disabled = busy;
  guideSocks5PortInput.disabled = busy || !draft.socks5Enabled;
  byId("guide-port-80-warning").hidden = draft.proxyPort !== 80;
  byId("guide-service-port-error").textContent = portError ? servicePortErrorMessage(portError) : "";
  document.querySelectorAll<HTMLButtonElement>("button[data-guide-proxy-port-preset]").forEach((button) => {
    const active = Number(button.dataset.guideProxyPortPreset) === draft?.proxyPort;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = busy;
  });
  guidePrepareButton.disabled = busy || !addressAllowed || Boolean(portError);
  byId<HTMLSelectElement>("guide-https-mode").value = draft.httpsMode ?? "inspect";
  byId<HTMLSelectElement>("guide-https-mode").disabled = busy;
  byId("guide-https-mode-help").textContent = t(!inspectionSupported() || draft.httpsMode === "tunnel" ? "httpsTunnelCopy" : "httpsInspectCopy");
  byId<HTMLSelectElement>("guide-https-inspection-scope").value = draft.httpsInspectionScope;
  byId<HTMLSelectElement>("guide-https-inspection-scope").disabled = busy || !inspectionSupported();
  byId("guide-https-scope-help").textContent = t(draft.httpsInspectionScope === "allSupportedHosts" ? "httpsScopeAllHelp" : "httpsScopeSelectedHelp");
  guideCacheCheckbox.checked = guideCacheEnabled;
  guideCacheCheckbox.disabled = busy;
  guideLanAuthCheckbox.checked = draft.lanAuthEnabled;
  syncTextInput(guideProxyUserInput, draft.proxyUsername);
  syncTextInput(guideProxyPasswordInput, draft.proxyPassword);
  guideProxyPasswordInput.type = guidePasswordRevealed ? "text" : "password";
  guideLanAuthCheckbox.disabled = busy;
  guideProxyUserInput.disabled = busy;
  guideProxyPasswordInput.disabled = busy;
  byId<HTMLButtonElement>("guide-edit-reveal-key").disabled = busy;
  byId<HTMLButtonElement>("guide-edit-reveal-key").textContent = guidePasswordRevealed ? t("hide") : t("show");
  byId("guide-open-lan-warning").hidden = draft.lanAuthEnabled;
  guidePrepareButton.textContent = busy
    ? running
      ? t("setupSaving")
      : t("setupPreparing")
    : running
      ? t("applyAndStart")
      : t("prepareAndStart");
  const prepareState = byId("guide-prepare-state");
  setTextIfChanged(prepareState, prepared ? t("setupPrepared") : "");
  prepareState.dataset.state = prepared ? "ready" : "pending";
  byId("guide-prepared-instructions").hidden = !instructionsReady;

  byId("guide-certificate-note").hidden = !inspecting;
  byId("guide-verify-copy").textContent = t(inspecting ? "step4Copy" : "step4TunnelCopy");
  const hostCertificateState = byId("guide-host-certificate-state");
  hostCertificateState.hidden = !inspecting;
  setTextIfChanged(
    hostCertificateState,
    snapshot.tlsInspectionReady ? t("hostCertificateReady") : t("hostCertificateMissing"),
  );
  hostCertificateState.dataset.state = snapshot.tlsInspectionReady ? "ready" : "error";
  document.querySelectorAll<HTMLButtonElement>("button[data-guide-host-copy]").forEach((button) => {
    button.disabled = !prepared;
  });
  byId<HTMLButtonElement>("guide-copy-ca").disabled = !prepared || !inspecting;

  const details = guideProxyDetails();
  const loginRequired = snapshot.settings.lanAuthEnabled;
  byId("guide-proxy-address").textContent = details.address || t("configureFirst");
  byId("guide-device-proxy-port").textContent = details.port;
  byId("guide-host-proxy-port").textContent = String(snapshot.settings.proxyPort);
  byId("host-proxy-local-copy").textContent = t("hostProxyLocalCopy", {
    port: snapshot.settings.proxyPort,
  });
  byId("troubleshooting-proxy-port").textContent = String(snapshot.settings.proxyPort);
  byId("guide-proxy-user").textContent = loginRequired
    ? details.username || "—"
    : t("loginNotRequired");
  byId("guide-proxy-key").textContent = loginRequired
    ? guidePasswordRevealed && details.key
      ? details.key
      : "••••••••••••••••"
    : t("loginNotRequired");
  const revealKey = byId<HTMLButtonElement>("guide-reveal-key");
  revealKey.textContent = guidePasswordRevealed ? t("hide") : t("show");
  revealKey.disabled = !prepared || !loginRequired;
  byId<HTMLButtonElement>("guide-edit-access").disabled = busy;
  document.querySelectorAll<HTMLButtonElement>("button[data-guide-copy]").forEach((button) => {
    const credential = button.dataset.guideCopy === "username" || button.dataset.guideCopy === "key";
    button.disabled = !prepared || (credential && !loginRequired);
  });
  byId<HTMLButtonElement>("guide-copy-all").disabled = !prepared;

  const socksDetails = guideSocks5Details();
  byId("guide-socks5-address").textContent = socksDetails.address || t("turnOnSocks5First");
  byId("guide-socks5-port-value").textContent = socksDetails.port || "—";
  byId("guide-telegram-port").textContent = snapshot.settings.socks5Enabled
    ? String(snapshot.settings.socks5Port)
    : "—";
  byId("smarttube-copy").textContent = t("smarttubeCopy", {
    port: snapshot.settings.socks5Port,
  });
  byId("whatsapp-messenger-copy").textContent = t("whatsappMessengerCopy", {
    port: snapshot.settings.socks5Port,
  });
  byId("telegram-copy").textContent = t("telegramCopy", {
    port: snapshot.settings.socks5Port,
  });
  byId("chat-app-problem-copy").textContent = t("chatAppProblemCopy", {
    port: snapshot.settings.socks5Port,
  });
  byId<HTMLButtonElement>("guide-copy-socks5").disabled = !prepared || !socksDetails.address;
  byId("guide-socks5-activity").textContent = snapshot.settings.socks5Enabled
    ? t("socks5ConnectionsSinceStart", { count: formatCount(snapshot.stats.socks5Connections) })
    : t("socks5DisabledHelp");

  guideVerifyButton.disabled = busy || !prepared;
  renderGuideVerification(prepared, verified);

  guideFinishButton.disabled = !verified;
  byId("guide-finish-help").textContent = verified ? t("guideAvailable") : t("finishBlocked");

  if (!addressAllowed) {
    setGuideStepState("guide-step-connection", "complete");
    setGuideStepState("guide-step-address", "current");
    setGuideStepState("guide-step-prepare", "pending");
    setGuideStepState("guide-step-verify", "pending");
  } else if (!prepared) {
    setGuideStepState("guide-step-connection", "complete");
    setGuideStepState("guide-step-address", "complete");
    setGuideStepState("guide-step-prepare", "current");
    setGuideStepState("guide-step-verify", "pending");
  } else if (!verified) {
    setGuideStepState("guide-step-connection", "complete");
    setGuideStepState("guide-step-address", "complete");
    if (guideBaselineSuccessfulRequests === null) {
      setGuideStepState("guide-step-prepare", "current");
      setGuideStepState("guide-step-verify", "pending");
    } else {
      setGuideStepState("guide-step-prepare", "complete");
      setGuideStepState("guide-step-verify", "current");
    }
  } else {
    for (const id of [
      "guide-step-connection",
      "guide-step-address",
      "guide-step-prepare",
      "guide-step-verify",
    ]) {
      setGuideStepState(id, "complete");
    }
  }
}

function currentDeviceSetupState(): PhoneSetupState | null {
  if (!snapshot) return null;
  const authority = snapshot.httpsAuthority ?? tlsStatus;
  // Saved settings only: an unsaved draft address does not accept connections yet.
  return phoneSetupState({
    running: snapshot.running,
    lanEnabled: snapshot.settings.lanEnabled,
    listenIps: selectedLanIps(snapshot.settings),
    available: snapshot.availableAddresses.map((address) => ({
      ip: address.ip,
      unsafe: isUnsafeGuideAddress(classifyLanAddress(address)),
    })),
    proxyEndpoints: snapshot.proxyAddresses,
    proxyPort: snapshot.settings.proxyPort,
    caPrepared: Boolean(authority?.prepared),
    fingerprint: authority?.sha256Fingerprint,
    locale,
    preferredIp: deviceSetupPreferredIp,
    guidedIp: guideSelectedIp,
  });
}

function deviceSetupBlockerText(blocker: PhoneSetupBlocker): string {
  if (blocker === "ca") return t((snapshot?.httpsAuthority?.capability ?? inspectionSupported()) ? "deviceSetupBlockedCa" : "deviceSetupCaUnsupported");
  return t(({ stopped: "deviceSetupBlockedStopped", lan: "deviceSetupBlockedLan", address: "deviceSetupBlockedAddress" } as const)[blocker]);
}

function renderDeviceSetup(): void {
  const state = currentDeviceSetupState();
  deviceSetupState = state?.kind === "ready" ? state : null;
  const blockers = state?.kind === "blocked" ? state.blockers : [];
  const caSupported = snapshot?.httpsAuthority?.capability ?? inspectionSupported();
  const prepareButton = byId<HTMLButtonElement>("device-setup-prepare-ca");
  const startButton = byId<HTMLButtonElement>("device-setup-start");
  prepareButton.disabled = busy || !caSupported;
  startButton.disabled = busy || Boolean(snapshot?.running);

  // Polling must not rebuild unchanged content: it would re-announce the live region,
  // reset a text selection or the open address menu.
  const signature = state ? `${phoneSetupSignature(state)}|${caSupported}` : "";
  if (signature === deviceSetupRenderSignature) return;
  deviceSetupRenderSignature = signature;

  const blockerList = byId<HTMLUListElement>("device-setup-blockers");
  blockerList.replaceChildren(...blockers.map((blocker) => {
    const item = document.createElement("li");
    item.textContent = deviceSetupBlockerText(blocker);
    return item;
  }));
  blockerList.hidden = !blockers.length;
  prepareButton.hidden = !blockers.includes("ca") || !caSupported;
  startButton.hidden = !blockers.includes("stopped");
  byId("device-setup-open-settings").hidden = !blockers.includes("lan") && !blockers.includes("address");
  byId("device-setup-actions").hidden = prepareButton.hidden && startButton.hidden && byId("device-setup-open-settings").hidden;

  const ready = state?.kind === "ready" ? state : null;
  const readyState = byId("device-setup-ready-state");
  readyState.hidden = !ready;
  readyState.textContent = ready ? t("deviceSetupReady", { address: ready.ip }) : "";
  byId("phone-setup-ready").hidden = !ready;
  byId("device-setup-address").textContent = ready?.ip ?? "";
  byId("phone-setup-url").textContent = ready?.url ?? "";
  byId("device-setup-fingerprint").textContent = ready?.fingerprint ?? "";

  const select = byId<HTMLSelectElement>("device-setup-address-select");
  const addresses = ready?.addresses ?? [];
  // A changed fingerprint or selection must not rebuild the user's address menu.
  if (JSON.stringify([...select.options].map((option) => option.value)) !== JSON.stringify(addresses)) {
    select.replaceChildren(...addresses.map((ip) => {
      const option = document.createElement("option");
      option.value = ip;
      option.textContent = ip;
      return option;
    }));
  }
  if (ready && select.value !== ready.ip) select.value = ready.ip;
  byId("device-setup-address-choice").hidden = addresses.length < 2;

  const svg = byId<SVGSVGElement>("phone-setup-qr");
  const path = byId<SVGPathElement>("device-setup-qr-path");
  const figure = svg.closest<HTMLElement>("figure");
  if (ready) {
    const qr = qrcode(0, "M");
    qr.addData(ready.url, "Byte");
    qr.make();
    const size = qr.getModuleCount() + 2 * DEVICE_SETUP_QUIET_ZONE;
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    svg.setAttribute("aria-label", t("deviceSetupQrAria", { url: ready.url }));
    path.setAttribute("d", qrModulePath(qr.getModuleCount(), (row, col) => qr.isDark(row, col), DEVICE_SETUP_QUIET_ZONE));
  } else {
    // Drop the previous code at once so a stale URL can never be scanned.
    svg.removeAttribute("aria-label");
    path.setAttribute("d", "");
  }
  if (figure) figure.dataset.state = ready ? "ready" : "blocked";
  // SVG has no reflected HTMLElement.hidden property; update its actual attribute.
  svg.toggleAttribute("hidden", !ready);
  byId("device-setup-qr-placeholder").hidden = Boolean(ready);
}

function focusDeviceSetup(): void {
  showPage("guide");
  const heading = byId("device-setup-title");
  heading.scrollIntoView({ block: "start" });
  heading.focus({ preventScroll: true });
}

function renderGuideAddressChoices(): void {
  if (!snapshot) return;
  const renderSignature = JSON.stringify({
    mode: guideConnectionMode,
    selectedIp: guideSelectedIp,
    hotspotFallbackVisible: guideHotspotFallbackVisible,
    addresses: snapshot.availableAddresses,
  });
  if (renderSignature === guideAddressRenderSignature) return;
  guideAddressRenderSignature = renderSignature;

  const container = byId<HTMLDivElement>("guide-address-options");
  container.replaceChildren();
  const recommended = recommendedLanAddress(snapshot.availableAddresses, guideConnectionMode);
  const visibleAddresses = guideConnectionMode === "hotspot"
    ? recommended
      ? [recommended]
      : guideHotspotFallbackVisible
        ? guideLanAddresses(snapshot.availableAddresses, "hotspot")
          .filter((address) => classifyLanAddress(address) === "unknown")
        : []
    : guideLanAddresses(snapshot.availableAddresses, "sameWifi");
  byId<HTMLFieldSetElement>("guide-address-fieldset").hidden = visibleAddresses.length === 0;

  for (const [index, address] of visibleAddresses.entries()) {
    const kind = classifyLanAddress(address);
    const allowed = isGuideAddressAllowed(kind, guideConnectionMode);
    const automaticallyDetected = guideConnectionMode === "hotspot" && kind === "hotspot";
    const label = document.createElement(automaticallyDetected ? "div" : "label");
    label.className = "address-choice";
    label.dataset.kind = kind;
    label.classList.toggle("is-detected", automaticallyDetected);
    label.classList.toggle("is-disabled", !allowed);

    let input: HTMLInputElement | null = null;
    if (!automaticallyDetected) {
      input = document.createElement("input");
      input.type = "radio";
      input.name = "guide-address";
      input.value = address.ip;
      input.id = `guide-address-${index}`;
      input.checked = address.ip === guideSelectedIp;
      input.disabled = !allowed;
      input.addEventListener("change", () => {
        if (!input?.checked) return;
        guideSelectedIp = address.ip;
        renderGuide();
        focusGuideStep("guide-step-prepare");
      });
    }

    const content = document.createElement("span");
    const addressText = document.createElement("strong");
    addressText.textContent = address.ip;
    const interfaceText = document.createElement("small");
    interfaceText.textContent = address.interfaceName;
    const badge = document.createElement("em");
    badge.textContent = automaticallyDetected
      ? t("hotspotDetectedAutomatically")
      : recommended?.ip === address.ip
        ? t("setupRecommended")
      : addressKindLabel(kind);
    content.append(addressText, interfaceText, badge);
    if (input) label.append(input, content);
    else label.append(content);
    container.append(label);
  }
}

function renderGuideVerification(prepared: boolean, verified: boolean): void {
  if (!snapshot) return;
  const card = byId("guide-verification");
  const title = byId("guide-verification-title");
  const copy = byId("guide-verification-copy");
  const trafficSeen = guideBaselineTotalRequests !== null
    && snapshot.stats.totalRequests > guideBaselineTotalRequests;
  const authenticatedTrafficSeen = guideBaselineAuthenticatedRequests !== null
    && snapshot.stats.authenticatedExternalRequests > guideBaselineAuthenticatedRequests;
  const elapsed = guideVerificationStartedAt === null ? 0 : Date.now() - guideVerificationStartedAt;

  if (verified) {
    card.dataset.state = "ready";
    setTextIfChanged(title, t("setupVerified"));
    setTextIfChanged(copy, t("setupVerifiedCopy"));
    return;
  }
  if (!prepared) {
    card.dataset.state = "pending";
    setTextIfChanged(title, t("setupPrepareFirst"));
    setTextIfChanged(copy, t("setupPrepareFirstCopy"));
    return;
  }
  if (guideBaselineSuccessfulRequests === null) {
    card.dataset.state = "pending";
    setTextIfChanged(title, t("setupReadyToVerify"));
    setTextIfChanged(copy, t("setupReadyToVerifyCopy"));
    return;
  }
  if (authenticatedTrafficSeen && elapsed >= 4_000) {
    card.dataset.state = "warning";
    setTextIfChanged(title, t("setupProxyProblem"));
    setTextIfChanged(copy, t("setupProxyProblemCopy"));
    return;
  }
  if (trafficSeen && elapsed >= 4_000) {
    card.dataset.state = "warning";
    setTextIfChanged(title, t("setupAuthProblem"));
    setTextIfChanged(copy, t("setupAuthProblemCopy"));
    return;
  }
  if (elapsed >= 20_000) {
    card.dataset.state = "warning";
    setTextIfChanged(title, t("setupNoTraffic"));
    setTextIfChanged(copy, t("setupNoTrafficCopy", {
      port: snapshot.settings.proxyPort,
    }));
    return;
  }
  card.dataset.state = "waiting";
  setTextIfChanged(title, t("setupWaiting"));
  setTextIfChanged(copy, t("setupWaitingCopy"));
}

async function beginGuideVerification(): Promise<void> {
  if (!snapshot || busy) return;
  let started = false;
  await runBusy(async () => {
    guideBaselineAuthenticatedRequests = null;
    guideBaselineSuccessfulRequests = null;
    guideBaselineTotalRequests = null;
    guideVerificationStartedAt = null;
    renderGuide();
    const latest = await invoke<AppSnapshot>("get_snapshot");
    guideBaselineAuthenticatedRequests = latest.stats.authenticatedExternalRequests;
    guideBaselineSuccessfulRequests = latest.stats.successfulExternalRequests;
    guideBaselineTotalRequests = latest.stats.totalRequests;
    guideVerificationStartedAt = Date.now();
    started = true;
    syncFromSnapshot(latest);
  });
  if (started) focusGuideStep("guide-step-verify");
}

async function prepareGuidedSetup(): Promise<void> {
  if (!snapshot || !draft || busy || !guideSelectedIp) return;
  const cacheValidation = currentCacheValidation();
  if (!cacheValidation.ok) { showNotice(cacheErrorText(cacheValidation), "error"); return; }
  if (validateServicePorts(draft) || hasInvalidDeviceLimits()) return;
  Object.assign(draft, cacheValidation.values);
  const wasRunning = snapshot.running;
  const intendedSettings = structuredClone(draft);
  const revisionAtPrepare = draftRevision;
  const availableIps = new Set(snapshot.availableAddresses.map((address) => address.ip));
  intendedSettings.listenIps = [...new Set([...selectedLanIps(intendedSettings).filter((ip) => availableIps.has(ip)), guideSelectedIp].filter((ip): ip is string => Boolean(ip)))];
  const selectedAddress = snapshot.availableAddresses.find((address) => address.ip === guideSelectedIp);
  if (!selectedAddress || !isGuideAddressAllowed(classifyLanAddress(selectedAddress), guideConnectionMode)) return;
  intendedSettings.listenIp = selectedAddress.ip;

  await runBusy(async () => {
    if (!snapshot) return;
    guideBaselineAuthenticatedRequests = null;
    guideBaselineSuccessfulRequests = null;
    guideBaselineTotalRequests = null;
    guideVerificationStartedAt = null;
    snapshot = await invoke<AppSnapshot>("configure_lan_and_start", {
      settings: intendedSettings,
      listenIp: selectedAddress.ip,
      cacheEnabled: guideCacheEnabled,
      expectedRevision: revisionAtPrepare,
    });
    syncFromSnapshot(snapshot, true);
    showNotice(wasRunning ? t("settingsSaved") : t("setupPrepared"), "success");
  });

  if (!wasRunning && snapshot?.running) focusGuideInstructions();
}

function guideProxyDetails(): { address: string; port: string; username: string; key: string } {
  const loginRequired = snapshot?.settings.lanAuthEnabled ?? true;
  return {
    address: guideProxyAddress()?.split(":")[0] ?? "",
    port: String(snapshot?.settings.proxyPort ?? DEFAULT_PROXY_PORT),
    username: loginRequired ? snapshot?.settings.proxyUsername ?? "" : "",
    key: loginRequired ? snapshot?.settings.proxyPassword ?? "" : "",
  };
}

function guideSocks5Details(): { address: string; port: string } {
  return {
    address: guideSocks5Address()?.split(":")[0] ?? "",
    port: snapshot?.settings.socks5Enabled ? String(snapshot.settings.socks5Port) : "",
  };
}

function guideIsVerified(): boolean {
  if (
    !snapshot?.running
    || !draft
    || (snapshot.settings.httpsInspectionScope ?? "selectedHosts") !== draft.httpsInspectionScope
    || !snapshot.settings.lanEnabled
    || !selectedLanIps(snapshot.settings).includes(guideSelectedIp ?? "")
    || !guideProxyAddress()
  ) {
    return false;
  }
  return connectionVerified(
    snapshot.stats.successfulExternalRequests,
    guideBaselineSuccessfulRequests,
  );
}

function addressKindLabel(kind: LanAddressKind): string {
  return {
    home: t("adapterHome"),
    hotspot: t("adapterHotspot"),
    vpn: t("adapterVpn"),
    internal: t("adapterInternal"),
    unknown: t("adapterOther"),
  }[kind];
}

function isUnsafeGuideAddress(kind: LanAddressKind | null): boolean {
  return kind === "vpn" || kind === "internal";
}

function isGuideAddressAllowed(kind: LanAddressKind, mode: ConnectionMode): boolean {
  if (isUnsafeGuideAddress(kind)) return false;
  return mode === "hotspot" ? kind === "hotspot" || kind === "unknown" : kind !== "hotspot";
}

function setGuideStepState(id: string, state: "complete" | "current" | "pending"): void {
  const step = byId<HTMLElement>(id);
  step.dataset.state = state;
  if (state === "current") step.setAttribute("aria-current", "step");
  else step.removeAttribute("aria-current");
}

function setTextIfChanged(element: HTMLElement, value: string): void {
  if (element.textContent !== value) element.textContent = value;
}

function focusGuideStep(id: string): void {
  const step = byId<HTMLElement>(id);
  const heading = step.querySelector<HTMLElement>("h2");
  if (!heading) return;
  heading.tabIndex = -1;
  heading.focus({ preventScroll: true });
  step.scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "start",
  });
}

function focusGuideInstructions(): void {
  const instructions = byId<HTMLElement>("guide-prepared-instructions");
  const heading = byId<HTMLElement>("host-proxy-note-title");
  heading.tabIndex = -1;
  heading.focus({ preventScroll: true });
  instructions.scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "start",
  });
}

function focusGuideAccessEditor(): void {
  const controls = byId<HTMLElement>("guide-access-controls");
  guideLanAuthCheckbox.focus({ preventScroll: true });
  controls.scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "center",
  });
}

function guideProxyAddress(): string | null {
  return snapshot?.running && snapshot.settings.lanEnabled ? selectedGuideEndpoint(snapshot.proxyAddresses, guideSelectedIp) : null;
}

function guideSocks5Address(): string | null {
  return snapshot?.running && snapshot.settings.lanEnabled && snapshot.settings.socks5Enabled ? selectedGuideEndpoint(snapshot.socks5Addresses, guideSelectedIp) : null;
}

function inspectionSupported(): boolean {
  return snapshot?.supportsHttpsInspection ?? !isLinux;
}

function preferredProxyAddress(): string | null {
  if (!snapshot?.running || !snapshot.settings.lanEnabled) return null;
  return snapshot.proxyAddresses.find((address) => !address.startsWith("127.")) ?? null;
}

function settingsPreviewHost(): string {
  if (draft?.lanEnabled && draft.listenIp) return draft.listenIp;
  return "127.0.0.1";
}

function updateDraftPort(field: "proxyPort" | "socks5Port", input: HTMLInputElement): void {
  if (!draft) return;
  const parsed = parseServicePort(input.value);
  draft[field] = parsed ?? (Number(input.value) || 0);
  markDirty();
  renderSettings();
  renderGuide();
}

function syncPortInput(input: HTMLInputElement, value: number): void {
  if (document.activeElement === input && parseServicePort(input.value) === null) return;
  input.value = String(value);
}

function syncTextInput(input: HTMLInputElement, value: string): void {
  if (input.value !== value) input.value = value;
}

function servicePortErrorMessage(error: ServicePortError): string {
  return {
    proxyInvalid: t("proxyPortInvalid"),
    socks5Invalid: t("socks5PortInvalid"),
    portsEqual: t("servicePortsEqual"),
  }[error];
}

function listenerBindFailureMessage(failure: ListenerBindFailure): string {
  const service = failure.service === "http" ? t("httpProxyService") : failure.service === "socks5" ? t("socks5ServiceShort") : "DNS";
  const key = {
    inUse: "listenerPortInUse",
    accessDenied: "listenerAccessDenied",
    addressUnavailable: "listenerAddressUnavailable",
    other: "listenerStartFailed",
  }[failure.reason] as "listenerPortInUse" | "listenerAccessDenied" | "listenerAddressUnavailable" | "listenerStartFailed";
  return t(key, { service, endpoint: failure.endpoint });
}

function clearSuccessNotice(): void {
  const notice = byId("notice");
  if (notice.dataset.kind !== "success" || notice.dataset.source !== "action") return;
  notice.hidden = true;
  if (noticeTimer !== undefined) window.clearTimeout(noticeTimer);
}

function markDirty(): void {
  clearSuccessNotice();
  dirty = true;
  renderDiagnostics();
  byId("settings-savebar").hidden = !byId("settings-page").classList.contains("is-active");
  byId("settings-save-state").textContent = t("pendingChanges");
  byId("endpoint-state").textContent = t("endpointDraft");
  byId<HTMLButtonElement>("copy-http-endpoint").disabled = true;
  byId<HTMLButtonElement>("copy-socks5-endpoint").disabled = true;
  saveButton.disabled = busy || !currentCacheValidation().ok || Boolean(currentOfflineValidation().error) || hasInvalidPolicy() || hasInvalidRouting() || Boolean(hasInvalidDeviceLimits());
}

async function runBusy(action: () => Promise<void>): Promise<void> {
  if (busy) return;
  busy = true;
  // A refresh already in flight was requested before this mutation; its response
  // must not overwrite the state the mutation is about to produce.
  activitySnapshotGeneration += 1;
  try {
    render();
    await action();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    showNotice(translateBackendMessage(message, locale), "error");
    // The mutation has settled. Regular polling reconciles backend state without
    // holding the UI lock on a second, potentially unavailable IPC call.
  } finally {
    busy = false;
    try {
      render();
    } catch (error) {
      showNotice(error instanceof Error ? error.message : String(error), "error");
    }
  }
}

async function copyText(value: string, success: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    showNotice(success, "success");
  } catch {
    showNotice(t("copyFailed"), "error");
  }
}

function showNotice(
  message: string,
  kind: "success" | "warning" | "error",
  autoHide = true,
): void {
  const notice = byId<HTMLDivElement>("notice");
  notice.textContent = message;
  notice.dataset.source = "action";
  notice.dataset.kind = kind;
  notice.hidden = false;
  if (noticeTimer !== undefined) window.clearTimeout(noticeTimer);
  if (autoHide) {
    // Service guidance (conflict, permissions) is long; give Linux errors time to be read.
    const visibleMs = isLinux && kind === "error" ? 20_000 : 4_500;
    noticeTimer = window.setTimeout(() => {
      notice.hidden = true;
    }, visibleMs);
  }
}

function hasSeenGuide(): boolean {
  try {
    return window.localStorage.getItem(guideSeenKey) === "1";
  } catch {
    return false;
  }
}

function markGuideSeen(): void {
  try {
    window.localStorage.setItem(guideSeenKey, "1");
  } catch {
    // Průvodce zůstane dostupný; blokované úložiště nesmí bránit ovládání aplikace.
  }
}

function formatBytesParts(bytes: number): [string, string] {
  if (bytes < 1024) return [String(bytes), "B"];
  if (bytes < 1024 ** 2) return [(bytes / 1024).toLocaleString(numberLocale, { maximumFractionDigits: 1 }), "KB"];
  if (bytes < 1024 ** 3) return [(bytes / 1024 ** 2).toLocaleString(numberLocale, { maximumFractionDigits: 1 }), "MB"];
  return [(bytes / 1024 ** 3).toLocaleString(numberLocale, { maximumFractionDigits: 2 }), "GB"];
}

function formatBytes(bytes: number): string {
  const [value, unit] = formatBytesParts(bytes);
  return `${value} ${unit}`;
}

/** Exact binary units for the cache read-out (1 GiB = 1024 MiB), not decimal marketing GB. */
function formatBinaryBytes(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${index === 0 ? String(value) : value.toLocaleString(numberLocale, { maximumFractionDigits: 2 })} ${units[index]}`;
}

function formatCount(value: number): string {
  return value.toLocaleString(numberLocale);
}

function formatActivityTime(timestamp: number): string {
  return new Intl.DateTimeFormat(numberLocale, { dateStyle: "short", timeStyle: "medium" }).format(new Date(timestamp));
}

function formatLastActive(lastSeenUnixMs: number): string {
  if (lastSeenUnixMs <= 0) return t("notSeenSinceRestart");
  return new Intl.DateTimeFormat(numberLocale, {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(lastSeenUnixMs));
}

function adblockLabel(value: AdblockMode): string {
  return { off: t("off"), mild: t("mild"), strict: t("strict") }[value];
}

function compressionLabel(value: CompressionPreset): string {
  return { off: t("off"), sharper: t("sharper"), balanced: t("balanced"), maximum: t("maximum") }[value];
}

async function refresh(): Promise<void> {
  if (busy || refreshing) return;
  refreshing = true;
  const activityGeneration = activitySnapshotGeneration;
  try {
    const next = await loadSnapshotWhenReady(() => invoke<AppSnapshot>("get_snapshot"));
    if (activityGeneration !== activitySnapshotGeneration) return;
    syncFromSnapshot(next);
    void refreshTlsStatus();
  } catch (error) {
    if (activityGeneration !== activitySnapshotGeneration) return;
    snapshotUnavailable = true;
    renderTransferReset();
    if (!snapshot && !startupErrorShown) {
      startupErrorShown = true;
      showPage("home");
      byId("diagnostics-card").scrollIntoView({block: "start"});
    }
    renderDiagnostics();
    const message = error instanceof Error ? error.message : String(error);
    showNotice(translateBackendMessage(message, locale), "error", false);
    // Tie the notice to the backend so it disappears once the service answers again.
    byId("notice").dataset.source = "backend";
  } finally {
    refreshing = false;
  }
}

function renderServiceStatus(): void {
  // A cached snapshot cannot establish whether an unreachable daemon is running.
  const running = snapshot?.running ?? false;
  serviceToggle.classList.toggle("is-on", !snapshotUnavailable && running);
  serviceToggle.setAttribute("aria-pressed", snapshotUnavailable ? "mixed" : String(running));
  serviceToggle.disabled = busy || snapshotUnavailable;
  byId("service-label").textContent = snapshotUnavailable ? t("diagnosticsUnavailable")
    : busy ? t("working") : running ? t("serviceOn") : t("serviceOff");
  const guideState = byId("guide-service-state");
  setTextIfChanged(guideState, snapshotUnavailable ? t("diagnosticsUnavailable") : running ? t("enabled") : t("off"));
  guideState.dataset.state = !snapshotUnavailable && running ? "ready" : "pending";
}

function renderDiagnostics(): void {
  renderServiceStatus();
  const state = byId("diagnostics-health-state");
  state.textContent = t(diagnosticsLoading ? "diagnosticsLoading" : diagnosticStateKey(diagnosticsStatus?.state ?? "unavailable"));
  state.dataset.state = diagnosticsStatus?.state ?? "unavailable";
  const details = byId("diagnostics-details");
  details.hidden = !diagnosticsStatus;
  if (diagnosticsStatus) {
    byId("diagnostics-recovery-count").textContent = t("diagnosticsRecoveryCount", {count: formatCount(diagnosticsStatus.recoveryCount)});
    byId("diagnostics-last-incident").textContent = diagnosticsStatus.lastIncidentAt === null
      ? t("diagnosticsNoIncident") : t("diagnosticsLastIncident", {time: formatLastActive(diagnosticsStatus.lastIncidentAt)});
    byId("diagnostics-storage").textContent = t(diagnosticsStatus.storageAvailable ? "diagnosticsStorageAvailable" : "diagnosticsStorageUnavailable");
  }
  const toggle = byId<HTMLInputElement>("automatic-recovery");
  toggle.checked = draft?.automaticRecovery ?? diagnosticsStatus?.enabled ?? true;
  toggle.disabled = busy || snapshotUnavailable || !draft;
  byId("diagnostics-recovery-pending").textContent = t(snapshotUnavailable || !draft ? "diagnosticsRecoveryUnavailable" : dirty ? "diagnosticsRecoveryPending" : "diagnosticsRecoverySaved");
  const save = byId<HTMLButtonElement>("diagnostics-save-settings");
  save.hidden = !dirty;
  save.disabled = busy || snapshotUnavailable || !draft;
  save.textContent = t(busy ? "working" : "saveChanges");
  const exportButton = byId<HTMLButtonElement>("export-diagnostics");
  // Export has its own lifetime: even a stalled snapshot/mutation must leave it usable.
  exportButton.disabled = diagnosticsExporting;
  exportButton.textContent = t(diagnosticsExporting ? "diagnosticsExporting" : "diagnosticsExport");
  const result = byId("diagnostics-export-result");
  result.hidden = !diagnosticsExporting && !diagnosticsExported && !diagnosticsExportError;
  result.textContent = diagnosticsExporting ? t("diagnosticsExporting") : diagnosticsExportError ? t(diagnosticsExportError)
    : diagnosticsExported ? t(diagnosticsExported.partial ? "diagnosticsPartial" : "diagnosticsSaved") : "";
  result.dataset.kind = diagnosticsExportError ? "error" : diagnosticsExported?.partial ? "warning" : "success";
  byId("diagnostics-saved-file").hidden = !diagnosticsExported;
  byId<HTMLTextAreaElement>("diagnostics-export-path").value = diagnosticsExported?.path ?? "";
}

async function refreshDiagnostics(): Promise<void> {
  if (diagnosticsRefreshing) return;
  diagnosticsRefreshing = true;
  // A slow IPC must stop looking healthy even while regular snapshot polling stalls.
  const timeout = window.setTimeout(() => {
    diagnosticsStatus = null;
    diagnosticsLoading = false;
    renderDiagnostics();
  }, 6_000);
  try {
    diagnosticsStatus = parseDiagnosticsStatus(await invoke<unknown>("get_diagnostics_status"));
  } catch {
    diagnosticsStatus = null;
  } finally {
    window.clearTimeout(timeout);
    diagnosticsLoading = false;
    diagnosticsRefreshing = false;
    renderDiagnostics();
  }
}

byId("export-diagnostics").addEventListener("click", async () => {
  if (diagnosticsExporting) return;
  diagnosticsExporting = true;
  diagnosticsExported = null;
  diagnosticsExportError = null;
  renderDiagnostics();
  try {
    const result = parseDiagnosticExport(await invoke<unknown>("export_diagnostics"));
    if (!result) throw new Error("invalid_export_result");
    diagnosticsExported = result;
  } catch (error) {
    diagnosticsExportError = diagnosticExportErrorKey(error);
  } finally {
    diagnosticsExporting = false;
    renderDiagnostics();
  }
});
byId("diagnostics-export-path").addEventListener("focus", () => byId<HTMLTextAreaElement>("diagnostics-export-path").select());
byId("automatic-recovery").addEventListener("change", () => {
  if (!draft || busy || snapshotUnavailable) return;
  draft.automaticRecovery = byId<HTMLInputElement>("automatic-recovery").checked;
  markDirty();
  renderDiagnostics();
});
byId("diagnostics-save-settings").addEventListener("click", async () => {
  if (!draft || busy || !dirty || snapshotUnavailable) return;
  await runBusy(async () => { await applyDirtyDraft(); });
});

async function refreshTlsStatus():Promise<void> {
  // Until a CA exists, recheck occasionally: Windows Inspect can prepare it outside this panel.
  if(snapshot?.httpsAuthority||tlsStatus?.prepared||!inspectionSupported()||Date.now()-tlsStatusCheckedAt<10_000)return;
  tlsStatusCheckedAt=Date.now();
  const generation = activitySnapshotGeneration;
  try {
    const next=await invoke<TlsStatus>("get_tls_status");
    // A mutation or a newer authoritative snapshot wins over this legacy read.
    if (generation !== activitySnapshotGeneration || snapshot?.httpsAuthority) return;
    if(!tlsStatus?.prepared)tlsStatus=next;
    renderOfflineControls();renderDeviceSetup();
  }
  catch { /* The snapshot still supplies service capability when setup is unavailable. */ }
}

if (!hasSeenGuide()) showPage("guide");
renderDiagnostics();
void refreshDiagnostics();
window.setInterval(() => void refreshDiagnostics(), 3_000);
void refresh();
window.setInterval(() => void refresh(), 1_500);
