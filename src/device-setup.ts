// Pure helpers for the device (Android, computer, optional iOS) certificate bootstrap QR card.
// The setup URL carries only public facts:
// a private LAN IPv4, the HTTP proxy port, the CA fingerprint and the UI language.

export type SetupLocale = "cs" | "en";

export interface SetupAddressCandidate {
  ip: string;
  /** VPN, container and other internal adapters can never reach the phone. */
  unsafe: boolean;
}

export interface PhoneSetupInput {
  running: boolean;
  lanEnabled: boolean;
  /** Saved listen IPs, in the order they were saved. */
  listenIps: readonly string[];
  available: readonly SetupAddressCandidate[];
  /** Live HTTP listener endpoints (`ip:port`) reported by the snapshot. */
  proxyEndpoints: readonly string[];
  proxyPort: number;
  caPrepared: boolean;
  fingerprint: string | null | undefined;
  locale: SetupLocale;
  /** Address the user picked on the card; falls back to the guide selection. */
  preferredIp: string | null;
  guidedIp: string | null;
}

export type PhoneSetupBlocker = "ca" | "stopped" | "lan" | "address";

export type PhoneSetupState =
  | { kind: "ready"; url: string; ip: string; addresses: string[]; fingerprint: string }
  | { kind: "blocked"; blockers: PhoneSetupBlocker[]; addresses: string[] };

const IPV4_PATTERN = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/**
 * Strict dotted-quad IPv4 inside RFC 1918 private space (the backend's `is_private_lan_ip`);
 * never loopback, link-local, CGNAT or public. Without the subnet mask a last octet of 0 or
 * 255 can be a valid host (for example in a /23), so only the saved listener decides.
 */
export function isEligibleSetupIpv4(ip: string): boolean {
  if (typeof ip !== "string" || !IPV4_PATTERN.test(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** Accepts `AB:CD:…`, spaced or plain hex and returns 64 lowercase hex characters. */
export function normalizeFingerprint(raw: string | null | undefined): string | null {
  if (typeof raw !== "string") return null;
  const compact = raw.replace(/[:\s]/g, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(compact) ? compact : null;
}

/** Full readable fingerprint in the colon form shown by most certificate viewers. */
export function formatFingerprint(hex: string): string {
  return (hex.toUpperCase().match(/.{2}/g) ?? []).join(":");
}

export function buildPhoneSetupUrl(ip: string, port: number, locale: SetupLocale, fingerprint: string): string | null {
  const fp = normalizeFingerprint(fingerprint);
  if (!isEligibleSetupIpv4(ip) || !fp || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  const lang = locale === "cs" ? "cs" : "en";
  return `http://${ip}:${port}/homeproxy/setup?lang=${lang}&fp=${fp}`;
}

/** Saved listen IPs that a phone on the same LAN can reach right now. */
export function phoneSetupAddresses(
  input: Pick<PhoneSetupInput, "running" | "lanEnabled" | "listenIps" | "available" | "proxyEndpoints" | "proxyPort">,
): string[] {
  if (!input.running || !input.lanEnabled) return [];
  const available = new Map(input.available.map((address) => [address.ip, address] as const));
  const bound = new Set(input.proxyEndpoints);
  return [...new Set(input.listenIps)].filter((ip) => {
    const address = available.get(ip);
    return Boolean(address && !address.unsafe && isEligibleSetupIpv4(ip) && bound.has(`${ip}:${input.proxyPort}`));
  });
}

export function choosePhoneSetupIp(addresses: readonly string[], preferredIp: string | null, guidedIp: string | null): string | null {
  for (const ip of [preferredIp, guidedIp]) if (ip && addresses.includes(ip)) return ip;
  return addresses[0] ?? null;
}

/** Recomputed on every snapshot, so a lost precondition drops the URL immediately. */
export function phoneSetupState(input: PhoneSetupInput): PhoneSetupState {
  const addresses = phoneSetupAddresses(input);
  const fingerprint = input.caPrepared ? normalizeFingerprint(input.fingerprint) : null;
  const blockers: PhoneSetupBlocker[] = [];
  if (!fingerprint) blockers.push("ca");
  if (!input.running) blockers.push("stopped");
  if (!input.lanEnabled) blockers.push("lan");
  if (input.running && input.lanEnabled && !addresses.length) blockers.push("address");
  const ip = choosePhoneSetupIp(addresses, input.preferredIp, input.guidedIp);
  const url = fingerprint && ip ? buildPhoneSetupUrl(ip, input.proxyPort, input.locale, fingerprint) : null;
  if (blockers.length || !url || !ip || !fingerprint) {
    return { kind: "blocked", blockers: blockers.length ? blockers : ["address"], addresses };
  }
  return { kind: "ready", url, ip, addresses, fingerprint };
}

/** Stable key of everything the card shows; polling re-renders only when it changes. */
export function phoneSetupSignature(state: PhoneSetupState): string {
  return state.kind === "ready"
    ? JSON.stringify([state.kind, state.url, state.ip, state.addresses])
    : JSON.stringify([state.kind, state.blockers, state.addresses]);
}

/**
 * SVG path for the QR modules offset by the quiet zone, one unit per module.
 * Horizontal runs are merged so the path stays small and renders without seams.
 */
export function qrModulePath(moduleCount: number, isDark: (row: number, col: number) => boolean, quietZone = 4): string {
  const parts: string[] = [];
  for (let row = 0; row < moduleCount; row += 1) {
    let col = 0;
    while (col < moduleCount) {
      if (!isDark(row, col)) { col += 1; continue; }
      const start = col;
      while (col < moduleCount && isDark(row, col)) col += 1;
      parts.push(`M${start + quietZone} ${row + quietZone}h${col - start}v1h${start - col}z`);
    }
  }
  return parts.join("");
}
