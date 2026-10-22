export type ConnectionMode = "sameWifi" | "hotspot";

export interface LanAddress {
  interfaceName: string;
  ip: string;
}

export type LanAddressKind = "home" | "hotspot" | "vpn" | "internal" | "unknown";

const vpnMarkers = [
  "anyconnect",
  "cisco secure",
  "cyberghost",
  "expressvpn",
  "forticlient",
  "globalprotect",
  "ivanti",
  "mullvad",
  "nordlynx",
  "openvpn",
  "pangp",
  "proton",
  "pulse secure",
  "surfshark",
  "tailscale",
  "vpn",
  "windscribe",
  "wireguard",
  "zerotier",
];

const internalMarkers = [
  "docker",
  "hyper-v",
  "loopback",
  "virtualbox",
  "vmware",
  "vethernet",
  "wsl",
];

const hotspotMarkers = [
  "hotspot",
  "local area connection*",
  "mobile hotspot",
  "wi-fi direct",
  "wifi direct",
];

const homeNetworkMarkers = ["ethernet", "wi-fi", "wifi", "wireless", "wlan"];

export type AdapterPlatform = "windows" | "linux";

// Linux uses kernel interface names. Tunnels, bridges and container/VM links are never
// home networks; only predictable (enp0s3, eno1, ens33, wlp2s0) and legacy (eth0, wlan0)
// physical names are. Anything else stays "unknown" instead of being guessed.
const linuxVpnPattern = /^(tun|tap|wg|tailscale|zt|ppp|ipsec|vpn|nordlynx|proton|mullvad)/;
const linuxInternalPattern = /^(lo$|docker|br-|br\d|veth|virbr|vmnet|vboxnet|lxc|lxd|podman|cni|flannel|cali|kube|vnet|dummy)/;
const linuxHomePattern = /^(en[a-z0-9]+|eth\d+|wl[a-z0-9]+)$/;

function classifyLinuxInterface(name: string): LanAddressKind {
  if (linuxVpnPattern.test(name)) return "vpn";
  if (linuxInternalPattern.test(name)) return "internal";
  if (linuxHomePattern.test(name)) return "home";
  return "unknown";
}

export function classifyLanAddress(
  address: LanAddress,
  platform: AdapterPlatform = "windows",
): LanAddressKind {
  const name = address.interfaceName.toLocaleLowerCase("en-US");
  // No Linux hotspot or gateway mode exists, so nothing is ever classified as one there.
  if (platform === "linux") return classifyLinuxInterface(name);
  if (address.ip === "192.168.137.1" || hotspotMarkers.some((marker) => name.includes(marker))) {
    return "hotspot";
  }
  if (vpnMarkers.some((marker) => name.includes(marker))) return "vpn";
  if (internalMarkers.some((marker) => name.includes(marker))) return "internal";
  if (homeNetworkMarkers.some((marker) => name.includes(marker))) return "home";
  return "unknown";
}

export function recommendedLanAddress(
  addresses: readonly LanAddress[],
  mode: ConnectionMode,
  platform: AdapterPlatform = "windows",
): LanAddress | null {
  if (mode === "hotspot") {
    return addresses.find((address) => classifyLanAddress(address, platform) === "hotspot") ?? null;
  }

  return addresses.find((address) => classifyLanAddress(address, platform) === "home") ?? null;
}

export function guideLanAddresses(
  addresses: readonly LanAddress[],
  mode: ConnectionMode,
  platform: AdapterPlatform = "windows",
): LanAddress[] {
  if (mode === "sameWifi") return [...addresses];
  return addresses.filter((address) => {
    const kind = classifyLanAddress(address, platform);
    return kind === "hotspot" || kind === "unknown";
  });
}

export function connectionVerified(
  successfulExternalRequests: number,
  baseline: number | null,
): boolean {
  return baseline !== null && successfulExternalRequests > baseline;
}

/** Keep a live explicit choice; after an adapter disappears suggest a safe replacement. */
export function availableGuideSelection(
  addresses: readonly LanAddress[],
  selectedIp: string | null,
  mode: ConnectionMode,
  platform: AdapterPlatform = "windows",
): string | null {
  if (addresses.some((address) => address.ip === selectedIp)) return selectedIp;
  return recommendedLanAddress(addresses, mode, platform)?.ip ?? null;
}

/** Matches the core's private IPv4 device-limit boundary. */
export function canLimitDevice(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  const [first, second] = parts.map(Number);
  return first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
}

export const MAX_DEVICE_LIMIT_KIB = Math.floor(1_000_000_000 / 1024);

export function parseDeviceLimitKib(value: string): number | null {
  const amount = Number(value);
  return value.trim() !== "" && Number.isInteger(amount) && amount >= 0 && amount <= MAX_DEVICE_LIMIT_KIB
    ? amount * 1024
    : null;
}

export function selectedGuideEndpoint(addresses: string[], selectedIp: string | null): string | null {
  return selectedIp ? addresses.find((address) => address.startsWith(`${selectedIp}:`)) ?? null : null;
}
