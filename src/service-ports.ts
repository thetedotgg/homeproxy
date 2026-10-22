export const DEFAULT_PROXY_PORT = 17_891;
export const DEFAULT_SOCKS5_PORT = 1_080;

export type ServicePortError = "proxyInvalid" | "socks5Invalid" | "portsEqual";

export interface ServicePortSettings {
  proxyPort: number;
  socks5Enabled: boolean;
  socks5Port: number;
}

export function parseServicePort(value: string): number | null {
  if (!/^\d+$/.test(value.trim())) return null;
  const port = Number(value);
  return Number.isSafeInteger(port) && port >= 1 && port <= 65_535 ? port : null;
}

export function validateServicePorts(settings: ServicePortSettings): ServicePortError | null {
  if (!Number.isInteger(settings.proxyPort) || settings.proxyPort < 1 || settings.proxyPort > 65_535) {
    return "proxyInvalid";
  }
  if (!Number.isInteger(settings.socks5Port) || settings.socks5Port < 1 || settings.socks5Port > 65_535) {
    return "socks5Invalid";
  }
  if (settings.socks5Enabled && settings.proxyPort === settings.socks5Port) return "portsEqual";
  return null;
}

export function serviceEndpoint(host: string, port: number): string {
  return `${host}:${port}`;
}
