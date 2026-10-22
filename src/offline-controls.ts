export interface PublicCacheEndpoint {
  host: string;
  pathPrefix: string;
}

export type HttpsInspectionScope = "selectedHosts" | "allSupportedHosts";

export interface OfflineSettings {
  httpsMode: "tunnel" | "inspect";
  httpsInspectionScope: HttpsInspectionScope;
  httpsInspectHosts: string[];
  httpsBypassHosts: string[];
  httpsClientTrustAcknowledged: boolean;
  cacheMode: "online" | "offline";
  offlineMaxStaleHours: number;
  publicCacheEndpoints: PublicCacheEndpoint[];
}

export interface OfflineRaw {
  inspectHosts: string;
  bypassHosts: string;
  endpoints: string;
  staleHours: string;
}

export type OfflineError = "hosts" | "endpoints" | "staleHours" | "trust";

/** Keep invalid pending rules editable even when switching to the broader scope. */
export function showInspectHostEditor(scope: HttpsInspectionScope, raw: string, editing = false): boolean {
  return editing || scope !== "allSupportedHosts" || parseHostRules(raw) === null;
}

export function parseHostRules(raw: string): string[] | null {
  const values = raw.split(/[\s,]+/).filter(Boolean).map((host) => host.toLowerCase());
  if (values.length > 128 || new Set(values).size !== values.length) return null;
  return values.every((value) => validHost(value.startsWith("*.") ? value.slice(2) : value)) ? values : null;
}

function validHost(host: string): boolean {
  return host.length > 0 && host.length <= 253 && host.split(".").every((label) =>
    label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

/** One exact host and path per line. Queries remain in request keys, never in these rules. */
export function parsePublicEndpoints(raw: string): PublicCacheEndpoint[] | null {
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length > 128) return null;
  const result: PublicCacheEndpoint[] = [];
  for (const line of lines) {
    const slash = line.indexOf("/");
    const host = line.slice(0, slash).toLowerCase();
    const pathPrefix = line.slice(slash);
    if (slash < 1 || !validHost(host) || pathPrefix.length > 2048 || !/^[\x21-\x7e]+$/.test(pathPrefix)
      || /[?#\\]/.test(pathPrefix)) return null;
    result.push({ host, pathPrefix });
  }
  return result;
}

export function validateOfflineInputs(raw: OfflineRaw, mode: "tunnel" | "inspect", acknowledged: boolean, scope: HttpsInspectionScope = "selectedHosts"):
  { error: OfflineError; values?: never } | { error: null; values: Pick<OfflineSettings, "httpsInspectHosts" | "httpsBypassHosts" | "offlineMaxStaleHours" | "publicCacheEndpoints"> } {
  const httpsInspectHosts = parseHostRules(raw.inspectHosts);
  const httpsBypassHosts = parseHostRules(raw.bypassHosts);
  if (!httpsInspectHosts || !httpsBypassHosts) return { error: "hosts" };
  const publicCacheEndpoints = parsePublicEndpoints(raw.endpoints);
  if (!publicCacheEndpoints) return { error: "endpoints" };
  if (!/^\d+$/.test(raw.staleHours) || Number(raw.staleHours) > 8760) return { error: "staleHours" };
  if (mode === "inspect" && (!acknowledged || (scope !== "allSupportedHosts" && httpsInspectHosts.length === 0))) return { error: "trust" };
  return { error: null, values: { httpsInspectHosts, httpsBypassHosts, publicCacheEndpoints, offlineMaxStaleHours: Number(raw.staleHours) } };
}
