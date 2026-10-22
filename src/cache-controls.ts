export const MIB_PER_GIB = 1024;

export type CacheField = "cacheLimitGib" | "cacheMaxObjectMib" | "responseBufferLimitMib" | "responseBufferBudgetMib";

export const CACHE_FIELDS: readonly CacheField[] = ["cacheLimitGib", "cacheMaxObjectMib", "responseBufferLimitMib", "responseBufferBudgetMib"];

export const CACHE_BOUNDS: Record<CacheField, { min: number; max: number }> = {
  cacheLimitGib: { min: 1, max: 1024 },
  cacheMaxObjectMib: { min: 1, max: 1024 },
  responseBufferLimitMib: { min: 0, max: 8 },
  responseBufferBudgetMib: { min: 0, max: 512 },
};

export type CacheSettingsValues = Record<CacheField, number>;
export type CacheRawInput = Record<CacheField, string>;

export type CacheValidationError =
  | { kind: "range"; field: CacheField }
  | { kind: "limitAboveBudget" }
  | { kind: "budgetZeroNeedsLimitZero" };

export interface CacheValidation {
  ok: boolean;
  values: CacheSettingsValues | null;
  errors: CacheValidationError[];
}

export interface CacheSnapshotInfo {
  usedBytes: number;
  entryCount: number;
  pendingMaintenance: boolean;
  usageIsCurrent?: boolean;
  measurementError?: string | null;
  measured?: boolean;
  maintenanceError?: string | null;
}

/** Whole decimal digits only: rejects empty, signs, decimals, exponents and separators. */
export function parseCacheInteger(raw: string, min: number, max: number): number | null {
  const text = raw.trim();
  if (!/^[0-9]{1,6}$/.test(text)) return null;
  const value = Number(text);
  return value >= min && value <= max ? value : null;
}

export function validateCacheInputs(raw: CacheRawInput): CacheValidation {
  const errors: CacheValidationError[] = [];
  const parsed: Partial<CacheSettingsValues> = {};
  for (const field of CACHE_FIELDS) {
    const { min, max } = CACHE_BOUNDS[field];
    const value = parseCacheInteger(raw[field], min, max);
    if (value === null) errors.push({ kind: "range", field });
    else parsed[field] = value;
  }
  const limit = parsed.responseBufferLimitMib;
  const budget = parsed.responseBufferBudgetMib;
  if (limit !== undefined && budget !== undefined) {
    if (budget === 0 && limit > 0) errors.push({ kind: "budgetZeroNeedsLimitZero" });
    else if (limit > budget) errors.push({ kind: "limitAboveBudget" });
  }
  const ok = errors.length === 0;
  return { ok, values: ok ? (parsed as CacheSettingsValues) : null, errors };
}

export function validateCacheValues(values: CacheSettingsValues): CacheValidation {
  return validateCacheInputs({
    cacheLimitGib: String(values.cacheLimitGib),
    cacheMaxObjectMib: String(values.cacheMaxObjectMib),
    responseBufferLimitMib: String(values.responseBufferLimitMib),
    responseBufferBudgetMib: String(values.responseBufferBudgetMib),
  });
}

export function cacheSettingsDiffer(a: CacheSettingsValues, b: CacheSettingsValues): boolean {
  return CACHE_FIELDS.some((field) => a[field] !== b[field]);
}

export function cacheFieldsWithErrors(validation: CacheValidation): Set<CacheField> {
  return new Set(validation.errors.flatMap((error) => (error.kind === "range" ? [error.field] : [])));
}

export type CacheUsageState = "unavailable" | "error" | "stale" | "current";

/**
 * Honest state of the disk-usage read-out. A missing cache object (older service), a
 * measurement error or a stale figure must never be shown as a current zero.
 */
export function cacheUsageState(cache: CacheSnapshotInfo | null | undefined): CacheUsageState {
  if (!cache) return "unavailable";
  if (cache.measurementError) return "error";
  if (cache.measured === false) return "unavailable";
  if (cache.usageIsCurrent === false) return "stale";
  return "current";
}

export interface SavingsSettings {
  cacheEnabled: boolean;
  compressionPreset: string;
  responseBufferLimitMib: number;
  responseBufferBudgetMib: number;
  httpsMode: string;
  httpsInspectionScope?: string;
  httpsClientTrustAcknowledged: boolean;
  httpsInspectHosts: readonly string[];
}

export type SavingsStatusKey = "savingsStopped" | "savingsCacheOn" | "savingsCacheOff"
  | "savingsImagesOn" | "savingsImagesOff" | "savingsImagesBufferOff"
  | "savingsHttpOnly" | "savingsInspectSelected" | "savingsInspectAll";

/**
 * Saved settings that actually route some HTTPS through inspection: inspect mode,
 * acknowledged client trust and a non-empty scope. Anything else is a raw tunnel.
 */
export function httpsInspectionActive(settings: SavingsSettings, supported = true): boolean {
  return supported && settings.httpsMode === "inspect" && settings.httpsClientTrustAcknowledged
    && (settings.httpsInspectionScope === "allSupportedHosts" || settings.httpsInspectHosts.length > 0);
}

/** Use the daemon's saved settings, never a pending UI draft or inferred traffic. */
export function savingsStatus(settings: SavingsSettings, running: boolean): SavingsStatusKey[] {
  if (!running) return ["savingsStopped"];
  return [
    settings.cacheEnabled ? "savingsCacheOn" : "savingsCacheOff",
    settings.compressionPreset === "off" ? "savingsImagesOff"
      : settings.responseBufferLimitMib === 0 || settings.responseBufferBudgetMib === 0
        ? "savingsImagesBufferOff" : "savingsImagesOn",
    httpsInspectionActive(settings)
      ? settings.httpsInspectionScope === "allSupportedHosts" ? "savingsInspectAll" : "savingsInspectSelected"
      : "savingsHttpOnly",
  ];
}

export type CacheProfileLabelKey = "off" | "publicWithSize" | "publicWithSizeHttpOnly";

/**
 * Home cache label from the daemon's saved settings. Without active HTTPS
 * inspection the cache can only serve plain HTTP, so the label says so.
 */
export function cacheProfileLabel(
  settings: SavingsSettings & { cacheLimitGib: number },
  inspectionSupported: boolean,
): { key: CacheProfileLabelKey; size: number } {
  if (!settings.cacheEnabled) return { key: "off", size: settings.cacheLimitGib };
  return {
    key: httpsInspectionActive(settings, inspectionSupported) ? "publicWithSize" : "publicWithSizeHttpOnly",
    size: settings.cacheLimitGib,
  };
}

export interface CacheBypassReasonCount { code: string; count: number }

/** Most frequent bypass reasons, by count then code; ignores malformed counts. */
export function topCacheBypassReasons(
  reasons: Readonly<Record<string, unknown>> | null | undefined,
  limit = 3,
): CacheBypassReasonCount[] {
  if (!reasons || typeof reasons !== "object") return [];
  return Object.entries(reasons)
    .flatMap(([code, count]) => typeof count === "number" && Number.isFinite(count) && count > 0 ? [{ code, count }] : [])
    .sort((left, right) => right.count - left.count || (left.code < right.code ? -1 : left.code > right.code ? 1 : 0))
    .slice(0, Math.max(0, limit));
}
