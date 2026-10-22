import type { TranslationKey } from "./i18n";

export const diagnosticStates = ["warmingUp", "healthy", "stopped", "checking", "suspected", "recovering", "suspended", "disabled", "unavailable"] as const;
export type DiagnosticState = typeof diagnosticStates[number];
export interface DiagnosticsStatus {
  enabled: boolean;
  state: DiagnosticState;
  recoveryCount: number;
  lastIncidentAt: number | null;
  storageAvailable: boolean;
}
export interface DiagnosticExport {
  path: string;
  fileName: string;
  partial: boolean;
}

const stateKeys: Record<DiagnosticState, TranslationKey> = {
  warmingUp: "diagnosticsWarmingUp", healthy: "diagnosticsHealthy", stopped: "diagnosticsStopped",
  checking: "diagnosticsChecking", suspected: "diagnosticsSuspected", recovering: "diagnosticsRecovering",
  suspended: "diagnosticsSuspended", disabled: "diagnosticsDisabled", unavailable: "diagnosticsUnavailable",
};
export function diagnosticStateKey(state: DiagnosticState): TranslationKey {
  return stateKeys[state] ?? "diagnosticsUnavailable";
}

/** Reject incomplete/future responses rather than displaying a false healthy state. */
export function parseDiagnosticsStatus(value: unknown): DiagnosticsStatus | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.enabled !== "boolean" || typeof v.storageAvailable !== "boolean"
    || !diagnosticStates.includes(v.state as DiagnosticState)
    || !Number.isSafeInteger(v.recoveryCount) || (v.recoveryCount as number) < 0
    || !(v.lastIncidentAt === null || (Number.isSafeInteger(v.lastIncidentAt)
      && (v.lastIncidentAt as number) >= 0 && (v.lastIncidentAt as number) <= 8_640_000_000_000_000))) return null;
  return { enabled: v.enabled, state: v.state as DiagnosticState, recoveryCount: v.recoveryCount as number,
    lastIncidentAt: v.lastIncidentAt as number | null, storageAvailable: v.storageAvailable };
}
export function parseDiagnosticExport(value: unknown): DiagnosticExport | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.path !== "string" || !v.path || typeof v.fileName !== "string"
    || !/^HomeProxy-diagnostika-[0-9-]+\.json$/.test(v.fileName) || typeof v.partial !== "boolean") return null;
  return { path: v.path, fileName: v.fileName, partial: v.partial };
}

/** The GUI shows only fixed, localized failure copy; never a raw IPC/OS message. */
export function diagnosticExportErrorKey(error: unknown): TranslationKey {
  const message = error instanceof Error ? error.message : String(error);
  if (message === "HOMEPROXY_DIAGNOSTICS:downloads_unavailable") return "diagnosticsDownloadsUnavailable";
  if (message === "HOMEPROXY_DIAGNOSTICS:report_too_large") return "diagnosticsTooLarge";
  return "diagnosticsExportFailed";
}
