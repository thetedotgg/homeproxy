export const PROJECT_WEBSITE = "homeproxy.thetasigma.io";
export const PROJECT_SOURCE = "github.com/thetedotgg/homeproxy";

export interface AboutVersions {
  app: string;
  /** Linux only: the separately installed service; null when not reported. */
  service: string | null;
  mismatch: boolean;
}

/** Versions shown under Settings → About, for bug reports and update checks. */
export function aboutVersions(appVersion: string, serviceVersion: string | null | undefined, linux: boolean): AboutVersions {
  const service = linux && typeof serviceVersion === "string" && serviceVersion.trim() ? serviceVersion.trim() : null;
  return { app: appVersion, service, mismatch: service !== null && service !== appVersion };
}
