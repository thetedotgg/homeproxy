export const APP_STATE_INITIALIZING = "APP_STATE_INITIALIZING";

const LEGACY_UNMANAGED_STATE = "state not managed for field 'state'";
const SNAPSHOT_COMMAND = "get_snapshot";

interface SnapshotRetryOptions {
  retryDelayMs?: number;
  wait?: (delayMs: number) => Promise<void>;
}

export type HostPlatform = "windows" | "linux";

/**
 * The desktop's own OS, known before (and independent of) any service answer, so the
 * "service unavailable" screen can already give Ubuntu-specific advice.
 */
export function detectHostPlatform(userAgent: string): HostPlatform {
  return /windows/i.test(userAgent) ? "windows" : /linux|x11/i.test(userAgent) ? "linux" : "windows";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function isSnapshotStateInitializing(error: unknown): boolean {
  const message = errorMessage(error);
  return message === APP_STATE_INITIALIZING
    || (message.includes(LEGACY_UNMANAGED_STATE) && message.includes(SNAPSHOT_COMMAND));
}

export async function loadSnapshotWhenReady<T>(
  load: () => Promise<T>,
  options: SnapshotRetryOptions = {},
): Promise<T> {
  const retryDelayMs = options.retryDelayMs ?? 50;
  const wait = options.wait ?? ((delayMs: number) => new Promise<void>((resolve) => {
    globalThis.setTimeout(resolve, delayMs);
  }));
  let initializationFailures = 0;

  for (;;) {
    try {
      return await load();
    } catch (error) {
      if (!isSnapshotStateInitializing(error)) throw error;
      initializationFailures += 1;
      if (initializationFailures > 1) await wait(retryDelayMs);
    }
  }
}
