import type { Locale } from "./i18n";

export interface PreparationStatus {
  activeJob: string | null;
  maxUrls: number;
  maxJobs: number;
  errorCode: string | null;
  pinUsage: { usedBytes: number; limitBytes: number; entryCount: number; degraded: boolean; error: string | null };
  jobs: Array<{ id: string; state: string; budgetBytes: number; receivedBytes: number; items: Array<{
    label: string; state: string; receivedBytes: number; storedBytes: number; cacheKey: string | null;
    pinned: boolean; offlineReady: boolean; errorCode: string | null;
  }> }>;
  pins: Array<{key: string; label: string; bytes: number; offlineReady: boolean}>;
}

export function preparationInput(urlsText: string, budgetText: string, pin: boolean):
  { urls: string[]; budgetMib: number; pin: boolean } | null {
  const urls = urlsText.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!urls.length || urls.length > 32 || new Set(urls).size !== urls.length
    || !/^\d+$/.test(budgetText) || Number(budgetText) < 1 || Number(budgetText) > 1024) return null;
  for (const value of urls) {
    if (value.length > 4096 || !/^https?:\/\//.test(value) || /[^\x21-\x7e]/.test(value) || value.includes("#")) return null;
    try {
      const url = new URL(value);
      if (url.username || url.password || !url.hostname || (url.port && !["80", "443", "8080"].includes(url.port))
        || (url.protocol === "https:" && url.port && url.port !== "443")
        || (url.protocol === "http:" && url.port && !["80", "8080"].includes(url.port))) return null;
    } catch { return null; }
  }
  return {urls, budgetMib: Number(budgetText), pin};
}

export function escapePreparationText(value: string): string {
  return value.replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]!));
}

export interface PreparationJobRenderState {
  signature: string;
  openById: ReadonlyMap<string, boolean>;
}

/** Polling changes job data, while disclosure state and focus belong to the user. */
export function updatePreparationJobs(
  previous: PreparationJobRenderState | undefined,
  jobs: ReadonlyArray<{id: string; content: string}>,
  observed: ReadonlyArray<{id: string; open: boolean}>,
  emptyContent: string,
  focusedJobId: string | null = null,
): {state: PreparationJobRenderState; markup: string | null; restoreFocusJobId: string | null} {
  const observedOpen = new Map(observed.map(job => [job.id, job.open]));
  const openById = new Map(jobs.map((job, index) => [
    job.id, observedOpen.get(job.id) ?? previous?.openById.get(job.id) ?? index === 0,
  ]));
  // Compare generated data, never browser-serialized HTML or mutable `open` attributes.
  const signature = JSON.stringify([jobs, jobs.length ? null : emptyContent]);
  const changed = previous?.signature !== signature;
  const markup = changed ? (jobs.length ? jobs.map(job =>
    `<details class="preparation-job" data-job-id="${escapePreparationText(job.id)}"${openById.get(job.id) ? " open" : ""}>${job.content}</details>`
  ).join("") : emptyContent) : null;
  return {
    state: {signature, openById},
    markup,
    restoreFocusJobId: changed && focusedJobId !== null && openById.has(focusedJobId) ? focusedJobId : null,
  };
}

const reasons: Record<string, readonly [string, string]> = {
  queued: ["Čeká na přípravu", "Queued"], running: ["Stahuje se", "Downloading"], stored: ["Uloženo", "Stored"],
  completed: ["Příprava dokončena", "Preparation completed"], failed: ["Příprava se nezdařila", "Preparation failed"],
  cancelled: ["Příprava zrušena", "Preparation cancelled"], interrupted: ["Přerušeno restartem", "Interrupted by restart"],
  "invalid-input": ["Zadejte 1–32 různé veřejné HTTP(S) adresy a limit 1–1024 MiB.", "Enter 1–32 different public HTTP(S) URLs and a 1–1024 MiB budget."],
  "invalid-url": ["Adresa není platná pro přípravu obsahu.", "This URL is not valid for preparation."],
  "duplicate-url": ["Každou adresu zadejte jen jednou.", "Enter each URL only once."],
  "private-target": ["Vnitřní a místní cíle nejsou povolené.", "Private and local destinations are not allowed."],
  "proxy-stopped": ["Proxy musí být spuštěná.", "The proxy must be running."],
  "offline-mode": ["Příprava vyžaduje uložený režim Online.", "Preparation requires saved Online mode."],
  "cache-disabled": ["Zapněte a uložte veřejnou cache.", "Enable and save public caching."],
  "https-not-inspected": ["Pro tuto HTTPS doménu musí být připravená a povolená kontrola HTTPS bez výjimky.", "This HTTPS domain needs prepared and allowed HTTPS inspection, without a bypass."],
  "pin-quota": ["Zvolený limit přesahuje volné místo pro připnutí; snižte jej nebo uvolněte připnutí.", "The budget exceeds free pin space; reduce it or release pins."],
  "variant-not-prepared": ["Server rozlišuje varianty podle hlaviček. Připravený požadavek nemusí odpovídat prohlížeči.", "The origin selects variants by request headers. The prepared request may differ from your browser."],
  "pin-failed": ["Soubor je uložený, ale nepodařilo se jej připnout.", "The file was stored, but pinning failed."],
  "byte-budget": ["Soubor přesahuje zbývající limit přenosu.", "The file exceeds the remaining transfer budget."],
  "unknown-length": ["Server neoznámil délku souboru; příprava jej nemůže bezpečně rezervovat.", "The server did not declare the file length; preparation cannot safely reserve it."],
  "response-not-cacheable": ["Odpověď serveru nesplňuje pravidla veřejné cache.", "The response does not meet public cache rules."],
  "request-ineligible": ["Pro tuto adresu chybí vhodné pravidlo veřejné cache.", "This URL needs a suitable public cache rule."],
  "redirect-not-prepared": ["Server přesměroval požadavek. Přidejte veřejnou cílovou adresu do seznamu.", "The server redirected the request. Add its public destination URL to the list."],
  "policy-denied": ["Přístup zakazují pravidla nebo limity proxy.", "Proxy rules or limits deny this access."],
  "origin-failed": ["Server není dostupný nebo se nepodařilo ověřit spojení.", "The origin is unavailable or its connection could not be verified."],
  "origin-status": ["Server nevrátil celý soubor.", "The origin did not return a complete file."],
  "body-failed": ["Přenos nebyl úplný; soubor není připravený.", "The transfer was incomplete; the file is not prepared."],
  "storage-failed": ["Zápis do cache se nezdařil nebo chybí místo.", "The cache write failed or there is insufficient space."],
  "manifest-invalid": ["Záznam přípravy je poškozený. Vymazání cache jej obnoví.", "The preparation record is invalid. Clearing the cache resets it."],
  "manifest-write-failed": ["Nepodařilo se uložit stav přípravy; další stahování se zastavilo.", "Preparation state could not be saved; further downloads stopped."],
  "job-active": ["Jiná příprava už běží.", "Another preparation job is running."],
  "job-not-active": ["Tato příprava už neběží.", "This preparation is no longer running."],
  "connection-limit": ["Proxy právě dosáhla limitu spojení.", "The proxy reached its connection limit."],
  timeout: ["Příprava překročila časový limit.", "Preparation exceeded its time limit."],
};
export function preparationReason(code: string, locale: Locale): string {
  return (reasons[code] ?? ["Obsah se nepodařilo připravit.", "The content could not be prepared."])[locale === "cs" ? 0 : 1];
}
