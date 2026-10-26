import { emptyOutput, errorMessage, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

export interface AdapterRun {
  adapter: string;
  startedAt: Date;
  finishedAt: Date;
  output: AdapterOutput;
}

export class TimeoutError extends Error {
  constructor(ms: number) {
    super(`Zeitlimit von ${Math.round(ms / 1000)} s überschritten`);
    this.name = "TimeoutError";
  }
}

export class CancelledError extends Error {
  constructor() {
    super("Prüfung wurde abgebrochen");
    this.name = "CancelledError";
  }
}

function withTimeout<T>(p: Promise<T>, ms: number, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) return reject(new CancelledError());
    const timer = setTimeout(() => reject(new TimeoutError(ms)), ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new CancelledError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(
      (v) => {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}

/**
 * Führt einen Adapter mit dem vollständigen Lebenszyklus aus:
 * Verfügbarkeit -> Autorisierung -> Ausführung (mit Timeout/Abbruch) -> Normalisierung bzw. Fehlerbericht.
 * Wirft nie; Fehler werden als Ergebnis mit Status "error" zurückgegeben.
 */
export async function runAdapter(adapter: ScannerAdapter, ctx: ScanContext): Promise<AdapterRun> {
  const startedAt = new Date();
  const done = (output: AdapterOutput): AdapterRun => ({ adapter: adapter.key, startedAt, finishedAt: new Date(), output });

  try {
    const availability = await adapter.checkAvailability();
    if (availability.status !== "available" && availability.status !== "degraded") {
      return done(emptyOutput("unavailable", availability.message ?? `Integration nicht verfügbar (${availability.status})`));
    }
  } catch (err) {
    return done(emptyOutput("unavailable", errorMessage(err)));
  }

  const auth = adapter.validateAuthorization(ctx);
  if (!auth.ok) return done(emptyOutput("not_authorized", auth.reason));

  try {
    const raw = await withTimeout(adapter.execute(ctx), adapter.timeoutMs, ctx.signal);
    return done(adapter.normalizeResults(raw, ctx));
  } catch (err) {
    ctx.log.warn(`Adapter ${adapter.key} fehlgeschlagen`, { error: errorMessage(err) });
    if (err instanceof CancelledError) return done(emptyOutput("skipped", err.message));
    return done(adapter.reportErrors(err, ctx));
  }
}

/** Führt Aufgaben mit begrenzter Parallelität aus. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return results;
}
