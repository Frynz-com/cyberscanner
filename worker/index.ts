import "./load-env";
import { hostname } from "node:os";
import { addTimeline, notify } from "../src/lib/core/events";
import { createLogger, createServiceClient, NonRetryableError, type WorkerDeps } from "./deps";
import { runDomainScan, type ScanJob } from "./jobs/domain-scan";
import { runPublicCheck } from "./jobs/public-check";
import { runIntelWatch } from "./jobs/intel-watch";
import { runReverify } from "./jobs/reverify";
import { processEmailOutbox } from "./mailer";
import { applyRetention, recheckVerifications, refreshKev } from "./maintenance";
import { generateMonthlyReports } from "./reports";
import { refreshProviderHealth } from "./providers";
import { enqueueDueIntelWatches, enqueueDueScans } from "./scheduler";

const env = process.env as Record<string, string | undefined>;
const workerId = env.WORKER_ID ?? `${hostname()}-${process.pid}`;
const log = createLogger({ worker: workerId });
const deps: WorkerDeps = { db: createServiceClient(env), env, log, workerId };

const CONCURRENCY = Math.max(1, Math.min(8, Number(env.WORKER_CONCURRENCY ?? 2)));
const KINDS = ["domain_scan", "reverify", "public_check", "intel_watch"];
let shuttingDown = false;

type Handler = (job: ScanJob, deps: WorkerDeps, signal: AbortSignal) => Promise<unknown>;
const HANDLERS: Record<string, Handler> = { domain_scan: runDomainScan, reverify: runReverify, public_check: runPublicCheck, intel_watch: runIntelWatch };

export async function processJob(job: ScanJob, d: WorkerDeps = deps): Promise<void> {
  const controller = new AbortController();
  const jobLog = createLogger({ worker: d.workerId, job: job.id, kind: job.kind });
  // Heartbeat + Abbruchprüfung
  const heartbeat = setInterval(async () => {
    const { data } = await d.db.from("scan_jobs").update({ heartbeat_at: new Date().toISOString() }).eq("id", job.id).select("cancel_requested").single();
    if (data?.cancel_requested) controller.abort();
  }, 15_000);
  try {
    const handler = HANDLERS[job.kind];
    if (!handler) throw new NonRetryableError(`Unbekannter Job-Typ ${job.kind}`);
    jobLog.info("job started", { attempt: job.attempts });
    const result = await handler(job, { ...d, log: jobLog }, controller.signal);
    const cancelled = controller.signal.aborted;
    await d.db
      .from("scan_jobs")
      .update({ status: cancelled ? "cancelled" : "succeeded", finished_at: new Date().toISOString(), summary: JSON.parse(JSON.stringify(result ?? {})), error: null, locked_by: null })
      .eq("id", job.id);
    jobLog.info("job finished", { cancelled });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const retryable = !(err instanceof NonRetryableError) && job.attempts < job.max_attempts;
    jobLog.error("job failed", { error: message, retryable });
    await d.db
      .from("scan_jobs")
      .update(
        retryable
          ? { status: "queued", error: message, locked_by: null, run_after: new Date(Date.now() + 60_000 * 2 ** job.attempts).toISOString() }
          : { status: "failed", error: message, finished_at: new Date().toISOString(), locked_by: null },
      )
      .eq("id", job.id);
    if (!retryable && job.org_id && job.kind !== "public_check") {
      await addTimeline(d.db, { orgId: job.org_id, type: "scan_failed", severity: "medium", title: "Prüfung fehlgeschlagen", body: message, domainId: job.domain_id, link: "/app" }).catch(() => {});
      await notify(d.db, {
        orgId: job.org_id,
        type: "scan_failed",
        severity: "warning",
        title: "Eine Sicherheitsprüfung ist fehlgeschlagen",
        body: `Grund: ${message}\nWir prüfen automatisch erneut. Bleibt das Problem bestehen, kontaktieren Sie uns bitte.`,
        link: "/app",
        dedupeKey: `scan_failed:${job.domain_id}:${new Date().toISOString().slice(0, 10)}`,
      }).catch(() => {});
    }
    if (job.kind === "public_check") {
      const id = (job.payload as { public_check_id?: string }).public_check_id;
      if (id && !retryable) await d.db.from("public_checks").update({ status: "failed" }).eq("id", id);
    }
  } finally {
    clearInterval(heartbeat);
  }
}

async function claimLoop(slot: number) {
  while (!shuttingDown) {
    const { data, error } = await deps.db.rpc("claim_scan_job", { p_worker: `${workerId}#${slot}`, p_kinds: KINDS });
    if (error) {
      log.error("claim failed", { error: error.message });
      await sleep(5000);
      continue;
    }
    const job = (data as ScanJob[] | null)?.[0];
    if (!job) {
      await sleep(3000);
      continue;
    }
    await processJob(job);
  }
}

/** Periodische Aufgaben mit eigenen Intervallen; Fehler einzelner Aufgaben stoppen den Worker nie. */
function every(name: string, ms: number, fn: () => Promise<unknown>, runImmediately = true) {
  const run = async () => {
    if (shuttingDown) return;
    try {
      const res = await fn();
      if (res !== undefined) log.info(`${name} done`, { result: res as Record<string, unknown> });
    } catch (err) {
      log.error(`${name} failed`, { error: err instanceof Error ? err.message : String(err) });
    }
  };
  if (runImmediately) void run();
  return setInterval(run, ms);
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  log.info("worker starting", { concurrency: CONCURRENCY });
  const timers = [
    every("provider-health", 10 * 60_000, () => refreshProviderHealth(deps.db, env)),
    every("scheduler", 60_000, () => enqueueDueScans(deps)),
    every("intel-scheduler", 5 * 60_000, () => enqueueDueIntelWatches(deps)),
    every("requeue-stale", 2 * 60_000, async () => (await deps.db.rpc("requeue_stale_jobs", { p_stale_seconds: 300 })).data),
    every("email-outbox", 30_000, () => processEmailOutbox(deps)),
    every("kev", 24 * 3600_000, () => refreshKev(deps)),
    every("verification-recheck", 6 * 3600_000, () => recheckVerifications(deps)),
    every("monthly-reports", 6 * 3600_000, () => generateMonthlyReports(deps)),
    every("retention", 24 * 3600_000, () => applyRetention(deps)),
  ];
  const loops = Array.from({ length: CONCURRENCY }, (_, i) => claimLoop(i));
  const shutdown = (sig: string) => {
    log.info("shutdown requested", { signal: sig });
    shuttingDown = true;
    timers.forEach(clearInterval);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  await Promise.all(loops);
  log.info("worker stopped");
  process.exit(0);
}

if (process.argv[1]?.endsWith("index.ts") || process.argv[1]?.endsWith("index.js")) {
  main().catch((err) => {
    log.error("fatal", { error: String(err) });
    process.exit(1);
  });
}
