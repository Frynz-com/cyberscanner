import { DohResolver } from "../../src/lib/core/net/dns";
import { runAdapter, type AdapterRun } from "../../src/lib/core/scanners/runner";
import { assessmentAdapters } from "../../src/lib/core/scanners/registry";
import { NonRetryableError, type WorkerDeps } from "../deps";
import { persistFindings, storeScanResults } from "../persist";
import { recordProviderOutcome } from "../providers";
import { buildContext, loadScanScope, type ScanJob } from "./domain-scan";

/** Quellen, die ohne Kontakt zu Kundensystemen laufen und daher häufig abgefragt werden können. */
export const INTEL_ADAPTERS = ["hibp", "hudsonrock", "ransomware_live", "lookalike"];

/**
 * Leichter Überwachungslauf (Basis für 24/7-Monitoring): nur Threat-Intel-Quellen.
 * Neue Treffer erzeugen sofort Befunde + Warnungen; bestehende werden dedupliziert.
 */
export async function runIntelWatch(job: ScanJob, deps: WorkerDeps, signal: AbortSignal) {
  if (!job.org_id || !job.domain_id) throw new NonRetryableError("Job ohne Organisation/Domain");
  const scope = await loadScanScope(deps.db, job.org_id, job.domain_id);
  const apex = scope.domain.hostname;
  const ctx = await buildContext(deps, { orgId: job.org_id, scope, signal, resolver: new DohResolver(), hosts: [apex], ips: [], vulnScanHosts: [] });
  const runs: AdapterRun[] = [];
  for (const adapter of assessmentAdapters(deps.env).filter((a) => INTEL_ADAPTERS.includes(a.key))) {
    if (signal.aborted) break;
    const run = await runAdapter(adapter, ctx);
    await recordProviderOutcome(deps.db, adapter.key, run.output.status, run.output.message);
    runs.push(run);
  }
  await storeScanResults(deps.db, job.id, job.org_id, scope.domain.id, runs);
  // Abgleich nur für die hier geprüften Checks – Ergebnisse anderer Module bleiben unberührt
  const restrictTo = runs.flatMap((r) => r.output.coverage);
  const summary = await persistFindings(deps.db, { orgId: job.org_id, domainId: scope.domain.id, apex, jobId: job.id, runs, restrictTo: restrictTo.length ? restrictTo : [{ asset: "-", check: "-" }] });
  return { adapters: runs.map((r) => `${r.adapter}:${r.output.status}`), ...summary };
}
