import { normalizeObservation } from "../../src/lib/core/risk/engine";
import { DohResolver } from "../../src/lib/core/net/dns";
import { runAdapter } from "../../src/lib/core/scanners/runner";
import { publicCheckAdapters } from "../../src/lib/core/scanners/registry";
import type { ScanContext } from "../../src/lib/core/scanners/types";
import { NonRetryableError, type WorkerDeps } from "../deps";
import type { ScanJob } from "./domain-scan";

/**
 * Öffentlicher Kurzcheck (ohne Verifikation): ausschließlich DNS/E-Mail-Konfiguration,
 * TLS-Zertifikat und HTTP-Header der Hauptdomain und www – entspricht einem Browseraufruf.
 * Keine Subdomain-Erkennung, keine Portscans, keine Leak-Abfragen, keine Schwachstellenprüfung.
 * Ergebnisse werden NICHT als Findings gespeichert, nur als Kurzbericht.
 */
export async function runPublicCheck(job: ScanJob, deps: WorkerDeps, signal: AbortSignal) {
  const { db } = deps;
  const checkId = (job.payload as { public_check_id?: string }).public_check_id;
  if (!checkId) throw new NonRetryableError("Ungültiger Kurzcheck");
  const { data: check } = await db.from("public_checks").select("*").eq("id", checkId).single();
  if (!check) throw new NonRetryableError("Kurzcheck nicht gefunden");
  await db.from("public_checks").update({ status: "running" }).eq("id", checkId);
  const apex = check.hostname;
  const ctx: ScanContext = {
    mode: "public_check",
    orgId: null,
    domainId: null,
    apex,
    hosts: [apex, `www.${apex}`],
    ips: [],
    vulnScanHosts: [],
    authorization: { domainVerified: false, scopes: ["passive", "config"], includeSubdomains: false },
    resolver: new DohResolver(),
    signal,
    log: deps.log,
    limits: { maxHosts: 2, breachMonitoring: false, vulnScan: false },
  };
  const modules: Array<{ key: string; label: string; status: string; message: string | null }> = [];
  const findings = [];
  const data: Record<string, unknown> = {};
  for (const adapter of publicCheckAdapters(deps.env)) {
    const run = await runAdapter(adapter, ctx);
    modules.push({ key: adapter.key, label: adapter.label, status: run.output.status, message: run.output.message ?? null });
    data[adapter.key] = run.output.data;
    for (const o of run.output.observations) {
      const f = normalizeObservation(o, adapter.key, apex);
      findings.push({ title: f.title, summary: f.summary, severity: f.severity, certainty: f.certainty, asset: f.asset, recommendation: f.recommendation, priority: f.priorityScore, category: f.category });
    }
  }
  findings.sort((a, b) => b.priority - a.priority);
  const result = { hostname: apex, checkedAt: new Date().toISOString(), modules, findings, data };
  await db.from("public_checks").update({ status: "done", result: JSON.parse(JSON.stringify(result)) }).eq("id", checkId);
  return { findings: findings.length };
}
