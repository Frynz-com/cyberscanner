import { addTimeline } from "../../src/lib/core/events";
import { DohResolver } from "../../src/lib/core/net/dns";
import { runAdapter } from "../../src/lib/core/scanners/runner";
import { assessmentAdapters } from "../../src/lib/core/scanners/registry";
import { NonRetryableError, type WorkerDeps } from "../deps";
import { persistFindings, storeScanResults } from "../persist";
import { recordProviderOutcome } from "../providers";
import { buildContext, loadScanScope, type ScanJob } from "./domain-scan";

export function adapterForCheck(check: string): string {
  if (check.startsWith("email.") || check.startsWith("dns.")) return "dns";
  if (check.startsWith("tls.")) return "tls";
  if (check.startsWith("web.")) return "http_headers";
  if (check.startsWith("exposure.")) return "internetdb";
  if (check.startsWith("breach.")) return "hibp";
  if (check.startsWith("vuln.")) return "nuclei";
  throw new NonRetryableError(`Keine Nachprüfung für ${check} möglich`);
}

/**
 * Gezielte Nachprüfung eines Befunds: führt nur die zuständige Prüfung für das betroffene Asset aus.
 * Ergebnis "behoben" nur, wenn die Prüfung vollständig lief und den Befund nicht mehr feststellt.
 */
export async function runReverify(job: ScanJob, deps: WorkerDeps, signal: AbortSignal) {
  const { db } = deps;
  const findingId = (job.payload as { finding_id?: string }).finding_id;
  if (!job.org_id || !findingId) throw new NonRetryableError("Ungültiger Nachprüfungs-Job");
  const { data: finding } = await db.from("findings").select("*").eq("id", findingId).eq("org_id", job.org_id).single();
  if (!finding || !finding.domain_id) throw new NonRetryableError("Befund nicht gefunden");
  const scope = await loadScanScope(db, job.org_id, finding.domain_id);
  const apex = scope.domain.hostname;
  const adapterKey = adapterForCheck(finding.check_key);
  const adapter = assessmentAdapters(deps.env).find((a) => a.key === adapterKey);
  if (!adapter) throw new NonRetryableError("Prüfmodul nicht verfügbar");

  const isIp = adapterKey === "internetdb";
  const { data: asset } = await db.from("assets").select("vuln_scan_approved").eq("org_id", job.org_id).eq("value", finding.asset_value).maybeSingle();
  const ctx = await buildContext(deps, {
    orgId: job.org_id,
    scope,
    signal,
    resolver: new DohResolver(),
    hosts: isIp ? [apex] : [...new Set([apex, finding.asset_value])].filter((h) => adapterKey === "dns" || h === finding.asset_value),
    ips: isIp ? [finding.asset_value] : [],
    vulnScanHosts: asset?.vuln_scan_approved ? [finding.asset_value] : [],
  });
  const run = await runAdapter(adapter, ctx);
  await recordProviderOutcome(db, adapter.key, run.output.status, run.output.message);
  await storeScanResults(db, job.id, job.org_id, finding.domain_id, [run]);

  const covered = run.output.coverage.some((c) => c.asset === finding.asset_value && c.check === finding.check_key);
  if (!covered) {
    await db.from("finding_events").insert({
      org_id: job.org_id,
      finding_id: finding.id,
      type: "comment",
      actor_type: "system",
      message: `Nachprüfung nicht möglich: ${run.output.message ?? "Prüfung konnte nicht vollständig durchgeführt werden"}. Der Status bleibt unverändert.`,
    });
    await addTimeline(db, {
      orgId: job.org_id,
      type: "reverify_failed",
      severity: "low",
      title: `Nachprüfung nicht abschließbar: ${finding.title}`,
      body: run.output.message ?? undefined,
      link: `/app/findings/${finding.id}`,
      findingId: finding.id,
      domainId: finding.domain_id,
    });
    return { covered: false, status: run.output.status };
  }
  const summary = await persistFindings(db, {
    orgId: job.org_id,
    domainId: finding.domain_id,
    apex,
    jobId: job.id,
    runs: [run],
    restrictTo: [{ asset: finding.asset_value, check: finding.check_key }],
  });
  // Explizites "weiterhin vorhanden" für offene Befunde, die erneut beobachtet wurden
  const { data: after } = await db.from("findings").select("status, verification_state").eq("id", finding.id).single();
  if (after && after.status !== "resolved" && summary.stillPresent === 0) {
    await db.from("findings").update({ verification_state: "still_present" }).eq("id", finding.id);
    await db.from("finding_events").insert({
      org_id: job.org_id,
      finding_id: finding.id,
      type: "still_present",
      actor_type: "system",
      message: "Nachprüfung: Das Problem wurde erneut festgestellt.",
    });
    await db.from("actions").update({ status: "still_open" }).eq("finding_id", finding.id).eq("status", "fixed_pending_verification");
    await addTimeline(db, {
      orgId: job.org_id,
      type: "reverify_failed",
      severity: finding.severity,
      title: `Nachprüfung: weiterhin offen – ${finding.title}`,
      link: `/app/findings/${finding.id}`,
      findingId: finding.id,
      domainId: finding.domain_id,
    });
  }
  return { covered: true, resolved: after?.status === "resolved", ...summary };
}
