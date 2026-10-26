import { adapterName } from "../src/lib/core/adapter-labels";
import { encryptField, hmac } from "../src/lib/core/crypto";
import { addTimeline, notify } from "../src/lib/core/events";
import { fingerprintOf, normalizeObservation, reconcile, SEVERITY_LABEL, type ExistingFinding } from "../src/lib/core/risk/engine";
import type { Coverage, NormalizedFinding } from "../src/lib/core/risk/types";
import type { AdapterRun } from "../src/lib/core/scanners/runner";
import type { Db } from "./deps";

export interface PersistSummary {
  created: number;
  reappeared: number;
  verifiedFixed: number;
  stillPresent: number;
  open: number;
}

const OPEN = ["new", "investigating", "action_required"];

/** Speichert die Rohergebnisse je Adapter (Nachvollziehbarkeit / Monitoring-Abdeckung). */
export async function storeScanResults(db: Db, jobId: string, orgId: string | null, domainId: string | null, runs: AdapterRun[]) {
  if (runs.length === 0) return;
  const rows = runs.map((r) => ({
    job_id: jobId,
    org_id: orgId,
    domain_id: domainId,
    adapter: r.adapter,
    status: r.output.status,
    started_at: r.startedAt.toISOString(),
    finished_at: r.finishedAt.toISOString(),
    duration_ms: r.finishedAt.getTime() - r.startedAt.getTime(),
    targets: r.output.targets.slice(0, 500),
    checks: [...new Set(r.output.coverage.map((c) => c.check))],
    observation_count: r.output.observations.length,
    message: r.output.message ?? null,
    data: JSON.parse(JSON.stringify(r.output.data)),
  }));
  const { error } = await db.from("scan_results").insert(rows);
  if (error) throw new Error(`scan_results: ${error.message}`);
}

/**
 * Normalisiert Beobachtungen, gleicht sie mit dem Bestand ab und schreibt
 * Findings, Ereignisse, Timeline und Benachrichtigungen.
 */
export async function persistFindings(
  db: Db,
  p: {
    orgId: string;
    domainId: string;
    apex: string;
    jobId: string;
    runs: AdapterRun[];
    /** Optional: Abgleich nur auf diese Asset/Check-Kombinationen begrenzen (Nachprüfung) */
    restrictTo?: Coverage[];
  },
): Promise<PersistSummary> {
  const now = new Date().toISOString();
  let normalized: NormalizedFinding[] = p.runs.flatMap((r) => r.output.observations.map((o) => normalizeObservation(o, r.adapter, p.apex)));
  let coverage = p.runs.flatMap((r) => r.output.coverage);

  const { data: existingRows, error } = await db
    .from("findings")
    .select("id, fingerprint, status, check_key, asset_value, severity, verification_state, title")
    .eq("org_id", p.orgId)
    .eq("domain_id", p.domainId);
  if (error) throw new Error(`findings laden: ${error.message}`);
  let existing: ExistingFinding[] = (existingRows ?? []).map((r) => ({
    id: r.id,
    fingerprint: r.fingerprint,
    status: r.status,
    checkKey: r.check_key,
    assetValue: r.asset_value,
    severity: r.severity,
    verificationState: r.verification_state as ExistingFinding["verificationState"],
  }));

  if (p.restrictTo) {
    const allowed = new Set(p.restrictTo.map((c) => `${c.asset}|${c.check}`));
    normalized = normalized.filter((f) => allowed.has(`${f.asset}|${f.check}`));
    coverage = coverage.filter((c) => allowed.has(`${c.asset}|${c.check}`));
    existing = existing.filter((e) => allowed.has(`${e.assetValue}|${e.checkKey}`));
  }

  const { data: assetRows } = await db.from("assets").select("id, value").eq("org_id", p.orgId).eq("domain_id", p.domainId);
  const assetIds = new Map((assetRows ?? []).map((a) => [a.value, a.id]));
  const titles = new Map((existingRows ?? []).map((r) => [r.id, r.title]));

  const ops = reconcile(existing, normalized, coverage);
  const summary: PersistSummary = { created: 0, reappeared: 0, verifiedFixed: 0, stillPresent: 0, open: 0 };
  const fpToId = new Map(existing.map((e) => [e.fingerprint, e.id]));
  const link = (id: string) => `/app/findings/${id}`;

  const content = (f: NormalizedFinding) => ({
    title: f.title,
    summary: f.summary,
    business_impact: f.businessImpact,
    recommendation: f.recommendation,
    technical_details: f.technicalDetails,
    verification_steps: f.verificationSteps,
    docs: JSON.parse(JSON.stringify(f.docs)),
    evidence: JSON.parse(JSON.stringify(f.evidence)),
    severity: f.severity,
    certainty: f.certainty,
    confidence: f.confidence,
    priority_score: f.priorityScore,
    priority_reasons: f.priorityReasons,
    source: f.source,
    source_ref: f.sourceRef,
    last_seen_at: now,
    last_job_id: p.jobId,
  });

  for (const op of ops) {
    if (op.type === "create") {
      const f = op.finding;
      const { data: ins, error: insErr } = await db
        .from("findings")
        .insert({
          org_id: p.orgId,
          domain_id: p.domainId,
          asset_id: assetIds.get(f.asset) ?? null,
          asset_value: f.asset,
          fingerprint: f.fingerprint,
          rule_id: f.ruleId,
          check_key: f.check,
          category: f.category,
          status: "new",
          first_seen_at: now,
          ...content(f),
        })
        .select("id")
        .single();
      if (insErr) {
        if (insErr.code === "23505") continue; // parallel angelegt – Unique-Constraint verhindert Duplikat
        throw new Error(`finding insert: ${insErr.message}`);
      }
      fpToId.set(f.fingerprint, ins.id);
      summary.created++;
      await db.from("finding_events").insert({
        org_id: p.orgId,
        finding_id: ins.id,
        type: "detected",
        to_status: "new",
        actor_type: "system",
        actor_label: adapterName(f.source),
        message: `Erstmals erkannt durch Prüfmodul „${adapterName(f.source)}“`,
        data: { severity: f.severity, certainty: f.certainty },
      });
      const isBreach = f.category === "breach";
      if (f.severity !== "info" || isBreach) {
        await addTimeline(db, {
          orgId: p.orgId,
          type: isBreach ? "breach_detected" : "finding_detected",
          severity: f.severity,
          title: f.title,
          body: `${f.asset} · Schweregrad ${SEVERITY_LABEL[f.severity]}`,
          link: link(ins.id),
          findingId: ins.id,
          domainId: p.domainId,
        });
      }
      if (f.severity === "critical" || f.severity === "high") {
        await notify(db, {
          orgId: p.orgId,
          type: isBreach ? "breach" : "finding",
          severity: f.severity === "critical" ? "critical" : "warning",
          title: `Neuer Befund: ${f.title}`,
          body: `${f.summary}\n\nEmpfehlung: ${f.recommendation}`,
          link: link(ins.id),
          dedupeKey: `finding:${f.fingerprint}:detected`,
        });
      }
    } else if (op.type === "seen_again") {
      await db.from("findings").update(content(op.finding)).eq("id", op.id);
      if (op.severityChanged) {
        await db.from("finding_events").insert({
          org_id: p.orgId,
          finding_id: op.id,
          type: "severity_changed",
          actor_type: "system",
          message: `Schweregrad geändert: ${SEVERITY_LABEL[op.previousSeverity]} → ${SEVERITY_LABEL[op.finding.severity]}`,
          data: { from: op.previousSeverity, to: op.finding.severity },
        });
        // z. B. Zertifikat rückt näher an das Ablaufdatum -> Eskalation melden
        const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
        if (rank[op.finding.severity] > rank[op.previousSeverity] && rank[op.finding.severity] >= 3) {
          await notify(db, {
            orgId: p.orgId,
            type: "finding",
            severity: op.finding.severity === "critical" ? "critical" : "warning",
            title: `Dringender geworden: ${op.finding.title}`,
            body: `${op.finding.summary}\n\nEmpfehlung: ${op.finding.recommendation}`,
            link: link(op.id),
            dedupeKey: `finding:${op.finding.fingerprint}:escalated:${op.finding.severity}`,
          });
        }
      }
    } else if (op.type === "reappeared") {
      await db
        .from("findings")
        .update({ ...content(op.finding), status: "action_required", resolved_at: null, verification_state: op.wasMarkedFixed ? "still_present" : null })
        .eq("id", op.id);
      const { data: cur } = await db.from("findings").select("reopened_count").eq("id", op.id).single();
      await db.from("findings").update({ reopened_count: (cur?.reopened_count ?? 0) + 1 }).eq("id", op.id);
      if (op.wasMarkedFixed) summary.stillPresent++;
      else summary.reappeared++;
      await db.from("finding_events").insert({
        org_id: p.orgId,
        finding_id: op.id,
        type: op.wasMarkedFixed ? "still_present" : "reappeared",
        from_status: op.previousStatus,
        to_status: "action_required",
        actor_type: "system",
        message: op.wasMarkedFixed
          ? "Nachprüfung: Das Problem besteht weiterhin, obwohl es als behoben markiert wurde."
          : "Das Problem ist erneut aufgetreten.",
      });
      await db.from("actions").update({ status: "still_open" }).eq("finding_id", op.id).eq("status", "fixed_pending_verification");
      await addTimeline(db, {
        orgId: p.orgId,
        type: op.wasMarkedFixed ? "reverify_failed" : "finding_reappeared",
        severity: op.finding.severity,
        title: op.wasMarkedFixed ? `Nachprüfung: weiterhin offen – ${op.finding.title}` : `Erneut aufgetreten: ${op.finding.title}`,
        body: op.finding.asset,
        link: link(op.id),
        findingId: op.id,
        domainId: p.domainId,
      });
      if (op.finding.severity === "critical" || op.finding.severity === "high") {
        await notify(db, {
          orgId: p.orgId,
          type: "finding",
          severity: "warning",
          title: `Erneut aufgetreten: ${op.finding.title}`,
          body: op.finding.summary,
          link: link(op.id),
          dedupeKey: `finding:${op.finding.fingerprint}:reappeared:${now.slice(0, 10)}`,
        });
      }
    } else if (op.type === "seen_closed") {
      await db.from("findings").update({ last_seen_at: now, last_job_id: p.jobId }).eq("id", op.id);
    } else if (op.type === "verified_fixed") {
      await db
        .from("findings")
        .update({ status: "resolved", verification_state: "verified_fixed", ...(op.alreadyClosed ? {} : { resolved_at: now }) })
        .eq("id", op.id);
      summary.verifiedFixed++;
      await db.from("finding_events").insert({
        org_id: p.orgId,
        finding_id: op.id,
        type: "verified_fixed",
        from_status: op.previousStatus,
        to_status: "resolved",
        actor_type: "system",
        message: "Nachprüfung erfolgreich: Die Prüfung wurde vollständig durchgeführt und das Problem nicht mehr festgestellt.",
      });
      await db.from("actions").update({ status: "verified" }).eq("finding_id", op.id).in("status", ["open", "in_progress", "fixed_pending_verification"]);
      await addTimeline(db, {
        orgId: p.orgId,
        type: "reverify_passed",
        severity: "success",
        title: `Behebung bestätigt: ${titles.get(op.id) ?? "Befund"}`,
        link: link(op.id),
        findingId: op.id,
        domainId: p.domainId,
      });
    }
  }

  // Personenbezogene Breach-Daten: verschlüsselt + pseudonymisiert, minimiert
  const breachInputs = p.runs.flatMap((r) => r.output.breachRecords ?? []);
  if (breachInputs.length > 0) {
    const rows = breachInputs.map((b) => ({
      org_id: p.orgId,
      domain_id: p.domainId,
      finding_id: fpToId.get(fingerprintOf(b.findingRuleId, p.apex, b.findingDiscriminator)) ?? null,
      provider: b.provider,
      account_hmac: hmac(b.account),
      account_enc: encryptField(b.account),
      breach_key: b.breachKey,
      breach_title: b.breachTitle,
      breach_date: b.breachDate,
      breach_added_at: b.breachAddedAt,
      data_classes: b.dataClasses,
      is_stealer_log: b.isStealerLog,
      is_synthetic: b.isSynthetic,
      last_observed_at: now,
    }));
    for (let i = 0; i < rows.length; i += 200) {
      const { error: bErr } = await db.from("breach_records").upsert(rows.slice(i, i + 200), { onConflict: "org_id,provider,account_hmac,breach_key" });
      if (bErr) throw new Error(`breach_records: ${bErr.message}`);
    }
  }

  const { count } = await db.from("findings").select("id", { count: "exact", head: true }).eq("org_id", p.orgId).in("status", OPEN as never);
  summary.open = count ?? 0;
  return summary;
}
