import { createHash } from "node:crypto";
import { getRule } from "./rules";
import type { Certainty, Coverage, FindingStatus, NormalizedFinding, Observation, Severity } from "./types";
import { OPEN_STATUSES } from "./types";

export const SEVERITY_BASE: Record<Severity, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 5 };
export const CERTAINTY_FACTOR: Record<Certainty, number> = { confirmed: 1, potential: 0.85, informational: 0.6, not_checkable: 0.3 };
export const SEVERITY_LABEL: Record<Severity, string> = { critical: "kritisch", high: "hoch", medium: "mittel", low: "niedrig", info: "Information" };
export const CERTAINTY_LABEL: Record<Certainty, string> = {
  confirmed: "Bestätigter Befund",
  potential: "Mögliches Risiko",
  informational: "Informationshinweis",
  not_checkable: "Nicht prüfbar",
};

export function fingerprintOf(ruleId: string, asset: string, discriminator?: string): string {
  return createHash("sha256").update(`${ruleId}|${asset.toLowerCase()}|${discriminator ?? ""}`).digest("hex").slice(0, 40);
}

/**
 * Deterministisches Priorisierungsmodell:
 *   Score = Basiswert(Schweregrad) × Faktor(Gewissheit) + nachvollziehbare Zuschläge, begrenzt auf 0..100.
 */
export function prioritize(
  severity: Severity,
  certainty: Certainty,
  ctx: { isPrimaryAsset: boolean; kev?: boolean; recentBreach?: boolean },
  severityReasons: string[],
): { score: number; reasons: string[] } {
  const reasons = [
    `Schweregrad „${SEVERITY_LABEL[severity]}“: ${severityReasons.join("; ")}`,
    `Einstufung: ${CERTAINTY_LABEL[certainty]} (Faktor ${CERTAINTY_FACTOR[certainty]})`,
  ];
  let score = SEVERITY_BASE[severity] * CERTAINTY_FACTOR[certainty];
  if (ctx.isPrimaryAsset && severity !== "info") {
    score += 5;
    reasons.push("+5: betrifft die Hauptdomain bzw. www");
  }
  if (ctx.kev) {
    score += 10;
    reasons.push("+10: Schwachstelle wird laut CISA aktiv ausgenutzt");
  }
  if (ctx.recentBreach) {
    score += 5;
    reasons.push("+5: Datenleck in den letzten 90 Tagen bekannt geworden");
  }
  return { score: Math.max(0, Math.min(100, Math.round(score))), reasons };
}

export function normalizeObservation(o: Observation, source: string, apex: string): NormalizedFinding {
  const rule = getRule(o.ruleId);
  const evaluation = rule.evaluate(o);
  const isPrimaryAsset = o.asset === apex || o.asset === `www.${apex}`;
  const { score, reasons } = prioritize(
    evaluation.severity,
    rule.certainty,
    { isPrimaryAsset, kev: Boolean(o.facts.kev), recentBreach: Boolean(o.facts.recentBreach) },
    evaluation.reasons,
  );
  return {
    fingerprint: fingerprintOf(o.ruleId, o.asset, o.discriminator),
    ruleId: rule.id,
    check: rule.check,
    category: rule.category,
    source,
    sourceRef: o.sourceRef ?? null,
    asset: o.asset,
    title: rule.title(o),
    summary: rule.summary(o),
    businessImpact: rule.businessImpact(o),
    recommendation: rule.recommendation(o),
    technicalDetails: rule.technicalDetails(o),
    verificationSteps: rule.verificationSteps?.(o) ?? null,
    docs: rule.docs,
    evidence: o.evidence,
    severity: evaluation.severity,
    certainty: rule.certainty,
    confidence: rule.confidence,
    priorityScore: score,
    priorityReasons: reasons,
  };
}

// ---------------------------------------------------------------------------
// Abgleich mit dem Bestand: Deduplizierung, Änderungserkennung, Nachprüfung
// ---------------------------------------------------------------------------

export interface ExistingFinding {
  id: string;
  fingerprint: string;
  status: FindingStatus;
  checkKey: string;
  assetValue: string;
  severity: Severity;
  verificationState: "unverified" | "verified_fixed" | "still_present" | null;
}

export type ReconcileOp =
  | { type: "create"; finding: NormalizedFinding }
  | { type: "seen_again"; id: string; finding: NormalizedFinding; severityChanged: boolean; previousSeverity: Severity }
  | { type: "reappeared"; id: string; finding: NormalizedFinding; wasMarkedFixed: boolean; previousStatus: FindingStatus }
  | { type: "seen_closed"; id: string; finding: NormalizedFinding }
  | { type: "verified_fixed"; id: string; previousStatus: FindingStatus; alreadyClosed: boolean };

/**
 * Reine Funktion: berechnet die nötigen Änderungen. Ein Befund gilt nur dann als behoben,
 * wenn die zugehörige Prüfung für dasselbe Asset in diesem Lauf vollständig erfolgreich war
 * und den Befund nicht mehr beobachtet hat. Nicht geprüfte Befunde bleiben unverändert.
 */
export function reconcile(existing: ExistingFinding[], observed: NormalizedFinding[], coverage: Coverage[]): ReconcileOp[] {
  const ops: ReconcileOp[] = [];
  const byFp = new Map(existing.map((e) => [e.fingerprint, e]));
  const seen = new Set<string>();
  // identische Beobachtungen innerhalb eines Laufs zusammenfassen
  const unique = new Map<string, NormalizedFinding>();
  for (const f of observed) if (!unique.has(f.fingerprint)) unique.set(f.fingerprint, f);

  for (const f of unique.values()) {
    seen.add(f.fingerprint);
    const e = byFp.get(f.fingerprint);
    if (!e) {
      ops.push({ type: "create", finding: f });
    } else if (OPEN_STATUSES.includes(e.status)) {
      ops.push({ type: "seen_again", id: e.id, finding: f, severityChanged: e.severity !== f.severity, previousSeverity: e.severity });
    } else if (e.status === "resolved") {
      ops.push({ type: "reappeared", id: e.id, finding: f, wasMarkedFixed: e.verificationState === "unverified", previousStatus: e.status });
    } else {
      ops.push({ type: "seen_closed", id: e.id, finding: f });
    }
  }

  const covered = new Set(coverage.map((c) => `${c.asset.toLowerCase()}|${c.check}`));
  for (const e of existing) {
    if (seen.has(e.fingerprint)) continue;
    if (!covered.has(`${e.assetValue.toLowerCase()}|${e.checkKey}`)) continue;
    if (OPEN_STATUSES.includes(e.status)) {
      ops.push({ type: "verified_fixed", id: e.id, previousStatus: e.status, alreadyClosed: false });
    } else if (e.status === "resolved" && e.verificationState !== "verified_fixed") {
      ops.push({ type: "verified_fixed", id: e.id, previousStatus: e.status, alreadyClosed: true });
    }
  }
  return ops;
}
