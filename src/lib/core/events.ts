import type { Json } from "../database.types";
import type { Db } from "./db";

type TimelineType =
  | "scan_completed" | "scan_failed" | "asset_discovered" | "finding_detected" | "finding_reappeared" | "breach_detected"
  | "shared_with_partner" | "partner_update" | "status_changed" | "reverify_passed" | "reverify_failed" | "report_created"
  | "incident_reported" | "domain_verified" | "domain_added" | "authorization_granted" | "monitoring_changed";

export async function addTimeline(
  db: Db,
  e: { orgId: string; type: TimelineType; severity?: string; title: string; body?: string; link?: string; findingId?: string; domainId?: string | null; data?: Json },
) {
  const { error } = await db.from("timeline_events").insert({
    org_id: e.orgId,
    type: e.type,
    severity: e.severity ?? "info",
    title: e.title,
    body: e.body ?? null,
    link: e.link ?? null,
    finding_id: e.findingId ?? null,
    domain_id: e.domainId ?? null,
    data: e.data ?? {},
  });
  if (error) throw new Error(`timeline insert: ${error.message}`);
}

/**
 * Benachrichtigung mit Deduplizierung (unique org_id + dedupe_key).
 * E-Mail nur für "critical"/"warning"; Info-Meldungen erscheinen nur in der App.
 */
export async function notify(
  db: Db,
  n: { orgId: string; type: string; severity: "critical" | "warning" | "info" | "success"; title: string; body: string; link?: string; dedupeKey: string; email?: boolean },
): Promise<boolean> {
  const wantsEmail = n.email ?? (n.severity === "critical" || n.severity === "warning");
  const { error } = await db.from("notifications").insert({
    org_id: n.orgId,
    type: n.type,
    severity: n.severity,
    title: n.title,
    body: n.body,
    link: n.link ?? null,
    dedupe_key: n.dedupeKey,
    email_status: wantsEmail ? "pending" : "skipped",
  });
  if (error) {
    if (error.code === "23505") return false; // bereits benachrichtigt
    throw new Error(`notification insert: ${error.message}`);
  }
  return true;
}

export async function audit(
  db: Db,
  a: { orgId: string | null; actorType: "user" | "system" | "partner" | "admin" | "stripe" | "public"; actorId?: string | null; action: string; targetType?: string; targetId?: string; data?: Json; ipHash?: string },
) {
  await db.from("audit_logs").insert({
    org_id: a.orgId,
    actor_type: a.actorType,
    actor_id: a.actorId ?? null,
    action: a.action,
    target_type: a.targetType ?? null,
    target_id: a.targetId ?? null,
    data: a.data ?? {},
    ip_hash: a.ipHash ?? null,
  });
}
