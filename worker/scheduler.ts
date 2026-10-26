import { getEntitlements } from "../src/lib/core/entitlements";
import type { WorkerDeps } from "./deps";

/**
 * Plant wiederkehrende Prüfungen. Idempotenz über den Schlüssel sched:<domain>:<fälligkeitszeitpunkt>,
 * damit mehrere Worker-Instanzen nie doppelt einplanen.
 */
export async function enqueueDueScans(deps: WorkerDeps): Promise<number> {
  const { db } = deps;
  const now = new Date();
  const { data: due } = await db
    .from("domains")
    .select("id, org_id, hostname, next_scan_at, scan_interval_hours, organizations!inner(is_demo, monitoring_paused, deleted_at)")
    .eq("verification_status", "verified")
    .eq("monitoring_enabled", true)
    .eq("is_demo", false)
    .lte("next_scan_at", now.toISOString())
    .limit(50);
  let queued = 0;
  for (const d of due ?? []) {
    const org = d.organizations as unknown as { is_demo: boolean; monitoring_paused: boolean; deleted_at: string | null };
    if (org.is_demo || org.monitoring_paused || org.deleted_at) continue;
    const ent = await getEntitlements(db, d.org_id);
    const next = new Date(now.getTime() + Math.max(d.scan_interval_hours, ent.limits.min_scan_interval_hours) * 3600_000).toISOString();
    if (!ent.active) {
      await db.from("domains").update({ next_scan_at: next }).eq("id", d.id);
      continue;
    }
    const { data: auth } = await db.from("scan_authorizations").select("id").eq("domain_id", d.id).is("revoked_at", null).gt("valid_until", now.toISOString()).limit(1).maybeSingle();
    if (!auth) {
      await db.from("domains").update({ next_scan_at: next }).eq("id", d.id);
      continue;
    }
    const { data: pendingJob } = await db.from("scan_jobs").select("id").eq("domain_id", d.id).eq("kind", "domain_scan").in("status", ["queued", "running"]).limit(1).maybeSingle();
    if (pendingJob) {
      await db.from("domains").update({ next_scan_at: next }).eq("id", d.id);
      continue;
    }
    const { error } = await db.from("scan_jobs").insert({
      org_id: d.org_id,
      domain_id: d.id,
      kind: "domain_scan",
      trigger: "schedule",
      priority: 0,
      idempotency_key: `sched:${d.id}:${d.next_scan_at}`,
    });
    if (!error) queued++;
    else if (error.code !== "23505") deps.log.error("enqueue failed", { domain: d.id, error: error.message });
    // nächste Fälligkeit setzen, damit dieselbe Domain nicht in jeder Runde erneut auftaucht
    await db.from("domains").update({ next_scan_at: next }).eq("id", d.id);
  }
  return queued;
}

/**
 * Plant leichte Threat-Intel-Läufe je nach Tarif (z. B. stündlich in Shield Care).
 * Läuft unabhängig vom vollständigen Scan; nie parallel zu einem laufenden Job derselben Domain.
 */
export async function enqueueDueIntelWatches(deps: WorkerDeps): Promise<number> {
  const { db } = deps;
  const now = new Date();
  const { data: domains } = await db
    .from("domains")
    .select("id, org_id, next_intel_at, last_scan_at, organizations!inner(is_demo, monitoring_paused, deleted_at)")
    .eq("verification_status", "verified")
    .eq("monitoring_enabled", true)
    .eq("is_demo", false)
    .not("last_scan_at", "is", null)
    .or(`next_intel_at.is.null,next_intel_at.lte.${now.toISOString()}`)
    .limit(100);
  let queued = 0;
  for (const d of domains ?? []) {
    const org = d.organizations as unknown as { monitoring_paused: boolean; deleted_at: string | null };
    if (org.monitoring_paused || org.deleted_at) continue;
    const ent = await getEntitlements(db, d.org_id);
    const next = new Date(now.getTime() + ent.limits.intel_interval_hours * 3600_000).toISOString();
    await db.from("domains").update({ next_intel_at: next }).eq("id", d.id);
    if (!ent.active) continue;
    const { data: busy } = await db.from("scan_jobs").select("id").eq("domain_id", d.id).in("status", ["queued", "running"]).limit(1).maybeSingle();
    if (busy) continue;
    const { error } = await db.from("scan_jobs").insert({ org_id: d.org_id, domain_id: d.id, kind: "intel_watch", trigger: "schedule", priority: 3, idempotency_key: `intel:${d.id}:${d.next_intel_at ?? now.toISOString().slice(0, 13)}` });
    if (!error) queued++;
  }
  return queued;
}
