import { addTimeline, notify } from "../src/lib/core/events";
import { buildReportSnapshot } from "../src/lib/core/report-data";
import type { WorkerDeps } from "./deps";

/** Erstellt am Monatsanfang den Bericht für den Vormonat (idempotent über Unique-Index). */
export async function generateMonthlyReports(deps: WorkerDeps, now = new Date()) {
  const { db } = deps;
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) - 1);
  // Nur Organisationen, die im Berichtszeitraum bereits bestanden
  const { data: orgs } = await db.from("organizations").select("id, name").eq("is_demo", false).is("deleted_at", null).lt("created_at", end.toISOString());
  let created = 0;
  for (const org of orgs ?? []) {
    const { count: domainCount } = await db.from("domains").select("id", { count: "exact", head: true }).eq("org_id", org.id).eq("verification_status", "verified");
    if (!domainCount) continue;
    const { data: existing } = await db.from("reports").select("id").eq("org_id", org.id).eq("kind", "monthly").eq("period_start", start.toISOString()).maybeSingle();
    if (existing) continue;
    const snapshot = await buildReportSnapshot(db, org.id, start, end);
    const { data: rep, error } = await db
      .from("reports")
      .insert({ org_id: org.id, kind: "monthly", period_start: start.toISOString(), period_end: end.toISOString(), snapshot: JSON.parse(JSON.stringify(snapshot)) })
      .select("id")
      .single();
    if (error) {
      if (error.code !== "23505") deps.log.error("report insert failed", { org: org.id, error: error.message });
      continue;
    }
    created++;
    const month = start.toLocaleDateString("de-DE", { month: "long", year: "numeric", timeZone: "UTC" });
    await addTimeline(db, { orgId: org.id, type: "report_created", severity: "info", title: `Monatsbericht ${month} erstellt`, link: `/app/reports` });
    await notify(db, {
      orgId: org.id,
      type: "report",
      severity: "info",
      title: `Ihr Sicherheitsbericht für ${month} ist verfügbar`,
      body: `Seit Ihrem letzten Bericht wurden ${snapshot.counts.newInPeriod} neue Befunde erkannt und ${snapshot.counts.verifiedInPeriod} Befunde erfolgreich nachgeprüft.`,
      link: `/app/reports/${rep.id}`,
      dedupeKey: `report:${start.toISOString().slice(0, 7)}`,
      email: true,
    });
  }
  return { created };
}
