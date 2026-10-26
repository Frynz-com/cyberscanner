import { notify } from "../src/lib/core/events";
import { DohResolver, resolveTxt, type DnsResolver } from "../src/lib/core/net/dns";
import type { WorkerDeps } from "./deps";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/** CISA KEV (gemeinfrei) für deterministische Priorisierung laden. */
export async function refreshKev(deps: WorkerDeps, fetchImpl: typeof fetch = fetch) {
  const res = await fetchImpl(KEV_URL, { signal: AbortSignal.timeout(60_000), headers: { "user-agent": "CyberSafe24-Shield/1.0" } });
  if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
  const json = (await res.json()) as {
    vulnerabilities: Array<{ cveID: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; knownRansomwareCampaignUse: string }>;
  };
  const rows = json.vulnerabilities.map((v) => ({
    cve_id: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    name: v.vulnerabilityName,
    date_added: v.dateAdded,
    known_ransomware: v.knownRansomwareCampaignUse === "Known",
  }));
  for (let i = 0; i < rows.length; i += 500) {
    const { error } = await deps.db.from("cve_kev").upsert(rows.slice(i, i + 500), { onConflict: "cve_id" });
    if (error) throw new Error(`KEV upsert: ${error.message}`);
  }
  await deps.db
    .from("provider_integrations")
    .update({ status: "available", last_checked_at: new Date().toISOString(), last_success_at: new Date().toISOString(), status_message: `${rows.length} Einträge` })
    .eq("key", "cisa_kev");
  return rows.length;
}

export const VERIFICATION_GRACE_DAYS = 14;

/**
 * Prüft regelmäßig, ob der Verifizierungseintrag noch existiert. Fehlt er länger als
 * VERIFICATION_GRACE_DAYS, wird die Verifizierung entzogen und die Überwachung stoppt.
 */
export async function recheckVerifications(deps: WorkerDeps, resolver: DnsResolver = new DohResolver()) {
  const { db } = deps;
  const cutoff = new Date(Date.now() - 7 * 86_400_000).toISOString();
  const { data: domains } = await db
    .from("domains")
    .select("id, org_id, hostname, verification_last_checked_at")
    .eq("verification_status", "verified")
    .eq("is_demo", false)
    .or(`verification_last_checked_at.is.null,verification_last_checked_at.lt.${cutoff}`)
    .limit(100);
  let expired = 0;
  for (const d of domains ?? []) {
    const { data: ch } = await db
      .from("verification_challenges")
      .select("id, record_name, token, last_result")
      .eq("domain_id", d.id)
      .not("consumed_at", "is", null)
      .order("consumed_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (!ch) continue;
    let present: boolean;
    try {
      const { records } = await resolveTxt(resolver, ch.record_name);
      present = records.some((r) => r.trim() === ch.token);
    } catch {
      continue; // DNS-Fehler: später erneut versuchen, nichts entziehen
    }
    const now = new Date();
    if (present) {
      await db.from("verification_challenges").update({ last_checked_at: now.toISOString(), last_result: "present" }).eq("id", ch.id);
      await db.from("domains").update({ verification_last_checked_at: now.toISOString() }).eq("id", d.id);
      continue;
    }
    const missingSince = ch.last_result?.startsWith("missing_since:") ? new Date(ch.last_result.slice(14)) : now;
    await db.from("verification_challenges").update({ last_checked_at: now.toISOString(), last_result: `missing_since:${missingSince.toISOString()}` }).eq("id", ch.id);
    const daysMissing = (now.getTime() - missingSince.getTime()) / 86_400_000;
    if (daysMissing >= VERIFICATION_GRACE_DAYS) {
      await db.from("domains").update({ verification_status: "expired", verification_last_checked_at: now.toISOString() }).eq("id", d.id);
      expired++;
      await notify(db, {
        orgId: d.org_id,
        type: "verification",
        severity: "warning",
        title: `Überwachung von ${d.hostname} gestoppt`,
        body: `Der DNS-Verifizierungseintrag ${ch.record_name} wurde seit ${VERIFICATION_GRACE_DAYS} Tagen nicht mehr gefunden. Aus Sicherheitsgründen werden keine weiteren Prüfungen durchgeführt, bis die Domain erneut verifiziert ist.`,
        link: "/app/domains",
        dedupeKey: `verification:${d.id}:expired:${now.toISOString().slice(0, 10)}`,
      });
    } else {
      await db.from("domains").update({ verification_last_checked_at: now.toISOString() }).eq("id", d.id);
      await notify(db, {
        orgId: d.org_id,
        type: "verification",
        severity: "warning",
        title: `Verifizierungseintrag für ${d.hostname} fehlt`,
        body: `Der DNS-TXT-Eintrag ${ch.record_name} wurde nicht gefunden. Bitte stellen Sie ihn wieder her. Ohne Eintrag endet die Überwachung in ${Math.ceil(VERIFICATION_GRACE_DAYS - daysMissing)} Tagen.`,
        link: "/app/domains",
        dedupeKey: `verification:${d.id}:missing:${missingSince.toISOString().slice(0, 10)}`,
      });
    }
  }
  return { checked: domains?.length ?? 0, expired };
}

/** Löschkonzept: abgelaufene Daten entfernen (Datenminimierung). */
export async function applyRetention(deps: WorkerDeps) {
  const { db } = deps;
  const now = Date.now();
  await db.from("public_checks").delete().lt("expires_at", new Date(now).toISOString());
  await db.from("rate_limits").delete().lt("window_start", new Date(now - 2 * 86_400_000).toISOString());
  await db.from("leads").delete().lt("created_at", new Date(now - 365 * 86_400_000).toISOString());
  // Breach-Datensätze: nach Aufbewahrungsfrist der Organisation löschen, wenn nicht mehr beobachtet
  const { data: orgs } = await db.from("organizations").select("id, data_retention_days, deleted_at");
  for (const o of orgs ?? []) {
    if (o.deleted_at && new Date(o.deleted_at).getTime() < now - 30 * 86_400_000) {
      await db.from("organizations").delete().eq("id", o.id); // Kaskadierende Löschung aller Mandantendaten
      continue;
    }
    const cutoff = new Date(now - o.data_retention_days * 86_400_000).toISOString();
    await db.from("breach_records").delete().eq("org_id", o.id).lt("last_observed_at", cutoff);
    await db.from("scan_results").delete().eq("org_id", o.id).lt("finished_at", cutoff);
  }
  // Dateien gelöschter Organisationen werden über incident_files/reports-Verweise mitgelöscht (siehe Storage-Bereinigung)
}
