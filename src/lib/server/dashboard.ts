import "server-only";
import { getEntitlements } from "@/lib/core/entitlements";
import { computeMonitoringStatus } from "@/lib/core/monitoring-status";
import { createClient } from "@/lib/supabase/server";

const OPEN = ["new", "investigating", "action_required"] as const;

export async function loadDashboard(orgId: string, isDemo: boolean, orgPaused: boolean) {
  const supabase = await createClient();
  const since7 = new Date(Date.now() - 7 * 86_400_000).toISOString();
  const [domains, auths, jobs, findings, coverage, providers, timeline, notifications, lastReport, ent] = await Promise.all([
    supabase.from("domains").select("id, hostname, verification_status, monitoring_enabled, last_scan_at, next_scan_at").eq("org_id", orgId).order("created_at"),
    supabase.from("scan_authorizations").select("domain_id").eq("org_id", orgId).is("revoked_at", null).gt("valid_until", new Date().toISOString()),
    supabase.from("scan_jobs").select("id, kind, status, created_at, finished_at, started_at, error, domain_id, trigger").eq("org_id", orgId).order("created_at", { ascending: false }).limit(10),
    supabase.from("findings").select("id, title, summary, severity, certainty, status, asset_value, category, priority_score, first_seen_at, last_seen_at, resolved_at, verification_state, recommendation").eq("org_id", orgId).order("priority_score", { ascending: false }).limit(2000),
    supabase.from("domain_coverage").select("*").eq("org_id", orgId),
    supabase.from("provider_integrations").select("key, label, status, status_message, last_success_at"),
    supabase.from("timeline_events").select("*").eq("org_id", orgId).order("created_at", { ascending: false }).limit(8),
    supabase.from("notifications").select("id, title, severity, created_at, link, read_at").eq("org_id", orgId).order("created_at", { ascending: false }).limit(5),
    supabase.from("reports").select("created_at").eq("org_id", orgId).order("created_at", { ascending: false }).limit(1).maybeSingle(),
    getEntitlements(supabase, orgId),
  ]);

  const authorized = new Set((auths.data ?? []).map((a) => a.domain_id));
  const allFindings = findings.data ?? [];
  const open = allFindings.filter((f) => (OPEN as readonly string[]).includes(f.status));
  const lastDomainJob = (jobs.data ?? []).find((j) => j.kind === "domain_scan" && ["succeeded", "failed"].includes(j.status));
  const runningJobs = (jobs.data ?? []).filter((j) => ["queued", "running"].includes(j.status));

  const relevantProviders = ["dns", "tls", "http_headers", "subfinder", "ct_logs", "internetdb", "hibp", "hudsonrock", "ransomware_live", "lookalike"];
  const missing = (providers.data ?? []).filter((p) => relevantProviders.includes(p.key) && !["available", "degraded"].includes(p.status));

  const status = computeMonitoringStatus({
    domains: (domains.data ?? []).map((d) => ({ ...d, hasAuthorization: authorized.has(d.id) || isDemo })),
    orgPaused,
    subscriptionActive: ent.active || isDemo,
    lastDomainJobStatus: lastDomainJob?.status ?? null,
    missingIntegrations: isDemo ? [] : missing.map((m) => m.key),
  });

  const sinceReport = lastReport.data?.created_at ?? null;
  const ref = sinceReport ?? new Date(Date.now() - 30 * 86_400_000).toISOString();
  const counts = {
    openCriticalHigh: open.filter((f) => f.severity === "critical" || f.severity === "high").length,
    open: open.length,
    new7d: allFindings.filter((f) => f.first_seen_at >= since7).length,
    resolved30d: allFindings.filter((f) => f.status === "resolved" && f.resolved_at && f.resolved_at >= new Date(Date.now() - 30 * 86_400_000).toISOString()).length,
    newSinceReport: allFindings.filter((f) => f.first_seen_at >= ref).length,
    verifiedSinceReport: allFindings.filter((f) => f.verification_state === "verified_fixed" && f.resolved_at && f.resolved_at >= ref).length,
    bySeverity: (["critical", "high", "medium", "low", "info"] as const).map((s) => ({ severity: s, count: open.filter((f) => f.severity === s).length })),
  };

  // Verlauf offener Befunde (8 Wochen), rekonstruiert aus Erkennungs- und Behebungszeitpunkten
  const trend = Array.from({ length: 8 }, (_, i) => {
    const t = new Date(Date.now() - (7 - i) * 7 * 86_400_000);
    const iso = t.toISOString();
    const openAt = allFindings.filter((f) => f.first_seen_at <= iso && !(f.resolved_at && f.resolved_at <= iso) && f.severity !== "info").length;
    return { label: t.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }), open: openAt };
  });

  const lastSuccessfulScan = (domains.data ?? []).map((d) => d.last_scan_at).filter(Boolean).sort().pop() ?? null;

  return {
    status,
    domains: (domains.data ?? []).map((d) => ({ ...d, authorized: authorized.has(d.id) })),
    attention: open.filter((f) => f.severity !== "info").slice(0, 5),
    counts,
    sinceReport,
    coverage: coverage.data ?? [],
    providers: providers.data ?? [],
    missingProviders: isDemo ? [] : missing,
    timeline: timeline.data ?? [],
    notifications: notifications.data ?? [],
    runningJobs,
    lastSuccessfulScan,
    entitlements: ent,
    trend,
  };
}
