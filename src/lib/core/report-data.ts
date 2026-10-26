import type { Db } from "./db";

export interface ReportFinding {
  id: string;
  title: string;
  asset: string;
  severity: string;
  certainty: string;
  status: string;
  verificationState: string | null;
  category: string;
  source: string;
  ruleId: string;
  summary: string;
  recommendation: string;
  technicalDetails: string;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  priority: number;
}

export interface ReportSnapshot {
  version: 1;
  isDemo: boolean;
  organization: { name: string };
  period: { start: string; end: string };
  generatedAt: string;
  domains: Array<{ hostname: string; status: string; lastScanAt: string | null; assetCount: number }>;
  coverage: Array<{ adapter: string; status: string; lastRun: string | null; message: string | null }>;
  scansInPeriod: number;
  counts: {
    openBySeverity: Record<string, number>;
    open: number;
    newInPeriod: number;
    resolvedInPeriod: number;
    verifiedInPeriod: number;
    acceptedRisk: number;
    previousPeriod: { newInPeriod: number; resolvedInPeriod: number };
  };
  topOpen: ReportFinding[];
  newFindings: ReportFinding[];
  resolvedFindings: ReportFinding[];
  openActions: Array<{ findingTitle: string; status: string; partner: string | null; createdAt: string }>;
}

const ADAPTER_LABELS: Record<string, string> = {
  dns: "DNS- und E-Mail-Sicherheit",
  tls: "TLS-Zertifikate",
  http_headers: "Webserver-Konfiguration",
  subfinder: "Subdomain-Erkennung",
  ct_logs: "Certificate Transparency",
  internetdb: "Shodan InternetDB",
  hibp: "Datenleck-Überwachung (HIBP)",
  nuclei: "Autorisierte Schwachstellenprüfung",
};
export const adapterLabel = (k: string) => ADAPTER_LABELS[k] ?? k;

function toReportFinding(f: Record<string, unknown>): ReportFinding {
  return {
    id: String(f.id),
    title: String(f.title),
    asset: String(f.asset_value),
    severity: String(f.severity),
    certainty: String(f.certainty),
    status: String(f.status),
    verificationState: (f.verification_state as string | null) ?? null,
    category: String(f.category),
    source: String(f.source),
    ruleId: String(f.rule_id),
    summary: String(f.summary),
    recommendation: String(f.recommendation),
    technicalDetails: String(f.technical_details).slice(0, 1200),
    firstSeen: String(f.first_seen_at),
    lastSeen: String(f.last_seen_at),
    resolvedAt: (f.resolved_at as string | null) ?? null,
    priority: Number(f.priority_score),
  };
}

/** Erstellt einen Berichts-Snapshot ausschließlich aus gespeicherten, echten Daten. */
export async function buildReportSnapshot(db: Db, orgId: string, start: Date, end: Date): Promise<ReportSnapshot> {
  const s = start.toISOString();
  const e = end.toISOString();
  const prevStart = new Date(start.getTime() - (end.getTime() - start.getTime())).toISOString();

  const [{ data: org }, { data: domains }, { data: findings }, { data: results }, { count: scans }, { data: actions }, { data: assets }] = await Promise.all([
    db.from("organizations").select("name, is_demo").eq("id", orgId).single(),
    db.from("domains").select("id, hostname, verification_status, last_scan_at").eq("org_id", orgId),
    db.from("findings").select("*").eq("org_id", orgId).order("priority_score", { ascending: false }).limit(2000),
    db.from("scan_results").select("adapter, status, finished_at, message").eq("org_id", orgId).lte("finished_at", e).order("finished_at", { ascending: false }).limit(500),
    db.from("scan_jobs").select("id", { count: "exact", head: true }).eq("org_id", orgId).eq("status", "succeeded").gte("finished_at", s).lte("finished_at", e),
    db.from("actions").select("status, created_at, findings(title), service_provider_invites(company_name, email)").eq("org_id", orgId).in("status", ["open", "in_progress", "fixed_pending_verification", "still_open"]),
    db.from("assets").select("domain_id").eq("org_id", orgId).eq("is_active", true),
  ]);
  const all = (findings ?? []) as unknown as Array<Record<string, unknown>>;
  const open = all.filter((f) => ["new", "investigating", "action_required"].includes(String(f.status)));
  const inRange = (v: unknown, a: string, b: string) => typeof v === "string" && v >= a && v <= b;

  const openBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  open.forEach((f) => (openBySeverity[String(f.severity)] += 1));

  const coverage = new Map<string, { adapter: string; status: string; lastRun: string | null; message: string | null }>();
  for (const r of results ?? []) {
    if (!coverage.has(r.adapter)) coverage.set(r.adapter, { adapter: adapterLabel(r.adapter), status: r.status, lastRun: r.finished_at, message: r.message });
  }

  const newFindings = all.filter((f) => inRange(f.first_seen_at, s, e));
  const resolved = all.filter((f) => f.status === "resolved" && inRange(f.resolved_at, s, e));

  return {
    version: 1,
    isDemo: Boolean(org?.is_demo),
    organization: { name: org?.name ?? "" },
    period: { start: s, end: e },
    generatedAt: new Date().toISOString(),
    domains: (domains ?? []).map((d) => ({
      hostname: d.hostname,
      status: d.verification_status,
      lastScanAt: d.last_scan_at,
      assetCount: (assets ?? []).filter((a) => a.domain_id === d.id).length,
    })),
    coverage: [...coverage.values()],
    scansInPeriod: scans ?? 0,
    counts: {
      openBySeverity,
      open: open.length,
      newInPeriod: newFindings.length,
      resolvedInPeriod: resolved.length,
      verifiedInPeriod: resolved.filter((f) => f.verification_state === "verified_fixed").length,
      acceptedRisk: all.filter((f) => f.status === "accepted_risk").length,
      previousPeriod: {
        newInPeriod: all.filter((f) => inRange(f.first_seen_at, prevStart, s)).length,
        resolvedInPeriod: all.filter((f) => f.status === "resolved" && inRange(f.resolved_at, prevStart, s)).length,
      },
    },
    topOpen: open.slice(0, 10).map(toReportFinding),
    newFindings: newFindings.slice(0, 50).map(toReportFinding),
    resolvedFindings: resolved.slice(0, 50).map(toReportFinding),
    openActions: (actions ?? []).map((a) => {
      const inv = a.service_provider_invites as unknown as { company_name: string | null; email: string } | null;
      return {
        findingTitle: (a.findings as unknown as { title: string } | null)?.title ?? "",
        status: a.status,
        partner: inv ? inv.company_name || inv.email : null,
        createdAt: a.created_at,
      };
    }),
  };
}
