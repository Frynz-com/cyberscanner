import { validateSubdomains } from "../../src/lib/core/discovery";
import { isWithinScope } from "../../src/lib/core/domain";
import { getEntitlements } from "../../src/lib/core/entitlements";
import { addTimeline, notify } from "../../src/lib/core/events";
import { isPublicIp } from "../../src/lib/core/net/ip";
import { DohResolver, resolveAddresses, type DnsResolver } from "../../src/lib/core/net/dns";
import { mapLimit, runAdapter, type AdapterRun } from "../../src/lib/core/scanners/runner";
import { assessmentAdapters, discoveryAdapters } from "../../src/lib/core/scanners/registry";
import type { ScanContext, ScannerAdapter, ScanScope } from "../../src/lib/core/scanners/types";
import { NonRetryableError, type Db, type WorkerDeps } from "../deps";
import { persistFindings, storeScanResults } from "../persist";
import { recordProviderOutcome } from "../providers";
import type { Tables } from "../../src/lib/database.types";

export type ScanJob = Tables<"scan_jobs">;

interface LoadedScope {
  domain: Tables<"domains">;
  scopes: ScanScope[];
  includeSubdomains: boolean;
}

/** Lädt Domain + gültige Autorisierung und erzwingt alle Vorbedingungen für einen Kundenscan. */
export async function loadScanScope(db: Db, orgId: string, domainId: string): Promise<LoadedScope> {
  const { data: domain } = await db.from("domains").select("*").eq("id", domainId).eq("org_id", orgId).maybeSingle();
  if (!domain) throw new NonRetryableError("Domain nicht gefunden");
  if (domain.is_demo) throw new NonRetryableError("Demo-Domains werden nie gescannt");
  if (domain.verification_status !== "verified") throw new NonRetryableError("Domain ist nicht (mehr) verifiziert");
  const { data: org } = await db.from("organizations").select("deleted_at, is_demo").eq("id", orgId).single();
  if (!org || org.deleted_at || org.is_demo) throw new NonRetryableError("Organisation nicht aktiv");
  const { data: auth } = await db
    .from("scan_authorizations")
    .select("scopes, include_subdomains, valid_until")
    .eq("domain_id", domainId)
    .eq("org_id", orgId)
    .is("revoked_at", null)
    .gt("valid_until", new Date().toISOString())
    .order("granted_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!auth) throw new NonRetryableError("Keine gültige Scan-Autorisierung vorhanden");
  return { domain, scopes: auth.scopes as ScanScope[], includeSubdomains: auth.include_subdomains };
}

export async function buildContext(
  deps: WorkerDeps,
  p: { orgId: string; scope: LoadedScope; signal: AbortSignal; resolver?: DnsResolver; hosts: string[]; ips: string[]; vulnScanHosts: string[] },
): Promise<ScanContext> {
  const ent = await getEntitlements(deps.db, p.orgId);
  if (!ent.active) throw new NonRetryableError("Kein aktives Abonnement – Überwachung pausiert");
  const kev = await loadKev(deps.db);
  return {
    mode: "customer",
    orgId: p.orgId,
    domainId: p.scope.domain.id,
    apex: p.scope.domain.hostname,
    hosts: p.hosts,
    ips: p.ips,
    vulnScanHosts: p.vulnScanHosts,
    authorization: { domainVerified: true, scopes: p.scope.scopes, includeSubdomains: p.scope.includeSubdomains },
    resolver: p.resolver ?? new DohResolver(),
    signal: p.signal,
    log: deps.log,
    limits: {
      maxHosts: Math.max(2, ent.limits.max_subdomains_checked + 2),
      breachMonitoring: ent.limits.breach_monitoring,
      vulnScan: ent.limits.vuln_scan,
    },
    isKnownExploited: (cve) => kev.has(cve),
  };
}

let kevCache: { at: number; set: Set<string> } | null = null;
async function loadKev(db: Db): Promise<Set<string>> {
  if (kevCache && Date.now() - kevCache.at < 3600_000) return kevCache.set;
  const set = new Set<string>();
  for (let from = 0; ; from += 1000) {
    const { data } = await db.from("cve_kev").select("cve_id").range(from, from + 999);
    if (!data || data.length === 0) break;
    data.forEach((r) => set.add(r.cve_id));
    if (data.length < 1000) break;
  }
  kevCache = { at: Date.now(), set };
  return set;
}

async function upsertAssets(
  db: Db,
  orgId: string,
  domainId: string,
  items: Array<{ kind: "domain" | "subdomain" | "ip"; value: string; source: string; metadata?: Record<string, unknown> }>,
): Promise<string[]> {
  if (items.length === 0) return [];
  const map = new Map<string, { sources: string[] }>();
  const values = [...new Set(items.map((i) => i.value))];
  for (let i = 0; i < values.length; i += 200) {
    const { data: existing, error } = await db.from("assets").select("kind, value, sources").eq("org_id", orgId).in("value", values.slice(i, i + 200));
    if (error) throw new Error(`assets laden: ${error.message}`);
    for (const a of existing ?? []) map.set(`${a.kind}|${a.value}`, a);
  }
  const now = new Date().toISOString();
  const created: string[] = [];
  const merged = new Map<string, { kind: string; value: string; sources: Set<string>; metadata?: Record<string, unknown> }>();
  for (const it of items) {
    const k = `${it.kind}|${it.value}`;
    const m = merged.get(k) ?? { kind: it.kind, value: it.value, sources: new Set<string>(map.get(k)?.sources ?? []), metadata: it.metadata };
    m.sources.add(it.source);
    merged.set(k, m);
  }
  const rows = [...merged.entries()].map(([k, m]) => {
    if (!map.has(k)) created.push(m.value);
    return {
      org_id: orgId,
      domain_id: domainId,
      kind: m.kind,
      value: m.value,
      sources: [...m.sources].slice(0, 20),
      last_seen_at: now,
      is_active: true,
      ...(m.metadata ? { metadata: JSON.parse(JSON.stringify(m.metadata)) } : {}),
    };
  });
  for (let i = 0; i < rows.length; i += 200) {
    const { error } = await db.from("assets").upsert(rows.slice(i, i + 200), { onConflict: "org_id,kind,value" });
    if (error) throw new Error(`assets upsert: ${error.message}`);
  }
  return created;
}

async function runAll(adapters: ScannerAdapter[], ctx: ScanContext, deps: WorkerDeps): Promise<AdapterRun[]> {
  const runs: AdapterRun[] = [];
  for (const adapter of adapters) {
    if (ctx.signal.aborted) break;
    const run = await runAdapter(adapter, ctx);
    deps.log.info("adapter finished", { adapter: adapter.key, status: run.output.status, observations: run.output.observations.length, ms: run.finishedAt.getTime() - run.startedAt.getTime() });
    runs.push(run);
    await recordProviderOutcome(deps.db, adapter.key, run.output.status, run.output.message);
  }
  return runs;
}

export async function runDomainScan(job: ScanJob, deps: WorkerDeps, signal: AbortSignal) {
  const { db } = deps;
  if (!job.org_id || !job.domain_id) throw new NonRetryableError("Job ohne Organisation/Domain");
  const orgId = job.org_id;
  const scope = await loadScanScope(db, orgId, job.domain_id);
  const apex = scope.domain.hostname;
  const resolver = new DohResolver();

  // Phase 1: passive Asset-Erkennung (nur mit Subdomain-Freigabe)
  const discoveryCtx = await buildContext(deps, { orgId, scope, signal, resolver, hosts: [apex], ips: [], vulnScanHosts: [] });
  const discoveryRuns = scope.includeSubdomains ? await runAll(discoveryAdapters(deps.env), discoveryCtx, deps) : [];
  const discovered = discoveryRuns.flatMap((r) => r.output.discoveredAssets).filter((a) => isWithinScope(a.value, apex));
  const validated = await validateSubdomains(resolver, apex, discovered, signal);
  deps.log.info("discovery validated", { candidates: validated.candidates, active: validated.hosts.length, wildcard: validated.wildcard, truncated: validated.truncated });
  const newAssets = await upsertAssets(db, orgId, scope.domain.id, [
    { kind: "domain", value: apex, source: "customer" },
    ...validated.hosts.flatMap((h) => h.sources.map((source) => ({ kind: "subdomain" as const, value: h.host, source, metadata: h.dangling ? { dangling: true } : undefined }))),
  ]);
  const newSubdomains = newAssets.filter((v) => v !== apex);
  const isFirstScan = !scope.domain.last_scan_at;
  if (newSubdomains.length > 0) {
    await addTimeline(db, {
      orgId,
      type: "asset_discovered",
      title: isFirstScan ? `${newSubdomains.length} Subdomains im Bestand erfasst` : `${newSubdomains.length} neue Subdomain(s) entdeckt`,
      body: newSubdomains.slice(0, 8).join(", ") + (newSubdomains.length > 8 ? " …" : ""),
      link: "/app/assets",
      domainId: scope.domain.id,
      data: { hosts: newSubdomains.slice(0, 100) },
    });
    if (!isFirstScan) {
      await notify(db, {
        orgId,
        type: "asset",
        severity: "info",
        title: `Neue Subdomain(s) für ${apex}`,
        body: `Seit der letzten Prüfung wurden neue öffentlich sichtbare Subdomains erkannt: ${newSubdomains.slice(0, 10).join(", ")}. Bitte prüfen Sie, ob diese bekannt und gewollt sind.`,
        link: "/app/assets",
        dedupeKey: `assets:${scope.domain.id}:${new Date().toISOString().slice(0, 10)}`,
      });
    }
  }

  // Host-Auswahl: Hauptdomain, www und bekannte aktive Subdomains (Tarif-Limit)
  const { data: subAssets } = await db
    .from("assets")
    .select("value, last_seen_at, vuln_scan_approved, kind")
    .eq("org_id", orgId)
    .eq("domain_id", scope.domain.id)
    .eq("is_active", true)
    .in("kind", ["domain", "subdomain"])
    .order("last_seen_at", { ascending: false });
  const ent = discoveryCtx.limits;
  const subs = (subAssets ?? []).map((a) => a.value).filter((v) => v !== apex && v !== `www.${apex}`);
  const hosts = [apex, `www.${apex}`, ...(scope.includeSubdomains ? subs.slice(0, ent.maxHosts - 2) : [])];

  // Öffentliche IPs der Hosts (für passive Intel); private Adressen werden nie verwendet
  const ipSet = new Map<string, string[]>();
  await mapLimit(hosts, 6, async (h) => {
    const r = await resolveAddresses(resolver, h).catch(() => null);
    for (const ip of [...(r?.v4 ?? []), ...(r?.v6 ?? [])]) {
      if (!isPublicIp(ip)) continue;
      ipSet.set(ip, [...(ipSet.get(ip) ?? []), h]);
    }
  });
  await upsertAssets(db, orgId, scope.domain.id, [...ipSet.entries()].slice(0, 200).map(([ip, hs]) => ({ kind: "ip" as const, value: ip, source: "dns", metadata: { hostnames: hs.slice(0, 10) } })));

  const vulnScanHosts = (subAssets ?? []).filter((a) => a.vuln_scan_approved && hosts.includes(a.value)).map((a) => a.value);
  const ctx = await buildContext(deps, { orgId, scope, signal, resolver, hosts, ips: [...ipSet.keys()], vulnScanHosts });
  const assessRuns = await runAll(assessmentAdapters(deps.env), ctx, deps);

  const runs = [...discoveryRuns, ...assessRuns];
  await storeScanResults(db, job.id, orgId, scope.domain.id, runs);
  if (signal.aborted) return { cancelled: true };

  const summary = await persistFindings(db, { orgId, domainId: scope.domain.id, apex, jobId: job.id, runs });
  const next = new Date(Date.now() + scope.domain.scan_interval_hours * 3600_000).toISOString();
  await db.from("domains").update({ last_scan_at: new Date().toISOString(), next_scan_at: next }).eq("id", scope.domain.id);

  const failed = runs.filter((r) => r.output.status === "error");
  await addTimeline(db, {
    orgId,
    type: "scan_completed",
    severity: summary.created > 0 ? "medium" : "success",
    title: `Prüfung von ${apex} abgeschlossen`,
    body: [
      `${hosts.length} Hosts geprüft`,
      summary.created ? `${summary.created} neue Befunde` : "keine neuen Befunde",
      summary.verifiedFixed ? `${summary.verifiedFixed} Behebung(en) bestätigt` : null,
      failed.length ? `${failed.length} Prüfmodul(e) mit Fehler` : null,
    ]
      .filter(Boolean)
      .join(" · "),
    link: "/app",
    domainId: scope.domain.id,
    data: { jobId: job.id, ...summary },
  });
  return { hosts: hosts.length, ips: ipSet.size, newAssets: newSubdomains.length, ...summary, adapterErrors: failed.map((f) => f.adapter) };
}
