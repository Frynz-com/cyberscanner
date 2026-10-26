import type { Metadata } from "next";
import Link from "next/link";
import { Logo } from "@/components/brand/logo";
import { formatDate, PROVIDER_STATUS } from "@/lib/labels";
import { requirePlatformAdmin } from "@/lib/server/auth";
import { cn } from "@/lib/utils";
import { PauseOrg, RetryJob } from "./admin-client";

export const metadata: Metadata = { title: "Admin", robots: { index: false } };
const TABS = [["orgs", "Organisationen"], ["jobs", "Jobs"], ["providers", "Scanner & Provider"], ["incidents", "Incidents"], ["logs", "Systemlogs"]] as const;

export default async function AdminPage({ searchParams }: { searchParams: Promise<{ tab?: string }> }) {
  const { admin } = await requirePlatformAdmin();
  const tab = (await searchParams).tab ?? "orgs";
  const card = "rounded-xl border bg-card overflow-x-auto";
  const th = "px-3 py-2 text-left text-xs font-medium text-muted-foreground";
  const td = "px-3 py-2 text-sm";

  let content: React.ReactNode = null;
  if (tab === "orgs") {
    // Nur aggregierte Kennzahlen – keine Befundinhalte
    const [{ data: orgs }, { data: subs }, { data: domains }, { data: findings }] = await Promise.all([
      admin.from("organizations").select("id, name, is_demo, monitoring_paused, created_at, deleted_at").order("created_at", { ascending: false }).limit(500),
      admin.from("subscriptions").select("org_id, plan_key, status"),
      admin.from("domains").select("org_id, verification_status, last_scan_at"),
      admin.from("findings").select("org_id, severity").in("status", ["new", "investigating", "action_required"]).limit(50000),
    ]);
    content = (
      <table className="w-full"><thead className="border-b"><tr><th className={th}>Organisation</th><th className={th}>Tarif</th><th className={th}>Domains (verifiziert)</th><th className={th}>Letzte Prüfung</th><th className={th}>Offene Befunde</th><th className={th}>Angelegt</th><th className={th} /></tr></thead>
        <tbody className="divide-y">{(orgs ?? []).map((o) => {
          const s = subs?.find((x) => x.org_id === o.id);
          const ds = (domains ?? []).filter((d) => d.org_id === o.id);
          const last = ds.map((d) => d.last_scan_at).filter(Boolean).sort().pop() ?? null;
          return (
            <tr key={o.id} className={o.deleted_at ? "opacity-50" : ""}>
              <td className={td}>{o.name}{o.is_demo && " · DEMO"}{o.deleted_at && " · Löschung angefordert"}</td>
              <td className={td}>{s ? `${s.plan_key} (${s.status})` : "–"}</td>
              <td className={td}>{ds.length} ({ds.filter((d) => d.verification_status === "verified").length})</td>
              <td className={td}>{formatDate(last, true)}</td>
              <td className={td}>{(findings ?? []).filter((f) => f.org_id === o.id).length}</td>
              <td className={td}>{formatDate(o.created_at)}</td>
              <td className={td}>{!o.is_demo && <PauseOrg id={o.id} paused={o.monitoring_paused} />}</td>
            </tr>
          );
        })}</tbody></table>
    );
  } else if (tab === "jobs") {
    const [{ data: failed }, { count: queued }, { count: running }] = await Promise.all([
      admin.from("scan_jobs").select("id, kind, trigger, error, attempts, finished_at, org_id, organizations(name)").eq("status", "failed").order("finished_at", { ascending: false }).limit(100),
      admin.from("scan_jobs").select("id", { count: "exact", head: true }).eq("status", "queued"),
      admin.from("scan_jobs").select("id", { count: "exact", head: true }).eq("status", "running"),
    ]);
    content = (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">Warteschlange: {queued ?? 0} · Laufend: {running ?? 0}</p>
        <div className={card}><table className="w-full"><thead className="border-b"><tr><th className={th}>Zeit</th><th className={th}>Typ</th><th className={th}>Organisation</th><th className={th}>Fehler</th><th className={th} /></tr></thead>
          <tbody className="divide-y">{(failed ?? []).map((j) => (
            <tr key={j.id}><td className={td}>{formatDate(j.finished_at, true)}</td><td className={td}>{j.kind} ({j.trigger})</td><td className={td}>{(j.organizations as unknown as { name: string } | null)?.name ?? "öffentlich"}</td><td className={cn(td, "max-w-md truncate text-muted-foreground")}>{j.error}</td><td className={td}><RetryJob id={j.id} /></td></tr>
          ))}</tbody></table></div>
      </div>
    );
  } else if (tab === "providers") {
    const { data } = await admin.from("provider_integrations").select("*").order("kind");
    content = (
      <table className="w-full"><thead className="border-b"><tr><th className={th}>Integration</th><th className={th}>Status</th><th className={th}>Hinweis</th><th className={th}>Letzter Erfolg</th><th className={th}>Fehler in Folge</th></tr></thead>
        <tbody className="divide-y">{(data ?? []).map((p) => (
          <tr key={p.key}><td className={td}>{p.label}</td><td className={cn(td, PROVIDER_STATUS[p.status]?.tone)}>{PROVIDER_STATUS[p.status]?.label}</td><td className={cn(td, "text-muted-foreground")}>{p.status_message}</td><td className={td}>{formatDate(p.last_success_at, true)}</td><td className={td}>{p.consecutive_failures}</td></tr>
        ))}</tbody></table>
    );
  } else if (tab === "incidents") {
    const { data } = await admin.from("incidents").select("id, type, priority, status, created_at, is_demo, organizations(name)").order("created_at", { ascending: false }).limit(100);
    content = (
      <table className="w-full"><thead className="border-b"><tr><th className={th}>Zeit</th><th className={th}>Organisation</th><th className={th}>Typ</th><th className={th}>Priorität</th><th className={th}>Status</th></tr></thead>
        <tbody className="divide-y">{(data ?? []).map((i) => (
          <tr key={i.id}><td className={td}>{formatDate(i.created_at, true)}</td><td className={td}>{(i.organizations as unknown as { name: string } | null)?.name}{i.is_demo && " · DEMO"}</td><td className={td}>{i.type}</td><td className={td}>{i.priority}</td><td className={td}>{i.status}</td></tr>
        ))}</tbody></table>
    );
  } else {
    const { data } = await admin.from("audit_logs").select("id, action, actor_type, target_type, created_at, organizations(name)").order("created_at", { ascending: false }).limit(150);
    content = (
      <table className="w-full"><thead className="border-b"><tr><th className={th}>Zeit</th><th className={th}>Aktion</th><th className={th}>Akteur</th><th className={th}>Organisation</th></tr></thead>
        <tbody className="divide-y">{(data ?? []).map((a) => (
          <tr key={a.id}><td className={td}>{formatDate(a.created_at, true)}</td><td className={cn(td, "font-mono text-xs")}>{a.action}</td><td className={td}>{a.actor_type}</td><td className={td}>{(a.organizations as unknown as { name: string } | null)?.name ?? "–"}</td></tr>
        ))}</tbody></table>
    );
  }

  return (
    <div className="min-h-dvh">
      <header className="flex items-center justify-between border-b px-6 py-4"><Logo /><span className="rounded-full bg-primary px-2.5 py-0.5 text-xs text-primary-foreground">Intern · CyberSafe24</span></header>
      <main className="mx-auto max-w-7xl space-y-6 px-6 py-8">
        <h1 className="text-2xl font-semibold">Administration</h1>
        <nav className="flex flex-wrap gap-1">{TABS.map(([k, l]) => <Link key={k} href={`/admin?tab=${k}`} className={cn("rounded-md px-3 py-1.5 text-sm", tab === k ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent")}>{l}</Link>)}</nav>
        <div className={tab === "jobs" ? "" : card}>{content}</div>
        <p className="text-xs text-muted-foreground">Admin-Ansichten zeigen bewusst nur Metadaten und Kennzahlen, keine Befundinhalte oder Datenleck-Konten. Alle Admin-Aktionen werden protokolliert.</p>
      </main>
    </div>
  );
}
