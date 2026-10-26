import type { Metadata } from "next";
import Link from "next/link";
import { AlertOctagon, ArrowRight, CircleDashed, Download, Globe, Loader2, Sparkles, UserPlus } from "lucide-react";
import { AutoRefresh } from "@/components/dashboard/auto-refresh";
import { Kpi } from "@/components/dashboard/kpis";
import { ScanButton } from "@/components/dashboard/scan-button";
import { StatusHero } from "@/components/dashboard/status-hero";
import { TimelineList } from "@/components/dashboard/timeline-list";
import { TrendChart } from "@/components/dashboard/trend-chart";
import { CertaintyBadge, SeverityBadge, SeverityDot } from "@/components/shared/badges";
import { Button } from "@/components/ui/button";
import { ADAPTER, PROVIDER_STATUS, relativeTime, SEVERITY } from "@/lib/labels";
import { loadDashboard } from "@/lib/server/dashboard";
import { requireOrg } from "@/lib/server/auth";
import { cn } from "@/lib/utils";

export const metadata: Metadata = { title: "Übersicht" };

function Panel({ title, action, children, className }: { title: string; action?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-xl border bg-card", className)}>
      <div className="flex items-center justify-between border-b px-5 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

export default async function DashboardPage() {
  const ctx = await requireOrg();
  const d = await loadDashboard(ctx.org.id, ctx.org.is_demo, ctx.org.monitoring_paused);
  const scanDomain = d.domains.find((x) => x.verification_status === "verified" && x.authorized);
  const nextScan = d.domains.map((x) => x.next_scan_at).filter(Boolean).sort()[0] ?? null;
  const running = d.runningJobs.length > 0;
  const coverageByAdapter = new Map(d.coverage.map((c) => [c.adapter, c]));

  return (
    <div className="space-y-6">
      <AutoRefresh active={running} />
      <StatusHero
        status={d.status}
        lastScan={d.lastSuccessfulScan}
        nextScan={nextScan}
        actions={
          <div className="flex flex-wrap gap-2">
            {running ? (
              <Button variant="outline" disabled><Loader2 className="animate-spin" /> Prüfung läuft</Button>
            ) : scanDomain && !ctx.org.is_demo ? (
              <ScanButton domainId={scanDomain.id} />
            ) : !scanDomain && !ctx.org.is_demo ? (
              <Button asChild><Link href="/onboarding">Einrichtung fortsetzen <ArrowRight /></Link></Button>
            ) : null}
          </div>
        }
      />

      {d.sinceReport !== undefined && (
        <div className="flex items-center gap-3 rounded-xl border border-brand/20 bg-brand-soft/60 px-4 py-3 text-sm" data-testid="since-report">
          <Sparkles className="size-4 shrink-0 text-brand" />
          <p>
            {d.sinceReport ? "Seit Ihrem letzten Bericht" : "In den letzten 30 Tagen"} wurden <strong className="tabular">{d.counts.newSinceReport}</strong> neue Befunde erkannt und{" "}
            <strong className="tabular">{d.counts.verifiedSinceReport}</strong> Befunde erfolgreich nachgeprüft.
          </p>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi testId="kpi-critical" label="Offene kritische & hohe Risiken" value={d.counts.openCriticalHigh} tone={d.counts.openCriticalHigh > 0 ? "danger" : "default"} hint={`${d.counts.open} offene Befunde insgesamt`} />
        <Kpi testId="kpi-new" label="Neue Befunde (7 Tage)" value={d.counts.new7d} />
        <Kpi testId="kpi-resolved" label="Behoben (30 Tage)" value={d.counts.resolved30d} tone={d.counts.resolved30d > 0 ? "ok" : "default"} />
        <Kpi testId="kpi-lastscan" label="Zuletzt geprüft" value={<span className="text-lg">{relativeTime(d.lastSuccessfulScan)}</span>} hint={d.domains.filter((x) => x.verification_status === "verified").map((x) => x.hostname).join(", ") || "Keine verifizierte Domain"} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel
          title="Ihre Aufmerksamkeit ist gefragt"
          className="lg:col-span-2"
          action={<Link href="/app/findings" className="text-xs text-muted-foreground hover:text-foreground">Alle Befunde →</Link>}
        >
          {d.attention.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-8 text-center">
              <CircleDashed className="size-6 text-muted-foreground" />
              <p className="text-sm font-medium">Keine offenen Maßnahmen</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                {d.lastSuccessfulScan ? "Bei der letzten Prüfung wurden keine offenen Risiken festgestellt, die Ihr Handeln erfordern." : "Nach der ersten Prüfung erscheinen hier priorisierte Maßnahmen."}
              </p>
            </div>
          ) : (
            <ul className="-my-2 divide-y">
              {d.attention.map((f) => (
                <li key={f.id}>
                  <Link href={`/app/findings/${f.id}`} className="group flex items-start gap-3 py-3">
                    <SeverityDot severity={f.severity} className="mt-1.5" />
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-sm font-medium group-hover:underline">{f.title}</p>
                        <SeverityBadge severity={f.severity} />
                        {f.certainty !== "confirmed" && <CertaintyBadge certainty={f.certainty} />}
                      </div>
                      <p className="line-clamp-1 text-sm text-muted-foreground">{f.recommendation}</p>
                      <p className="text-xs text-muted-foreground">{f.asset_value} · erkannt {relativeTime(f.first_seen_at)}</p>
                    </div>
                    <ArrowRight className="mt-1 size-4 shrink-0 text-muted-foreground opacity-0 transition group-hover:opacity-100" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Entwicklung">
          <TrendChart data={d.trend} />
          <div className="mt-4 space-y-1.5">
            {d.counts.bySeverity.filter((s) => s.severity !== "info").map((s) => (
              <div key={s.severity} className="flex items-center gap-2 text-sm">
                <SeverityDot severity={s.severity} />
                <span className="flex-1 text-muted-foreground">{SEVERITY[s.severity].label}</span>
                <span className="font-medium tabular">{s.count}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel title="Sicherheits-Timeline" className="lg:col-span-2" action={<Link href="/app/timeline" className="text-xs text-muted-foreground hover:text-foreground">Vollständige Timeline →</Link>}>
          <TimelineList items={d.timeline} />
        </Panel>

        <div className="space-y-6">
          <Panel title="Monitoring-Abdeckung">
            <ul className="space-y-2.5" data-testid="coverage">
              {Object.entries(ADAPTER).map(([key, a]) => {
                const run = coverageByAdapter.get(key);
                const provider = d.providers.find((p) => p.key === key);
                const ps = provider?.status ?? "unknown";
                const ran = run && ["ok", "partial"].includes(run.status ?? "");
                const label = ctx.org.is_demo ? "Demo" : ran ? (run.status === "partial" ? "Teilweise geprüft" : "Geprüft") : run?.status === "not_authorized" ? "Nicht freigegeben" : run?.status === "error" ? "Fehler" : run?.status === "unavailable" ? "Nicht verfügbar" : !run && ps === "available" ? "Noch nicht gelaufen" : PROVIDER_STATUS[ps]?.label ?? "Unbekannt";
                const tone = ran ? "bg-ok" : run?.status === "error" ? "bg-sev-critical" : !run && ps === "available" ? "bg-sev-low" : "bg-sev-info";
                return (
                  <li key={key} className="flex items-start gap-2.5 text-sm" title={run?.message ?? provider?.status_message ?? a.description}>
                    <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", tone)} />
                    <div className="min-w-0 flex-1">
                      <div className="flex justify-between gap-2">
                        <span className="truncate">{a.label}</span>
                        <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
                      </div>
                      {!ran && !ctx.org.is_demo && (provider?.status_message || run?.message) && <p className="line-clamp-2 text-xs text-muted-foreground">{run?.message ?? provider?.status_message}</p>}
                    </div>
                  </li>
                );
              })}
            </ul>
          </Panel>

          <Panel title="Schnellzugriff">
            <div className="grid grid-cols-2 gap-2">
              {[
                { href: "/app/domains", label: "Domain hinzufügen", icon: Globe },
                { href: "/app/partners", label: "IT-Dienstleister einladen", icon: UserPlus },
                { href: "/app/reports", label: "Bericht herunterladen", icon: Download },
                { href: "/app/emergency", label: "Notfall melden", icon: AlertOctagon },
              ].map((q) => (
                <Link key={q.href} href={q.href} className="flex flex-col gap-2 rounded-lg border p-3 text-sm transition hover:border-foreground/20 hover:bg-accent">
                  <q.icon className="size-4 text-muted-foreground" />
                  {q.label}
                </Link>
              ))}
            </div>
          </Panel>

          {d.notifications.length > 0 && (
            <Panel title="Benachrichtigungen" action={<Link href="/app/notifications" className="text-xs text-muted-foreground hover:text-foreground">Alle →</Link>}>
              <ul className="space-y-3">
                {d.notifications.map((n) => (
                  <li key={n.id} className="flex gap-2.5 text-sm">
                    <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", n.read_at ? "bg-transparent" : "bg-brand")} />
                    <div className="min-w-0">
                      {n.link ? <Link href={n.link} className="line-clamp-2 hover:underline">{n.title}</Link> : <p className="line-clamp-2">{n.title}</p>}
                      <p className="text-xs text-muted-foreground">{relativeTime(n.created_at)}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
