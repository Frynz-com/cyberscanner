import type { Metadata } from "next";
import { TimelineList } from "@/components/dashboard/timeline-list";
import { PageHeader } from "@/components/shared/page-header";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Sicherheits-Timeline" };

export default async function TimelinePage({ searchParams }: { searchParams: Promise<{ month?: string }> }) {
  const ctx = await requireOrg();
  const sp = await searchParams;
  const now = new Date();
  const month = /^\d{4}-\d{2}$/.test(sp.month ?? "") ? sp.month! : `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  const [y, m] = month.split("-").map(Number);
  const start = new Date(Date.UTC(y, m - 1, 1));
  const end = new Date(Date.UTC(y, m, 1));
  const supabase = await createClient();
  const { data: events } = await supabase
    .from("timeline_events")
    .select("id, type, severity, title, body, link, created_at")
    .eq("org_id", ctx.org.id)
    .gte("created_at", start.toISOString())
    .lt("created_at", end.toISOString())
    .order("created_at", { ascending: false })
    .limit(500);
  const list = events ?? [];
  const stats = {
    scans: list.filter((e) => e.type === "scan_completed").length,
    detected: list.filter((e) => e.type === "finding_detected" || e.type === "breach_detected").length,
    verified: list.filter((e) => e.type === "reverify_passed").length,
    shared: list.filter((e) => e.type === "shared_with_partner").length,
    assets: list.filter((e) => e.type === "asset_discovered").length,
  };
  const prev = new Date(Date.UTC(y, m - 2, 1));
  const next = new Date(Date.UTC(y, m, 1));
  const fmt = (d: Date) => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
  const label = start.toLocaleDateString("de-DE", { month: "long", year: "numeric", timeZone: "UTC" });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Sicherheits-Timeline"
        description="Alles, was CyberSafe24 für Sie geprüft, erkannt und bestätigt hat – nachvollziehbar und chronologisch."
        actions={
          <div className="flex items-center gap-2 text-sm">
            <a href={`/app/timeline?month=${fmt(prev)}`} className="rounded-md border px-2.5 py-1 hover:bg-accent">←</a>
            <span className="w-36 text-center font-medium">{label}</span>
            {next <= now && <a href={`/app/timeline?month=${fmt(next)}`} className="rounded-md border px-2.5 py-1 hover:bg-accent">→</a>}
          </div>
        }
      />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {[
          ["Prüfungen", stats.scans],
          ["Neue Befunde", stats.detected],
          ["Bestätigte Behebungen", stats.verified],
          ["An IT übergeben", stats.shared],
          ["Asset-Änderungen", stats.assets],
        ].map(([l, v]) => (
          <div key={l} className="rounded-xl border bg-card p-3">
            <p className="text-xs text-muted-foreground">{l}</p>
            <p className="text-xl font-semibold tabular">{v}</p>
          </div>
        ))}
      </div>
      <div className="rounded-xl border bg-card p-5">
        <TimelineList items={list} />
      </div>
    </div>
  );
}
