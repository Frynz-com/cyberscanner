import type { Metadata } from "next";
import Link from "next/link";
import { ChevronRight, SearchX } from "lucide-react";
import { CertaintyBadge, SeverityBadge, StatusBadge } from "@/components/shared/badges";
import { PageHeader } from "@/components/shared/page-header";
import { CATEGORY, relativeTime } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";
import { cn } from "@/lib/utils";

export const metadata: Metadata = { title: "Befunde" };

const FILTERS = [
  { key: "open", label: "Offen", statuses: ["new", "investigating", "action_required"] },
  { key: "resolved", label: "Behoben", statuses: ["resolved"] },
  { key: "accepted", label: "Akzeptiert / Fehlalarm", statuses: ["accepted_risk", "false_positive"] },
  { key: "all", label: "Alle", statuses: null },
] as const;

export default async function FindingsPage({ searchParams }: { searchParams: Promise<{ filter?: string; category?: string; severity?: string }> }) {
  const ctx = await requireOrg();
  const sp = await searchParams;
  const filter = FILTERS.find((f) => f.key === sp.filter) ?? FILTERS[0];
  const supabase = await createClient();
  let q = supabase
    .from("findings")
    .select("id, title, severity, certainty, status, asset_value, category, priority_score, first_seen_at, last_seen_at, verification_state")
    .eq("org_id", ctx.org.id)
    .order("priority_score", { ascending: false })
    .order("last_seen_at", { ascending: false })
    .limit(500);
  if (filter.statuses) q = q.in("status", filter.statuses as unknown as string[] as never);
  if (sp.category && CATEGORY[sp.category]) q = q.eq("category", sp.category);
  if (sp.severity && ["critical", "high", "medium", "low", "info"].includes(sp.severity)) q = q.eq("severity", sp.severity as never);
  const { data: findings } = await q;
  const categories = [...new Set((findings ?? []).map((f) => f.category))];

  const href = (patch: Record<string, string | undefined>) => {
    const p = new URLSearchParams();
    const merged = { filter: filter.key, category: sp.category, severity: sp.severity, ...patch };
    Object.entries(merged).forEach(([k, v]) => v && p.set(k, v));
    return `/app/findings?${p.toString()}`;
  };

  return (
    <div className="space-y-6">
      <PageHeader title="Befunde" description="Alle Ergebnisse, priorisiert nach nachvollziehbaren technischen Kriterien." />
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex rounded-lg border bg-card p-0.5">
          {FILTERS.map((f) => (
            <Link key={f.key} href={href({ filter: f.key })} className={cn("rounded-md px-3 py-1 text-sm", f.key === filter.key ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")}>
              {f.label}
            </Link>
          ))}
        </div>
        {categories.length > 1 && (
          <div className="flex flex-wrap gap-1.5">
            <Link href={href({ category: undefined })} className={cn("rounded-full border px-2.5 py-0.5 text-xs", !sp.category ? "border-foreground/30 bg-accent" : "text-muted-foreground")}>Alle Kategorien</Link>
            {categories.map((c) => (
              <Link key={c} href={href({ category: c })} className={cn("rounded-full border px-2.5 py-0.5 text-xs", sp.category === c ? "border-foreground/30 bg-accent" : "text-muted-foreground")}>{CATEGORY[c] ?? c}</Link>
            ))}
          </div>
        )}
      </div>

      {(findings ?? []).length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-16 text-center">
          <SearchX className="size-6 text-muted-foreground" />
          <p className="font-medium">Keine Befunde in dieser Ansicht</p>
          <p className="text-sm text-muted-foreground">Ändern Sie den Filter oder warten Sie auf die nächste Prüfung.</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card">
          <ul className="divide-y">
            {findings!.map((f) => (
              <li key={f.id}>
                <Link href={`/app/findings/${f.id}`} className="group flex items-center gap-4 px-4 py-3.5 hover:bg-accent/50 sm:px-5">
                  <div className="w-10 shrink-0 text-center">
                    <span className="text-xs font-semibold text-muted-foreground tabular" title="Prioritätswert (0–100)">{f.priority_score}</span>
                  </div>
                  <div className="min-w-0 flex-1 space-y-1">
                    <p className="truncate text-sm font-medium">{f.title}</p>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span className="font-mono">{f.asset_value}</span>
                      <span>{CATEGORY[f.category] ?? f.category}</span>
                      <span>zuletzt gesehen {relativeTime(f.last_seen_at)}</span>
                    </div>
                  </div>
                  <div className="hidden flex-wrap items-center justify-end gap-1.5 sm:flex">
                    {f.certainty !== "confirmed" && <CertaintyBadge certainty={f.certainty} />}
                    <SeverityBadge severity={f.severity} />
                    <StatusBadge status={f.status} />
                  </div>
                  <ChevronRight className="size-4 text-muted-foreground" />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
