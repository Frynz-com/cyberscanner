import type { Metadata } from "next";
import { Download, FileText } from "lucide-react";
import { CreateReportButton } from "@/components/app/report-button";
import { PageHeader } from "@/components/shared/page-header";
import type { ReportSnapshot } from "@/lib/core/report-data";
import { formatDate } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Berichte" };

export default async function ReportsPage() {
  const ctx = await requireOrg();
  const supabase = await createClient();
  const { data: reports } = await supabase.from("reports").select("id, kind, period_start, period_end, created_at, snapshot").eq("org_id", ctx.org.id).order("created_at", { ascending: false }).limit(60);
  return (
    <div className="space-y-6">
      <PageHeader title="Berichte" description="Professionelle PDF-Berichte mit echten Prüfergebnissen – monatlich automatisch oder jederzeit auf Abruf." actions={ctx.rank >= 50 ? <CreateReportButton orgId={ctx.org.id} /> : undefined} />
      {(reports ?? []).length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-16 text-center">
          <FileText className="size-6 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">Noch keine Berichte. Der erste Monatsbericht wird zu Beginn des Folgemonats erstellt.</p>
        </div>
      ) : (
        <ul className="divide-y rounded-xl border bg-card">
          {reports!.map((r) => {
            const snap = r.snapshot as unknown as ReportSnapshot;
            return (
              <li key={r.id} className="flex flex-wrap items-center gap-4 px-5 py-4">
                <FileText className="size-5 text-muted-foreground" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{r.kind === "monthly" ? `Monatsbericht ${new Date(r.period_start).toLocaleDateString("de-DE", { month: "long", year: "numeric", timeZone: "UTC" })}` : "Bericht auf Abruf"}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDate(r.period_start)} – {formatDate(r.period_end)} · {snap.counts.newInPeriod} neue Befunde · {snap.counts.verifiedInPeriod} bestätigte Behebungen · {snap.counts.open} offen
                  </p>
                </div>
                <a href={`/api/reports/${r.id}/pdf`} className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"><Download className="size-3.5" /> PDF</a>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
