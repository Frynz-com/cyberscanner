import type { Metadata } from "next";
import Link from "next/link";
import { Info } from "lucide-react";
import { ReportFlow } from "@/components/emergency/report-flow";
import { PageHeader } from "@/components/shared/page-header";
import { contractedExpert, PLAYBOOKS, type IncidentType } from "@/lib/content/playbooks";
import { formatDate } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Notfall" };

const STATUS: Record<string, string> = { open: "Offen", in_progress: "In Bearbeitung", contained: "Eingedämmt", closed: "Abgeschlossen" };
const PRIO: Record<string, string> = { p1: "bg-sev-critical text-white", p2: "bg-sev-high text-white", p3: "bg-muted text-muted-foreground" };

export default async function EmergencyPage() {
  const ctx = await requireOrg();
  const supabase = await createClient();
  const [{ data: incidents }, { data: profile }, { count: partners }] = await Promise.all([
    supabase.from("incidents").select("id, type, priority, status, title, created_at").eq("org_id", ctx.org.id).order("created_at", { ascending: false }).limit(50),
    supabase.from("profiles").select("full_name").eq("id", ctx.userId).single(),
    supabase.from("service_provider_invites").select("id", { count: "exact", head: true }).eq("org_id", ctx.org.id).is("revoked_at", null).gt("expires_at", new Date().toISOString()),
  ]);
  const expert = contractedExpert();
  return (
    <div className="space-y-6">
      <PageHeader title="Emergency Desk" description="Digitale Erstunterstützung bei Cybervorfällen: sichere Sofortmaßnahmen, Dokumentation und Benachrichtigung." />
      <div className="flex gap-3 rounded-xl border bg-card p-4 text-sm text-muted-foreground">
        <Info className="mt-0.5 size-4 shrink-0" />
        <p>
          CyberSafe24 Shield bietet digitale Notfallunterstützung. {expert ? `Für Ihren Vertrag ist ${expert.name} als Experte angebunden${expert.hours ? ` (Erreichbarkeit: ${expert.hours})` : ""}.` : "Ein persönlicher Bereitschaftsdienst ist in Ihrem Vertrag derzeit nicht enthalten; es gelten keine zugesicherten Reaktionszeiten."} Bei akuter Gefahr wenden Sie sich bitte an Ihren IT-Dienstleister und die Polizei.
        </p>
      </div>
      {ctx.rank >= 50 && <ReportFlow orgId={ctx.org.id} defaultName={profile?.full_name ?? ""} hasPartner={(partners ?? 0) > 0} expert={expert} />}
      <section>
        <h2 className="mb-3 text-sm font-semibold">Gemeldete Vorfälle</h2>
        {(incidents ?? []).length === 0 ? (
          <p className="rounded-xl border border-dashed py-10 text-center text-sm text-muted-foreground">Keine Vorfälle gemeldet.</p>
        ) : (
          <ul className="divide-y rounded-xl border bg-card">
            {incidents!.map((i) => (
              <li key={i.id}>
                <Link href={`/app/emergency/${i.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-accent/50">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase ${PRIO[i.priority]}`}>{i.priority}</span>
                  <span className="flex-1 truncate text-sm font-medium">{PLAYBOOKS[i.type as IncidentType]?.title ?? i.title}</span>
                  <span className="text-xs text-muted-foreground">{STATUS[i.status]} · {formatDate(i.created_at, true)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
