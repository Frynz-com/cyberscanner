import type { Metadata } from "next";
import { CheckCircle2, Download } from "lucide-react";
import { DeleteOrgForm, OrgForm, PauseToggle, PlanButton, PortalButton } from "@/components/app/settings-client";
import { PageHeader } from "@/components/shared/page-header";
import { getEntitlements } from "@/lib/core/entitlements";
import { formatDate } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";
import { stripeConfigured } from "@/lib/server/stripe";

export const metadata: Metadata = { title: "Einstellungen" };

const SUB_STATUS: Record<string, string> = { trialing: "Testphase", active: "Aktiv", past_due: "Zahlung ausstehend", canceled: "Beendet", unpaid: "Unbezahlt", incomplete: "Unvollständig", incomplete_expired: "Abgelaufen", paused: "Pausiert" };
const ROLE: Record<string, string> = { owner: "Inhaber", admin: "Administrator", member: "Mitglied", viewer: "Lesezugriff" };

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="grid gap-4 border-b pb-8 lg:grid-cols-3">
      <div><h2 className="font-semibold">{title}</h2>{description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}</div>
      <div className="lg:col-span-2">{children}</div>
    </section>
  );
}

export default async function SettingsPage({ searchParams }: { searchParams: Promise<{ billing?: string }> }) {
  const ctx = await requireOrg();
  const { billing } = await searchParams;
  const supabase = await createClient();
  const [{ data: org }, { data: plans }, { data: members }, ent, { data: auditLogs }] = await Promise.all([
    supabase.from("organizations").select("*").eq("id", ctx.org.id).single(),
    supabase.from("plans").select("key, name, price_cents, features").eq("active", true).neq("key", "trial").order("sort"),
    supabase.from("memberships").select("user_id, role, created_at, profiles(full_name)").eq("org_id", ctx.org.id),
    getEntitlements(supabase, ctx.org.id),
    ctx.rank >= 80 ? supabase.from("audit_logs").select("id, action, actor_type, created_at").eq("org_id", ctx.org.id).order("created_at", { ascending: false }).limit(25) : Promise.resolve({ data: [] }),
  ]);
  const isOwner = ctx.rank >= 100;
  const canEdit = ctx.rank >= 80 && !ctx.org.is_demo;
  const stripeOn = stripeConfigured();

  return (
    <div className="space-y-8">
      <PageHeader title="Einstellungen" description="Organisation, Abonnement, Datenschutz." />
      {billing === "success" && <p className="flex items-center gap-2 rounded-lg border border-ok/30 bg-ok/5 p-3 text-sm"><CheckCircle2 className="size-4 text-ok" /> Vielen Dank! Ihr Abonnement wird aktiviert, sobald die Zahlung bestätigt ist (in der Regel wenige Sekunden).</p>}

      <Section title="Organisation" description="Stammdaten und Kontaktadresse für Warnmeldungen.">
        <OrgForm org={org!} disabled={!canEdit} />
      </Section>

      <Section title="Überwachung">
        <PauseToggle orgId={ctx.org.id} paused={ctx.org.monitoring_paused} disabled={!canEdit} />
      </Section>

      <Section title="Abonnement" description="Leistungsumfang wird serverseitig anhand Ihres Abonnements freigeschaltet.">
        <div className="space-y-4">
          <div className="rounded-xl border bg-card p-4 text-sm" data-testid="subscription">
            <p><span className="text-muted-foreground">Tarif:</span> <strong>{ent.planName ?? "–"}</strong> · <span className="text-muted-foreground">Status:</span> {ent.status ? SUB_STATUS[ent.status] : "kein Abonnement"}</p>
            {ent.status === "trialing" && ent.trialEndsAt && <p className="text-muted-foreground">Testphase bis {formatDate(ent.trialEndsAt)}</p>}
            {ent.currentPeriodEnd && <p className="text-muted-foreground">{ent.cancelAtPeriodEnd ? "Endet" : "Verlängert sich"} am {formatDate(ent.currentPeriodEnd)}</p>}
            <p className="mt-2 text-xs text-muted-foreground">Enthalten: {ent.limits.max_domains} Domain(s), bis zu {ent.limits.max_subdomains_checked} Subdomains je Prüfung, Prüfintervall ab {ent.limits.min_scan_interval_hours} h, Datenleck-Überwachung {ent.limits.breach_monitoring ? "ja" : "nein"}.</p>
          </div>
          {!stripeOn && !ctx.org.is_demo && <p className="text-sm text-muted-foreground">Die Online-Zahlungsabwicklung ist in dieser Umgebung noch nicht eingerichtet. Bitte kontaktieren Sie uns für die Buchung.</p>}
          {isOwner && !ctx.org.is_demo && (
            <div className="grid gap-3 sm:grid-cols-2">
              {(plans ?? []).map((p) => (
                <div key={p.key} className="rounded-xl border p-4">
                  <p className="font-medium">{p.name}</p>
                  <p className="text-sm text-muted-foreground">{(p.price_cents / 100).toLocaleString("de-DE")} € netto / Monat</p>
                  <div className="mt-3"><PlanButton orgId={ctx.org.id} planKey={p.key} label={ent.planKey === p.key && ent.status === "active" ? "Aktueller Tarif" : `${p.name} buchen`} disabled={!stripeOn || (ent.planKey === p.key && ent.status === "active")} /></div>
                </div>
              ))}
            </div>
          )}
          {isOwner && stripeOn && !ctx.org.is_demo && <PortalButton orgId={ctx.org.id} />}
        </div>
      </Section>

      <Section title="Mitglieder" description="Personen mit Zugriff auf diese Organisation.">
        <ul className="divide-y rounded-xl border bg-card text-sm">
          {(members ?? []).map((m) => (
            <li key={m.user_id} className="flex justify-between px-4 py-2.5"><span>{(m.profiles as unknown as { full_name: string | null } | null)?.full_name || "Unbenannt"}{m.user_id === ctx.userId && " (Sie)"}</span><span className="text-muted-foreground">{ROLE[m.role]}</span></li>
          ))}
        </ul>
      </Section>

      <Section title="Datenschutz" description="Export Ihrer Daten (Art. 20 DSGVO) und Löschung.">
        <div className="space-y-6">
          {ctx.rank >= 80 && <a href="/api/export" className="inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-accent"><Download className="size-4" /> Alle Daten exportieren (JSON)</a>}
          {isOwner && !ctx.org.is_demo && <DeleteOrgForm orgId={ctx.org.id} name={ctx.org.name} />}
        </div>
      </Section>

      {ctx.rank >= 80 && (
        <Section title="Protokoll" description="Die letzten sicherheitsrelevanten Aktionen (unveränderbar gespeichert).">
          <ul className="divide-y rounded-xl border bg-card text-sm">
            {(auditLogs ?? []).map((a) => <li key={a.id} className="flex justify-between gap-3 px-4 py-2"><span className="font-mono text-xs">{a.action}</span><span className="text-xs text-muted-foreground">{a.actor_type} · {formatDate(a.created_at, true)}</span></li>)}
          </ul>
        </Section>
      )}
    </div>
  );
}
