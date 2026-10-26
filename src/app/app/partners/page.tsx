import type { Metadata } from "next";
import Link from "next/link";
import { ShieldCheck, Users } from "lucide-react";
import { NewShare, RevokeInvite } from "@/components/partners/partners-client";
import { PageHeader } from "@/components/shared/page-header";
import { formatDate, relativeTime } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "IT-Dienstleister" };

const ACTION_STATUS: Record<string, { label: string; tone: string }> = {
  open: { label: "Offen", tone: "text-muted-foreground" },
  in_progress: { label: "In Bearbeitung", tone: "text-sev-low" },
  fixed_pending_verification: { label: "Umgesetzt – Nachprüfung läuft", tone: "text-[oklch(0.55_0.13_70)]" },
  verified: { label: "Behebung bestätigt", tone: "text-ok" },
  still_open: { label: "Weiterhin offen", tone: "text-sev-high" },
  cancelled: { label: "Widerrufen", tone: "text-muted-foreground" },
};

export default async function PartnersPage() {
  const ctx = await requireOrg();
  const supabase = await createClient();
  const [{ data: invites }, { data: actions }, { data: open }] = await Promise.all([
    supabase.from("service_provider_invites").select("id, email, contact_name, company_name, expires_at, revoked_at, last_access_at, access_count, created_at").eq("org_id", ctx.org.id).order("created_at", { ascending: false }),
    supabase.from("actions").select("id, invite_id, status, updated_at, findings(id, title)").eq("org_id", ctx.org.id),
    supabase.from("findings").select("id, title, severity, asset_value").eq("org_id", ctx.org.id).in("status", ["new", "investigating", "action_required"]).neq("severity", "info").order("priority_score", { ascending: false }).limit(100),
  ]);
  const now = new Date();

  return (
    <div className="space-y-6">
      <PageHeader title="IT-Dienstleister" description="Geben Sie einzelne Befunde gezielt und zeitlich begrenzt an Ihren IT-Partner weiter – ohne Zugriff auf Ihr Konto." />
      <div className="grid gap-6 lg:grid-cols-5">
        {ctx.rank >= 80 && (
          <section className="rounded-xl border bg-card p-5 lg:col-span-2">
            <h2 className="mb-1 font-semibold">Neue Freigabe</h2>
            <p className="mb-4 text-sm text-muted-foreground">Wählen Sie die Befunde, die Ihr Dienstleister bearbeiten soll.</p>
            <NewShare orgId={ctx.org.id} findings={open ?? []} isDemo={ctx.org.is_demo} />
            <div className="mt-5 flex gap-2.5 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
              <ShieldCheck className="size-4 shrink-0" />
              <p>Ihr Dienstleister sieht nur die freigegebenen Befunde mit technischen Details und kann Rückmeldungen geben sowie eine Nachprüfung anstoßen. Sie können jede Freigabe jederzeit widerrufen.</p>
            </div>
          </section>
        )}
        <section className={ctx.rank >= 80 ? "lg:col-span-3" : "lg:col-span-5"}>
          {(invites ?? []).length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 rounded-xl border border-dashed py-16 text-center">
              <Users className="size-6 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">Noch keine Freigaben.</p>
            </div>
          ) : (
            <ul className="space-y-4">
              {invites!.map((inv) => {
                const active = !inv.revoked_at && new Date(inv.expires_at) > now;
                const acts = (actions ?? []).filter((a) => a.invite_id === inv.id);
                return (
                  <li key={inv.id} className="rounded-xl border bg-card">
                    <div className="flex flex-wrap items-start justify-between gap-3 border-b p-4">
                      <div>
                        <p className="font-medium">{inv.company_name || inv.email}</p>
                        <p className="text-xs text-muted-foreground">
                          {inv.contact_name && `${inv.contact_name} · `}{inv.email} · erstellt {formatDate(inv.created_at)} ·{" "}
                          {inv.revoked_at ? "widerrufen" : active ? `gültig bis ${formatDate(inv.expires_at)}` : "abgelaufen"}
                          {inv.last_access_at && ` · zuletzt geöffnet ${relativeTime(inv.last_access_at)}`}
                        </p>
                      </div>
                      {active && ctx.rank >= 80 && <RevokeInvite inviteId={inv.id} />}
                    </div>
                    <ul className="divide-y text-sm">
                      {acts.map((a) => {
                        const f = a.findings as unknown as { id: string; title: string } | null;
                        return (
                          <li key={a.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                            {f ? <Link href={`/app/findings/${f.id}`} className="truncate hover:underline">{f.title}</Link> : <span>–</span>}
                            <span className={`shrink-0 text-xs ${ACTION_STATUS[a.status]?.tone}`}>{ACTION_STATUS[a.status]?.label}</span>
                          </li>
                        );
                      })}
                    </ul>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
