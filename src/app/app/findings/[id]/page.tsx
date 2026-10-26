import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, BadgeCheck, BookOpen, CircleAlert, Clock, ExternalLink, Info, Lightbulb, ShieldQuestion } from "lucide-react";
import { CertaintyBadge, SeverityBadge, StatusBadge } from "@/components/shared/badges";
import { FindingActions } from "@/components/findings/finding-actions";
import { FindingEvents } from "@/components/findings/finding-events";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { decryptField, maskAccount } from "@/lib/core/crypto";
import { adapterName } from "@/lib/core/adapter-labels";
import { CATEGORY, CERTAINTY, formatDate } from "@/lib/labels";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Befund" };

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const ctx = await requireOrg();
  const supabase = await createClient();
  const { data: f } = await supabase.from("findings").select("*").eq("id", id).eq("org_id", ctx.org.id).maybeSingle();
  if (!f) notFound();
  const [{ data: events }, { data: actions }, { data: breaches }] = await Promise.all([
    supabase.from("finding_events").select("*").eq("finding_id", f.id).order("created_at"),
    supabase.from("actions").select("id, status, created_at, service_provider_invites(email, company_name, expires_at, revoked_at)").eq("finding_id", f.id).order("created_at", { ascending: false }),
    f.category === "breach" ? supabase.from("breach_records").select("id, breach_title, breach_date, data_classes, is_stealer_log, is_synthetic, first_observed_at").eq("finding_id", f.id).limit(200) : Promise.resolve({ data: null }),
  ]);

  // Betroffene Konten: nur Administratoren sehen vollständige Adressen (Entschlüsselung serverseitig)
  let accounts: Array<{ id: string; label: string; synthetic: boolean }> = [];
  if (f.category === "breach" && breaches?.length) {
    const admin = createAdminClient();
    const { data: enc } = await admin.from("breach_records").select("id, account_enc, is_synthetic").eq("finding_id", f.id).eq("org_id", ctx.org.id).limit(200);
    accounts = (enc ?? []).map((r) => {
      let plain = "***";
      try {
        plain = decryptField(r.account_enc);
      } catch {
        /* Schlüsselrotation o. ä. */
      }
      return { id: r.id, label: ctx.rank >= 80 ? plain : maskAccount(plain), synthetic: r.is_synthetic };
    });
  }

  const docs = (f.docs as Array<{ label: string; url: string }>) ?? [];
  const reasons = (f.priority_reasons as string[]) ?? [];
  const evidence = f.evidence as Record<string, unknown>;

  return (
    <div className="space-y-6">
      <Link href="/app/findings" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-3.5" /> Alle Befunde
      </Link>

      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <CertaintyBadge certainty={f.certainty} />
          <StatusBadge status={f.status} />
          {f.is_demo && <span className="rounded-full bg-violet-500/10 px-2 py-0.5 text-xs font-medium text-violet-700">DEMO</span>}
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-balance">{f.title}</h1>
        <p className="text-sm text-muted-foreground">
          <span className="font-mono text-foreground">{f.asset_value}</span> · {CATEGORY[f.category] ?? f.category} · erstmals erkannt {formatDate(f.first_seen_at, true)} · zuletzt bestätigt {formatDate(f.last_seen_at, true)}
        </p>
      </div>

      {f.verification_state === "unverified" && (
        <div className="flex gap-3 rounded-xl border border-sev-low/25 bg-sev-low/5 p-4 text-sm">
          <Clock className="mt-0.5 size-4 shrink-0 text-sev-low" />
          <p>Als behoben markiert. <strong>Die technische Bestätigung steht noch aus</strong> – sie erfolgt durch die Nachprüfung.</p>
        </div>
      )}
      {f.verification_state === "verified_fixed" && (
        <div className="flex gap-3 rounded-xl border border-ok/25 bg-ok/5 p-4 text-sm">
          <BadgeCheck className="mt-0.5 size-4 shrink-0 text-ok" />
          <p><strong>Behebung technisch bestätigt</strong> am {formatDate(f.resolved_at, true)}: Die zuständige Prüfung lief vollständig und hat das Problem nicht mehr festgestellt.</p>
        </div>
      )}
      {f.verification_state === "still_present" && (
        <div className="flex gap-3 rounded-xl border border-sev-high/25 bg-sev-high/5 p-4 text-sm">
          <CircleAlert className="mt-0.5 size-4 shrink-0 text-sev-high" />
          <p><strong>Nachprüfung: weiterhin vorhanden.</strong> Das Problem wurde bei der letzten Prüfung erneut festgestellt.</p>
        </div>
      )}

      <FindingActions finding={{ id: f.id, status: f.status, title: f.title }} orgId={ctx.org.id} canManage={ctx.rank >= 50} canShare={ctx.rank >= 80} isDemo={ctx.org.is_demo} />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Tabs defaultValue="business">
            <TabsList>
              <TabsTrigger value="business">Verständlich erklärt</TabsTrigger>
              <TabsTrigger value="technical">Für IT-Dienstleister</TabsTrigger>
            </TabsList>
            <TabsContent value="business" className="mt-4 space-y-4">
              <section className="rounded-xl border bg-card p-5">
                <h2 className="mb-2 flex items-center gap-2 font-semibold"><Info className="size-4 text-muted-foreground" /> Was wurde festgestellt?</h2>
                <p className="text-sm leading-relaxed">{f.summary}</p>
              </section>
              <section className="rounded-xl border bg-card p-5">
                <h2 className="mb-2 flex items-center gap-2 font-semibold"><ShieldQuestion className="size-4 text-muted-foreground" /> Warum ist das wichtig?</h2>
                <p className="text-sm leading-relaxed">{f.business_impact}</p>
              </section>
              <section className="rounded-xl border border-brand/25 bg-brand-soft/40 p-5">
                <h2 className="mb-2 flex items-center gap-2 font-semibold"><Lightbulb className="size-4 text-brand" /> Was sollte ich jetzt tun?</h2>
                <p className="text-sm leading-relaxed whitespace-pre-line">{f.recommendation.replace(/ (\d)\. /g, "\n$1. ")}</p>
              </section>
              {accounts.length > 0 && (
                <section className="rounded-xl border bg-card p-5">
                  <h2 className="mb-1 font-semibold">Betroffene Konten ({accounts.length})</h2>
                  <p className="mb-3 text-xs text-muted-foreground">
                    {ctx.rank >= 80 ? "Vollständige Adressen sind nur für Administratoren sichtbar." : "Adressen werden maskiert angezeigt. Administratoren sehen die vollständigen Adressen."} Passwörter werden von uns weder abgerufen noch gespeichert.
                  </p>
                  <ul className="grid gap-1.5 sm:grid-cols-2">
                    {accounts.map((a) => (
                      <li key={a.id} className="rounded-md bg-muted px-2.5 py-1 font-mono text-xs">{a.label}{a.synthetic && " (Testdaten)"}</li>
                    ))}
                  </ul>
                </section>
              )}
            </TabsContent>
            <TabsContent value="technical" className="mt-4 space-y-4">
              <section className="rounded-xl border bg-card p-5">
                <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
                  <div><dt className="text-xs text-muted-foreground">Betroffenes Asset</dt><dd className="font-mono">{f.asset_value}</dd></div>
                  <div><dt className="text-xs text-muted-foreground">Quelle</dt><dd>{adapterName(f.source)}{f.source_ref && <> · <a className="inline-flex items-center gap-0.5 underline" href={f.source_ref} target="_blank" rel="noreferrer">Referenz <ExternalLink className="size-3" /></a></>}</dd></div>
                  <div><dt className="text-xs text-muted-foreground">Regel</dt><dd className="font-mono text-xs">{f.rule_id}</dd></div>
                  <div><dt className="text-xs text-muted-foreground">Prüfung</dt><dd className="font-mono text-xs">{f.check_key}</dd></div>
                  <div><dt className="text-xs text-muted-foreground">Erstmals beobachtet</dt><dd>{formatDate(f.first_seen_at, true)}</dd></div>
                  <div><dt className="text-xs text-muted-foreground">Zuletzt beobachtet</dt><dd>{formatDate(f.last_seen_at, true)}</dd></div>
                  <div><dt className="text-xs text-muted-foreground">Einstufung</dt><dd>{CERTAINTY[f.certainty].label} · Konfidenz {f.confidence === "high" ? "hoch" : f.confidence === "medium" ? "mittel" : "niedrig"}</dd></div>
                </dl>
              </section>
              <section className="rounded-xl border bg-card p-5">
                <h2 className="mb-2 text-sm font-semibold">Technische Beobachtung</h2>
                <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap">{f.technical_details}</pre>
                {Object.keys(evidence).length > 0 && (
                  <>
                    <h3 className="mt-4 mb-2 text-xs font-semibold text-muted-foreground uppercase">Nachweis</h3>
                    <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs">{JSON.stringify(evidence, null, 2)}</pre>
                  </>
                )}
              </section>
              {f.verification_steps && (
                <section className="rounded-xl border bg-card p-5">
                  <h2 className="mb-2 text-sm font-semibold">Reproduzierbare Prüfschritte</h2>
                  <pre className="overflow-x-auto rounded-md bg-primary p-3 font-mono text-xs text-primary-foreground">{f.verification_steps}</pre>
                </section>
              )}
              <section className="rounded-xl border bg-card p-5">
                <h2 className="mb-2 text-sm font-semibold">Empfohlene Behebung</h2>
                <p className="text-sm">{f.recommendation}</p>
                {docs.length > 0 && (
                  <ul className="mt-3 space-y-1">
                    {docs.map((d) => (
                      <li key={d.url}><a href={d.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-sm text-brand hover:underline"><BookOpen className="size-3.5" />{d.label}</a></li>
                    ))}
                  </ul>
                )}
              </section>
            </TabsContent>
          </Tabs>
        </div>

        <aside className="space-y-6">
          <section className="rounded-xl border bg-card p-5">
            <div className="flex items-baseline justify-between">
              <h2 className="text-sm font-semibold">Priorität</h2>
              <span className="text-2xl font-semibold tabular">{f.priority_score}<span className="text-sm text-muted-foreground">/100</span></span>
            </div>
            <ul className="mt-3 space-y-1.5 text-xs text-muted-foreground">
              {reasons.map((r) => <li key={r}>• {r}</li>)}
            </ul>
          </section>
          {(actions ?? []).length > 0 && (
            <section className="rounded-xl border bg-card p-5">
              <h2 className="mb-3 text-sm font-semibold">Weitergegeben an</h2>
              <ul className="space-y-2 text-sm">
                {actions!.map((a) => {
                  const inv = a.service_provider_invites as unknown as { email: string; company_name: string | null } | null;
                  return (
                    <li key={a.id} className="flex justify-between gap-2">
                      <span className="truncate">{inv?.company_name || inv?.email}</span>
                      <span className="text-xs text-muted-foreground">{{ open: "Offen", in_progress: "In Bearbeitung", fixed_pending_verification: "Umgesetzt – Prüfung ausstehend", verified: "Bestätigt", still_open: "Weiterhin offen", cancelled: "Widerrufen" }[a.status]}</span>
                    </li>
                  );
                })}
              </ul>
            </section>
          )}
          <section className="rounded-xl border bg-card p-5">
            <h2 className="mb-4 text-sm font-semibold">Verlauf</h2>
            <FindingEvents events={events ?? []} />
          </section>
        </aside>
      </div>
    </div>
  );
}
