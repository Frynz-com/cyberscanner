import type { Metadata } from "next";
import Link from "next/link";
import { CheckCircle2, CircleDashed, ShieldAlert } from "lucide-react";
import { ScanButton } from "@/components/dashboard/scan-button";
import { AutoRefresh } from "@/components/dashboard/auto-refresh";
import { AddDomainForm, CancelJobButton, DomainSettingsForm, RevokeAuthorizationButton, VerifyButton } from "@/components/domains/domain-client";
import { CopyField } from "@/components/shared/copy-field";
import { PageHeader } from "@/components/shared/page-header";
import { getEntitlements } from "@/lib/core/entitlements";
import { SCOPE_DESCRIPTIONS } from "@/lib/core/scope-descriptions";
import { formatDate, relativeTime } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Domains" };

const JOB_STATUS: Record<string, string> = { queued: "Wartet", running: "Läuft", succeeded: "Abgeschlossen", failed: "Fehlgeschlagen", cancelled: "Abgebrochen" };
const JOB_KIND: Record<string, string> = { domain_scan: "Vollständige Prüfung", reverify: "Nachprüfung" };
const TRIGGER: Record<string, string> = { manual: "manuell", schedule: "geplant", onboarding: "Einrichtung", reverify: "Nachprüfung", partner: "IT-Dienstleister" };

export default async function DomainsPage() {
  const ctx = await requireOrg();
  const supabase = await createClient();
  const [{ data: domains }, { data: challenges }, { data: auths }, { data: jobs }, ent] = await Promise.all([
    supabase.from("domains").select("*").eq("org_id", ctx.org.id).order("created_at"),
    supabase.from("verification_challenges").select("domain_id, record_name, token, expires_at, last_result, last_checked_at").eq("org_id", ctx.org.id).is("consumed_at", null),
    supabase.from("scan_authorizations").select("domain_id, scopes, include_subdomains, signer_name, signer_role, granted_at, valid_until, revoked_at").eq("org_id", ctx.org.id).order("granted_at", { ascending: false }),
    supabase.from("scan_jobs").select("id, domain_id, kind, status, trigger, created_at, finished_at, error").eq("org_id", ctx.org.id).order("created_at", { ascending: false }).limit(20),
    getEntitlements(supabase, ctx.org.id),
  ]);
  const isAdmin = ctx.rank >= 80;
  const running = (jobs ?? []).some((j) => ["queued", "running"].includes(j.status));

  return (
    <div className="space-y-6">
      <AutoRefresh active={running} />
      <PageHeader title="Domains" description="Verifizierte Domains, Prüfberechtigungen und Prüfintervalle." />
      {isAdmin && !ctx.org.is_demo && (
        <div className="rounded-xl border bg-card p-4">
          <AddDomainForm orgId={ctx.org.id} />
          <p className="mt-2 text-xs text-muted-foreground">Ihr Tarif ({ent.planName ?? "kein aktives Abonnement"}) umfasst bis zu {ent.limits.max_domains} Domain(s).</p>
        </div>
      )}
      {(domains ?? []).length === 0 && (
        <div className="rounded-xl border border-dashed py-14 text-center text-sm text-muted-foreground">Noch keine Domain hinterlegt.</div>
      )}
      {(domains ?? []).map((d) => {
        const ch = challenges?.find((c) => c.domain_id === d.id);
        const auth = auths?.find((a) => a.domain_id === d.id && !a.revoked_at && new Date(a.valid_until) > new Date());
        const domainJobs = (jobs ?? []).filter((j) => j.domain_id === d.id).slice(0, 5);
        return (
          <section key={d.id} className="rounded-xl border bg-card" data-testid={`domain-${d.hostname}`}>
            <div className="flex flex-col gap-3 border-b p-5 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="font-mono text-lg font-semibold">{d.hostname}</h2>
                <p className="text-sm text-muted-foreground">
                  {d.verification_status === "verified" ? <span className="inline-flex items-center gap-1 text-ok"><CheckCircle2 className="size-3.5" /> Verifiziert am {formatDate(d.verified_at)}</span> : d.verification_status === "expired" ? <span className="text-sev-high">Verifizierung abgelaufen – bitte erneut verifizieren</span> : <span className="inline-flex items-center gap-1 text-[oklch(0.55_0.13_70)]"><CircleDashed className="size-3.5" /> Verifizierung ausstehend</span>}
                  {d.last_scan_at && <> · zuletzt geprüft {relativeTime(d.last_scan_at)}</>}
                </p>
              </div>
              {d.verification_status === "verified" && auth && !ctx.org.is_demo && ctx.rank >= 50 && <ScanButton domainId={d.id} variant="outline" size="sm" />}
            </div>

            <div className="grid gap-6 p-5 lg:grid-cols-2">
              {d.verification_status !== "verified" && ch && (
                <div className="space-y-3 lg:col-span-2">
                  <p className="text-sm">Legen Sie diesen TXT-Eintrag bei Ihrem DNS-Anbieter an:</p>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <CopyField value={ch.record_name} />
                    <CopyField value={ch.token} />
                  </div>
                  {ch.last_checked_at && <p className="text-xs text-muted-foreground">Zuletzt geprüft {relativeTime(ch.last_checked_at)}: {ch.last_result === "not_found" ? "nicht gefunden" : ch.last_result}</p>}
                  {isAdmin && <VerifyButton domainId={d.id} />}
                </div>
              )}

              {d.verification_status === "verified" && (
                <div className="space-y-2">
                  <h3 className="text-sm font-semibold">Prüfberechtigung</h3>
                  {auth ? (
                    <>
                      <ul className="space-y-1 text-sm">
                        {auth.scopes.map((s) => <li key={s} className="flex items-center gap-2"><CheckCircle2 className="size-3.5 text-ok" />{SCOPE_DESCRIPTIONS[s as keyof typeof SCOPE_DESCRIPTIONS]?.title ?? s}</li>)}
                        {auth.include_subdomains && <li className="flex items-center gap-2"><CheckCircle2 className="size-3.5 text-ok" />Subdomains einbezogen</li>}
                      </ul>
                      <p className="text-xs text-muted-foreground">Erteilt von {auth.signer_name} ({auth.signer_role}) am {formatDate(auth.granted_at)} · gültig bis {formatDate(auth.valid_until)}</p>
                      {isAdmin && !ctx.org.is_demo && <RevokeAuthorizationButton domainId={d.id} />}
                    </>
                  ) : (
                    <div className="flex items-start gap-2 text-sm">
                      <ShieldAlert className="mt-0.5 size-4 text-[oklch(0.55_0.13_70)]" />
                      <p>Keine gültige Freigabe. <Link href="/onboarding" className="underline">Freigabe erteilen</Link></p>
                    </div>
                  )}
                </div>
              )}

              {d.verification_status === "verified" && isAdmin && !ctx.org.is_demo && (
                <div className="space-y-2">
                  <h3 className="text-sm font-semibold">Zeitplan</h3>
                  <DomainSettingsForm domainId={d.id} interval={d.scan_interval_hours} enabled={d.monitoring_enabled} minInterval={ent.limits.min_scan_interval_hours} />
                  {d.next_scan_at && d.monitoring_enabled && <p className="text-xs text-muted-foreground">Nächste geplante Prüfung: {formatDate(d.next_scan_at, true)}</p>}
                </div>
              )}

              {domainJobs.length > 0 && (
                <div className="lg:col-span-2">
                  <h3 className="mb-2 text-sm font-semibold">Letzte Prüfungen</h3>
                  <ul className="divide-y rounded-lg border text-sm">
                    {domainJobs.map((j) => (
                      <li key={j.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2">
                        <span className="w-40 shrink-0">{JOB_KIND[j.kind] ?? j.kind}</span>
                        <span className="text-muted-foreground">{formatDate(j.created_at, true)} · {TRIGGER[j.trigger] ?? j.trigger}</span>
                        <span className={j.status === "failed" ? "text-destructive" : j.status === "succeeded" ? "text-ok" : "text-muted-foreground"}>{JOB_STATUS[j.status]}</span>
                        {j.error && <span className="truncate text-xs text-muted-foreground">{j.error}</span>}
                        {["queued", "running"].includes(j.status) && ctx.rank >= 50 && <span className="ml-auto"><CancelJobButton jobId={j.id} /></span>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </section>
        );
      })}
    </div>
  );
}
