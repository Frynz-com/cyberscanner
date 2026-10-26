import type { Metadata } from "next";
import { BookOpen, LinkIcon, Lock } from "lucide-react";
import { Logo } from "@/components/brand/logo";
import { CertaintyBadge, SeverityBadge } from "@/components/shared/badges";
import { formatDate } from "@/lib/labels";
import { createAdminClient } from "@/lib/supabase/admin";
import { resolvePartnerToken } from "@/lib/server/partner";
import { adapterName } from "@/lib/core/adapter-labels";
import { PartnerControls } from "./controls";

export const metadata: Metadata = { title: "Freigegebene Befunde", robots: { index: false, follow: false } };
export const dynamic = "force-dynamic";

const STATUS: Record<string, string> = { open: "Offen", in_progress: "In Bearbeitung", fixed_pending_verification: "Umgesetzt – Nachprüfung läuft", verified: "Behebung bestätigt", still_open: "Nachprüfung: weiterhin offen", cancelled: "Widerrufen" };

export default async function PartnerPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const session = await resolvePartnerToken(token);
  if (!session) {
    return (
      <main className="flex min-h-dvh flex-col items-center justify-center gap-4 px-4 text-center">
        <Lock className="size-8 text-muted-foreground" />
        <h1 className="text-xl font-semibold">Link ungültig oder abgelaufen</h1>
        <p className="max-w-md text-sm text-muted-foreground">Dieser Freigabe-Link ist nicht (mehr) gültig. Bitte wenden Sie sich an Ihren Kunden, um eine neue Freigabe zu erhalten.</p>
      </main>
    );
  }
  // Ausschließlich freigegebene Befunde laden (Service-Client, harte Filterung auf IDs + Organisation)
  const admin = createAdminClient();
  const { data: findings } = await admin
    .from("findings")
    .select("id, title, severity, certainty, asset_value, source, source_ref, technical_details, verification_steps, recommendation, docs, evidence, first_seen_at, last_seen_at, status, verification_state")
    .eq("org_id", session.orgId)
    .in("id", session.findingIds.length ? session.findingIds : ["00000000-0000-0000-0000-000000000000"]);
  const { data: actions } = await admin.from("actions").select("finding_id, status").eq("invite_id", session.inviteId);

  return (
    <div className="min-h-dvh bg-background">
      <header className="border-b bg-card">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <Logo />
          <p className="text-xs text-muted-foreground">Freigabe für {session.companyName || session.email} · gültig bis {formatDate(session.expiresAt)}</p>
        </div>
      </header>
      <main className="mx-auto max-w-4xl space-y-6 px-4 py-8">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">{session.orgName} bittet um Unterstützung</h1>
          <p className="text-sm text-muted-foreground">
            Unten finden Sie {findings?.length ?? 0} freigegebene Befund(e) mit technischen Details. Bitte geben Sie eine Rückmeldung, sobald Sie mit der Bearbeitung beginnen bzw. die Maßnahme umgesetzt ist – wir prüfen dann automatisch nach.
          </p>
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><LinkIcon className="size-3" /> Dieser Link ist persönlich und gewährt nur Zugriff auf diese Befunde. Bitte nicht weitergeben.</p>
        </div>
        {(findings ?? []).map((f) => {
          const a = actions?.find((x) => x.finding_id === f.id);
          const docs = (f.docs as Array<{ label: string; url: string }>) ?? [];
          return (
            <article key={f.id} className="rounded-xl border bg-card" data-testid="partner-finding">
              <div className="space-y-2 border-b p-5">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <CertaintyBadge certainty={f.certainty} />
                  <span className="text-xs text-muted-foreground">Status: {STATUS[a?.status ?? "open"]}</span>
                </div>
                <h2 className="text-lg font-semibold">{f.title}</h2>
                <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
                  <div><dt className="inline text-muted-foreground">Asset: </dt><dd className="inline font-mono">{f.asset_value}</dd></div>
                  <div><dt className="inline text-muted-foreground">Quelle: </dt><dd className="inline">{adapterName(f.source)}</dd></div>
                  <div><dt className="inline text-muted-foreground">Erstmals: </dt><dd className="inline">{formatDate(f.first_seen_at, true)}</dd></div>
                  <div><dt className="inline text-muted-foreground">Zuletzt bestätigt: </dt><dd className="inline">{formatDate(f.last_seen_at, true)}</dd></div>
                </dl>
              </div>
              <div className="space-y-4 p-5">
                <section>
                  <h3 className="mb-1 text-sm font-semibold">Technische Beobachtung</h3>
                  <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap">{f.technical_details}</pre>
                </section>
                {f.verification_steps && (
                  <section>
                    <h3 className="mb-1 text-sm font-semibold">Prüfschritte</h3>
                    <pre className="overflow-x-auto rounded-md bg-primary p-3 font-mono text-xs text-primary-foreground">{f.verification_steps}</pre>
                  </section>
                )}
                <section>
                  <h3 className="mb-1 text-sm font-semibold">Empfohlene Behebung</h3>
                  <p className="text-sm">{f.recommendation}</p>
                  {docs.map((d) => <a key={d.url} href={d.url} target="_blank" rel="noreferrer" className="mt-1 mr-4 inline-flex items-center gap-1 text-sm text-brand hover:underline"><BookOpen className="size-3.5" />{d.label}</a>)}
                </section>
                {a?.status !== "cancelled" && <PartnerControls token={token} findingId={f.id} status={a?.status ?? "open"} />}
              </div>
            </article>
          );
        })}
      </main>
    </div>
  );
}
