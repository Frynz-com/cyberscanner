"use client";

import { useActionState, useEffect, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2, Clock, Loader2, RefreshCw, ShieldCheck, XCircle } from "lucide-react";
import { toast } from "sonner";
import { createOrganizationAction } from "@/app/actions/org";
import { addDomainAction, checkVerificationAction, getScanJobStatusAction, grantAuthorizationAction, requestScanAction } from "@/app/actions/domains";
import { FieldError, FormError, SubmitButton } from "@/components/forms/submit-button";
import { CopyField } from "@/components/shared/copy-field";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SCOPE_DESCRIPTIONS } from "@/lib/core/scope-descriptions";

function StepHeader({ title, text }: { title: string; text: string }) {
  return (
    <div className="mb-8 space-y-2">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="text-muted-foreground">{text}</p>
    </div>
  );
}

export function CompanyStep({ defaultEmail }: { defaultEmail: string }) {
  const [state, action] = useActionState(createOrganizationAction, null);
  const fe = state && !state.ok ? state.fieldErrors : undefined;
  return (
    <div>
      <StepHeader title="Ihr Unternehmen" text="Damit wir Berichte und Benachrichtigungen richtig zuordnen können." />
      <form action={action} className="space-y-5">
        <div className="space-y-2">
          <Label htmlFor="name">Firmenname</Label>
          <Input id="name" name="name" placeholder="Muster GmbH" required autoFocus />
          <FieldError message={fe?.name} />
        </div>
        <div className="grid gap-5 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="industry">Branche <span className="text-muted-foreground">(optional)</span></Label>
            <Input id="industry" name="industry" placeholder="z. B. Maschinenbau" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="employeeRange">Mitarbeitende <span className="text-muted-foreground">(optional)</span></Label>
            <select id="employeeRange" name="employeeRange" className="h-9 w-full rounded-md border bg-transparent px-3 text-sm shadow-xs">
              <option value="">Bitte wählen</option>
              {["1-9", "10-49", "50-249", "250-999", "1000+"].map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="contactEmail">E-Mail für Sicherheitswarnungen</Label>
          <Input id="contactEmail" name="contactEmail" type="email" defaultValue={defaultEmail} />
          <p className="text-xs text-muted-foreground">Zum Beispiel Geschäftsführung oder IT-Verantwortliche.</p>
          <FieldError message={fe?.contactEmail} />
        </div>
        <FormError message={state && !state.ok && !fe ? state.error : undefined} />
        <SubmitButton pendingText="Wird gespeichert …">Weiter</SubmitButton>
      </form>
    </div>
  );
}

export function DomainStep({ orgId, suggested }: { orgId: string; suggested?: string }) {
  const router = useRouter();
  const [state, action] = useActionState(async (prev: unknown, fd: FormData) => {
    const res = await addDomainAction(prev, fd);
    if (res.ok) router.refresh();
    return res;
  }, null);
  return (
    <div>
      <StepHeader title="Welche Domain sollen wir überwachen?" text="In der Regel die Domain Ihrer Website und E-Mail-Adressen, z. B. firma.de." />
      <form action={action} className="space-y-5">
        <input type="hidden" name="orgId" value={orgId} />
        <div className="space-y-2">
          <Label htmlFor="domain">Domain</Label>
          <Input id="domain" name="domain" placeholder="firma.de" defaultValue={suggested} required autoFocus autoCapitalize="none" spellCheck={false} />
          <FieldError message={state && !state.ok ? state.error : undefined} />
        </div>
        <SubmitButton pendingText="Wird geprüft …">Domain hinzufügen</SubmitButton>
      </form>
    </div>
  );
}

const PROVIDER_HINTS = [
  { name: "IONOS", hint: "Domains & SSL → Domain auswählen → DNS → Eintrag hinzufügen → TXT" },
  { name: "STRATO", hint: "Domains → Domainverwaltung → DNS → TXT- und CNAME-Records verwalten" },
  { name: "Cloudflare", hint: "DNS → Records → Add record → Type TXT" },
  { name: "Microsoft 365 / andere", hint: "Bitten Sie Ihren IT-Dienstleister, den Eintrag anzulegen – die Werte unten können Sie direkt weiterleiten." },
];

export function VerifyStep({ domainId, hostname, recordName, token }: { domainId: string; hostname: string; recordName: string; token: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [result, setResult] = useState<{ verified: boolean; found: string[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const check = () =>
    start(async () => {
      setError(null);
      const res = await checkVerificationAction(domainId);
      if (!res.ok) return setError(res.error);
      setResult(res.data ?? null);
      if (res.data?.verified) {
        toast.success("Domain erfolgreich verifiziert");
        router.refresh();
      }
    });
  return (
    <div>
      <StepHeader title={`Bestätigen Sie, dass ${hostname} Ihnen gehört`} text="Bevor wir Ihre Systeme prüfen, benötigen wir einen Nachweis. Legen Sie dazu einmalig einen DNS-Eintrag an – das dauert 2 Minuten." />
      <div className="space-y-4 rounded-xl border bg-card p-5">
        <div className="grid gap-4 sm:grid-cols-[100px_1fr]">
          <span className="pt-2 text-sm text-muted-foreground">Typ</span>
          <CopyField value="TXT" />
          <span className="pt-2 text-sm text-muted-foreground">Name / Host</span>
          <CopyField value={recordName} hint={`Bei manchen Anbietern nur: _cybersafe24-verification`} />
          <span className="pt-2 text-sm text-muted-foreground">Wert</span>
          <CopyField value={token} />
        </div>
      </div>
      <details className="mt-4 rounded-lg border px-4 py-3 text-sm">
        <summary className="cursor-pointer font-medium">Wo lege ich den Eintrag an?</summary>
        <ul className="mt-3 space-y-2 text-muted-foreground">
          {PROVIDER_HINTS.map((p) => (
            <li key={p.name}><span className="font-medium text-foreground">{p.name}:</span> {p.hint}</li>
          ))}
        </ul>
      </details>
      <div className="mt-6 flex flex-wrap items-center gap-3">
        <Button onClick={check} disabled={pending}>
          {pending ? <Loader2 className="animate-spin" /> : <RefreshCw />}
          Eintrag jetzt prüfen
        </Button>
        <span className="text-xs text-muted-foreground">DNS-Änderungen können einige Minuten dauern.</span>
      </div>
      {error && <FormError message={error} />}
      {result && !result.verified && (
        <div className="mt-4 flex gap-3 rounded-lg border border-sev-medium/30 bg-sev-medium/10 p-4 text-sm">
          <Clock className="mt-0.5 size-4 shrink-0" />
          <div>
            <p className="font-medium">Eintrag noch nicht gefunden</p>
            <p className="text-muted-foreground">
              {result.found.length > 0 ? `Gefunden wurde: ${result.found.join(", ")} – bitte Wert prüfen.` : "Bitte warten Sie einige Minuten und prüfen Sie erneut. Sie können die Einrichtung auch später fortsetzen."}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export function AuthorizeStep({ domainId, hostname, orgName, defaultName }: { domainId: string; hostname: string; orgName: string; defaultName: string }) {
  const router = useRouter();
  const [state, action] = useActionState(async (prev: unknown, fd: FormData) => {
    const res = await grantAuthorizationAction(prev, fd);
    if (res.ok) router.refresh();
    return res;
  }, null);
  const fe = state && !state.ok ? state.fieldErrors : undefined;
  return (
    <div>
      <StepHeader title="Prüfungen freigeben" text={`Wir prüfen ${hostname} nur in dem Umfang, den Sie hier ausdrücklich erlauben. Sie können die Freigabe jederzeit widerrufen.`} />
      <form action={action} className="space-y-6">
        <input type="hidden" name="domainId" value={domainId} />
        <div className="space-y-3">
          {(["passive", "config"] as const).map((k) => (
            <label key={k} className="flex gap-3 rounded-xl border bg-card p-4 has-[:checked]:border-brand/40 has-[:checked]:bg-brand-soft/40">
              <Checkbox name={k === "passive" ? "scopePassive" : "scopeConfig"} defaultChecked className="mt-0.5" />
              <span>
                <span className="block text-sm font-medium">{SCOPE_DESCRIPTIONS[k].title}</span>
                <span className="block text-sm text-muted-foreground">{SCOPE_DESCRIPTIONS[k].text}</span>
              </span>
            </label>
          ))}
          <label className="flex gap-3 rounded-xl border bg-card p-4 has-[:checked]:border-brand/40 has-[:checked]:bg-brand-soft/40">
            <Checkbox name="includeSubdomains" defaultChecked className="mt-0.5" />
            <span>
              <span className="block text-sm font-medium">Subdomains einbeziehen</span>
              <span className="block text-sm text-muted-foreground">z. B. shop.{hostname} oder mail.{hostname} – werden passiv ermittelt und schonend geprüft.</span>
            </span>
          </label>
          <p className="text-xs text-muted-foreground">Aktive Schwachstellenprüfungen sind nicht Teil dieser Freigabe und erfordern eine gesonderte Freigabe je System.</p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="signerName">Ihr Name</Label>
            <Input id="signerName" name="signerName" defaultValue={defaultName} required />
            <FieldError message={fe?.signerName} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="signerRole">Ihre Funktion</Label>
            <Input id="signerRole" name="signerRole" placeholder="z. B. Geschäftsführer" required />
            <FieldError message={fe?.signerRole} />
          </div>
        </div>
        <label className="flex items-start gap-3 text-sm">
          <Checkbox name="confirm" className="mt-0.5" required />
          <span className="text-muted-foreground">
            Ich bestätige, dass ich berechtigt bin, für <span className="font-medium text-foreground">{orgName}</span> Sicherheitsprüfungen der Domain {hostname} zu beauftragen. Diese Erklärung wird mit Zeitstempel protokolliert.
          </span>
        </label>
        <FormError message={state && !state.ok && !fe?.signerName && !fe?.signerRole ? state.error : undefined} />
        <SubmitButton pendingText="Wird gespeichert …">
          <ShieldCheck /> Freigabe erteilen
        </SubmitButton>
      </form>
    </div>
  );
}

const MODULES = ["DNS & E-Mail-Sicherheit", "Subdomain-Erkennung", "TLS-Zertifikate", "Website-Konfiguration", "Offene Dienste", "Datenlecks"];

export function FirstScanStep({ domainId, hostname, existingJobId }: { domainId: string; hostname: string; existingJobId: string | null }) {
  const router = useRouter();
  const [jobId, setJobId] = useState<string | null>(existingJobId);
  const [status, setStatus] = useState<string>(existingJobId ? "queued" : "idle");
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [pending, start] = useTransition();

  useEffect(() => {
    if (!jobId || ["succeeded", "failed", "cancelled"].includes(status)) return;
    const t = setInterval(async () => {
      setElapsed((e) => e + 3);
      const res = await getScanJobStatusAction(jobId);
      if (res.ok && res.data) {
        setStatus(res.data.status);
        if (res.data.status === "failed") setError(res.data.error);
      }
    }, 3000);
    return () => clearInterval(t);
  }, [jobId, status]);

  const startScan = () =>
    start(async () => {
      const res = await requestScanAction(domainId, "onboarding");
      if (!res.ok) return setError(res.error);
      if (res.data?.jobId) {
        setJobId(res.data.jobId);
        setStatus("queued");
      }
    });

  if (status === "idle") {
    return (
      <div>
        <StepHeader title="Alles bereit für die erste Prüfung" text={`Wir prüfen jetzt ${hostname} mit allen freigegebenen und verfügbaren Modulen. Das dauert in der Regel 2–6 Minuten.`} />
        <Button size="lg" onClick={startScan} disabled={pending}>
          {pending ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Erste Prüfung starten
        </Button>
        {error && <div className="mt-4"><FormError message={error} /></div>}
      </div>
    );
  }
  const done = status === "succeeded";
  const failed = status === "failed" || status === "cancelled";
  return (
    <div>
      <StepHeader
        title={done ? "Erste Prüfung abgeschlossen" : failed ? "Prüfung nicht abgeschlossen" : "Prüfung läuft …"}
        text={done ? "Ihre Ergebnisse stehen im Dashboard bereit." : failed ? "Bitte versuchen Sie es erneut oder kontaktieren Sie uns." : `Sie können diese Seite verlassen – wir benachrichtigen Sie im Dashboard. Laufzeit: ${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, "0")} min`}
      />
      <ul className="space-y-2 rounded-xl border bg-card p-5">
        {MODULES.map((m) => (
          <li key={m} className="flex items-center gap-3 text-sm">
            {done ? <CheckCircle2 className="size-4 text-ok" /> : failed ? <XCircle className="size-4 text-muted-foreground" /> : <Loader2 className="size-4 animate-spin text-muted-foreground" />}
            {m}
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-muted-foreground">Module ohne Lizenz oder Zugang werden übersprungen und im Dashboard transparent ausgewiesen.</p>
      {error && <div className="mt-4"><FormError message={error} /></div>}
      <div className="mt-6 flex gap-3">
        {done && <Button onClick={() => router.push("/app")}>Ergebnisse ansehen</Button>}
        {failed && <Button onClick={() => { setStatus("idle"); setError(null); }}>Erneut versuchen</Button>}
        {!done && !failed && <Button variant="outline" onClick={() => router.push("/app")}>Zum Dashboard</Button>}
      </div>
    </div>
  );
}
