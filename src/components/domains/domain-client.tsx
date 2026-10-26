"use client";

import { useActionState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus, RefreshCw, ShieldOff, X } from "lucide-react";
import { toast } from "sonner";
import { addDomainAction, cancelScanAction, checkVerificationAction, renewChallengeAction, revokeAuthorizationAction, updateDomainSettingsAction } from "@/app/actions/domains";
import { FieldError, SubmitButton } from "@/components/forms/submit-button";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function AddDomainForm({ orgId }: { orgId: string }) {
  const router = useRouter();
  const [state, action] = useActionState(async (prev: unknown, fd: FormData) => {
    const res = await addDomainAction(prev, fd);
    if (res.ok) {
      toast.success("Domain hinzugefügt – bitte jetzt verifizieren");
      router.refresh();
    }
    return res;
  }, null);
  return (
    <form action={action} className="flex flex-col gap-2 sm:flex-row sm:items-start">
      <input type="hidden" name="orgId" value={orgId} />
      <div className="flex-1">
        <Input name="domain" placeholder="weitere-domain.de" required autoCapitalize="none" spellCheck={false} />
        <FieldError message={state && !state.ok ? state.error : undefined} />
      </div>
      <SubmitButton pendingText="Wird hinzugefügt …"><Plus /> Domain hinzufügen</SubmitButton>
    </form>
  );
}

export function VerifyButton({ domainId }: { domainId: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <div className="flex flex-wrap gap-2">
      <Button
        size="sm"
        disabled={pending}
        onClick={() =>
          start(async () => {
            const res = await checkVerificationAction(domainId);
            if (!res.ok) toast.error(res.error);
            else if (res.data?.verified) toast.success("Domain verifiziert");
            else toast.warning("Eintrag noch nicht gefunden", { description: "DNS-Änderungen können einige Minuten dauern." });
            router.refresh();
          })
        }
      >
        {pending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Eintrag prüfen
      </Button>
      <Button size="sm" variant="ghost" disabled={pending} onClick={() => start(async () => { const r = await renewChallengeAction(domainId); if (!r.ok) toast.error(r.error); router.refresh(); })}>
        Neuen Code erzeugen
      </Button>
    </div>
  );
}

export function RevokeAuthorizationButton({ domainId }: { domainId: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Button
      size="sm"
      variant="ghost"
      className="text-destructive hover:text-destructive"
      disabled={pending}
      onClick={() => {
        if (!confirm("Prüfberechtigung wirklich widerrufen? Danach finden keine Prüfungen mehr statt.")) return;
        start(async () => {
          const res = await revokeAuthorizationAction(domainId);
          if (res.ok) toast.success(res.message ?? "Widerrufen");
          else toast.error(res.error);
          router.refresh();
        });
      }}
    >
      <ShieldOff /> Freigabe widerrufen
    </Button>
  );
}

export function CancelJobButton({ jobId }: { jobId: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Button size="xs" variant="ghost" disabled={pending} onClick={() => start(async () => { const r = await cancelScanAction(jobId); if (r.ok) toast.success(r.message ?? "Abgebrochen"); else toast.error(r.error); router.refresh(); })}>
      {pending ? <Loader2 className="animate-spin" /> : <X />} Abbrechen
    </Button>
  );
}

export function DomainSettingsForm({ domainId, interval, enabled, minInterval }: { domainId: string; interval: number; enabled: boolean; minInterval: number }) {
  const [state, action] = useActionState(updateDomainSettingsAction, null);
  const options = [6, 12, 24, 48, 168, 336, 720].filter((h) => h >= minInterval);
  if (!options.includes(interval)) options.unshift(interval);
  return (
    <form action={action} className="flex flex-wrap items-end gap-3">
      <input type="hidden" name="domainId" value={domainId} />
      <label className="space-y-1 text-sm">
        <span className="block text-xs text-muted-foreground">Prüfintervall</span>
        <select name="intervalHours" defaultValue={interval} className="h-8 rounded-md border bg-transparent px-2 text-sm">
          {options.map((h) => <option key={h} value={h}>{h < 24 ? `alle ${h} Stunden` : h === 24 ? "täglich" : h === 168 ? "wöchentlich" : `alle ${Math.round(h / 24)} Tage`}</option>)}
        </select>
      </label>
      <label className="space-y-1 text-sm">
        <span className="block text-xs text-muted-foreground">Regelmäßige Prüfung</span>
        <select name="monitoringEnabled" defaultValue={enabled ? "on" : "off"} className="h-8 rounded-md border bg-transparent px-2 text-sm">
          <option value="on">Aktiv</option>
          <option value="off">Pausiert</option>
        </select>
      </label>
      <SubmitButton size="sm" variant="outline">Speichern</SubmitButton>
      {state && (state.ok ? <span className="text-xs text-ok">{state.message}</span> : <span className="text-xs text-destructive">{state.error}</span>)}
    </form>
  );
}

