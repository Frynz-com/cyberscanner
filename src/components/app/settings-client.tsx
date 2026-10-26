"use client";

import { useActionState, useTransition } from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { openBillingPortalAction, startCheckoutAction } from "@/app/actions/billing";
import { deleteOrganizationAction, setMonitoringPausedAction, updateOrganizationAction } from "@/app/actions/org";
import { FormError, SubmitButton } from "@/components/forms/submit-button";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";

type Org = { id: string; name: string; industry: string | null; employee_range: string | null; contact_email: string | null; contact_phone: string | null; data_retention_days: number; monitoring_paused: boolean };

export function OrgForm({ org, disabled }: { org: Org; disabled: boolean }) {
  const [state, action] = useActionState(updateOrganizationAction, null);
  return (
    <form action={action} className="grid gap-4 sm:grid-cols-2">
      <input type="hidden" name="orgId" value={org.id} />
      <div className="space-y-2 sm:col-span-2"><Label htmlFor="name">Firmenname</Label><Input id="name" name="name" defaultValue={org.name} disabled={disabled} /></div>
      <div className="space-y-2"><Label htmlFor="industry">Branche</Label><Input id="industry" name="industry" defaultValue={org.industry ?? ""} disabled={disabled} /></div>
      <div className="space-y-2">
        <Label htmlFor="employeeRange">Mitarbeitende</Label>
        <select id="employeeRange" name="employeeRange" defaultValue={org.employee_range ?? ""} disabled={disabled} className="h-9 w-full rounded-md border bg-transparent px-3 text-sm">
          <option value="">–</option>{["1-9", "10-49", "50-249", "250-999", "1000+"].map((r) => <option key={r}>{r}</option>)}
        </select>
      </div>
      <div className="space-y-2"><Label htmlFor="contactEmail">E-Mail für Sicherheitswarnungen</Label><Input id="contactEmail" name="contactEmail" type="email" defaultValue={org.contact_email ?? ""} disabled={disabled} /></div>
      <div className="space-y-2"><Label htmlFor="contactPhone">Telefon (Notfall)</Label><Input id="contactPhone" name="contactPhone" defaultValue={org.contact_phone ?? ""} disabled={disabled} /></div>
      <div className="space-y-2">
        <Label htmlFor="retentionDays">Aufbewahrung von Datenleck-Details</Label>
        <select id="retentionDays" name="retentionDays" defaultValue={org.data_retention_days} disabled={disabled} className="h-9 w-full rounded-md border bg-transparent px-3 text-sm">
          {[90, 180, 365, 730].map((d) => <option key={d} value={d}>{d} Tage</option>)}
        </select>
      </div>
      <div className="flex items-end gap-3 sm:col-span-2">
        {!disabled && <SubmitButton>Speichern</SubmitButton>}
        {state && (state.ok ? <span className="text-sm text-ok">{state.message}</span> : <FormError message={state.error} />)}
      </div>
    </form>
  );
}

export function PauseToggle({ orgId, paused, disabled }: { orgId: string; paused: boolean; disabled: boolean }) {
  const [pending, start] = useTransition();
  return (
    <label className="flex items-center gap-3 text-sm">
      <Switch checked={!paused} disabled={disabled || pending} onCheckedChange={(v) => start(async () => { const r = await setMonitoringPausedAction(orgId, !v); if (!r.ok) toast.error(r.error); })} />
      Regelmäßige Überwachung {paused ? "pausiert" : "aktiv"}
    </label>
  );
}

export function PlanButton({ orgId, planKey, label, disabled }: { orgId: string; planKey: string; label: string; disabled?: boolean }) {
  const [pending, start] = useTransition();
  return (
    <Button className="w-full" disabled={disabled || pending} onClick={() => start(async () => { const r = await startCheckoutAction(orgId, planKey); if (r && !r.ok) toast.error(r.error); })}>
      {pending && <Loader2 className="animate-spin" />} {label}
    </Button>
  );
}

export function PortalButton({ orgId }: { orgId: string }) {
  const [pending, start] = useTransition();
  return (
    <Button variant="outline" disabled={pending} onClick={() => start(async () => { const r = await openBillingPortalAction(orgId); if (r && !r.ok) toast.error(r.error); })}>
      {pending && <Loader2 className="animate-spin" />} Rechnungen & Zahlungsdaten verwalten
    </Button>
  );
}

export function DeleteOrgForm({ orgId, name }: { orgId: string; name: string }) {
  const [state, action] = useActionState(deleteOrganizationAction, null);
  return (
    <form action={action} className="space-y-3">
      <input type="hidden" name="orgId" value={orgId} />
      <p className="text-sm text-muted-foreground">Alle Domains, Befunde, Berichte und Vorfälle werden nach 30 Tagen endgültig gelöscht. Laufende Prüfungen werden sofort beendet. Zur Bestätigung geben Sie bitte „{name}“ ein.</p>
      <Input name="confirm" placeholder={name} />
      <FormError message={state && !state.ok ? state.error : undefined} />
      <SubmitButton variant="outline" className="border-destructive/40 text-destructive">Organisation löschen</SubmitButton>
    </form>
  );
}
