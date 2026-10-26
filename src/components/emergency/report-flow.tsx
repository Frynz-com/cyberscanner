"use client";

import { useActionState, useState } from "react";
import { AlertOctagon, ArrowLeft, Ban, CheckCircle2, ChevronRight, Phone } from "lucide-react";
import { createIncidentAction } from "@/app/actions/incidents";
import { FieldError, FormError, SubmitButton } from "@/components/forms/submit-button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PLAYBOOKS, PUBLIC_CONTACTS, type IncidentType } from "@/lib/content/playbooks";
import { cn } from "@/lib/utils";

export function ReportFlow({ orgId, defaultName, hasPartner, expert }: { orgId: string; defaultName: string; hasPartner: boolean; expert: { name: string; phone: string | null; email: string | null; hours: string | null } | null }) {
  const [stage, setStage] = useState<"idle" | "choose" | "playbook">("idle");
  const [type, setType] = useState<IncidentType | null>(null);
  const [state, action] = useActionState(createIncidentAction, null);

  if (stage === "idle") {
    return (
      <button
        onClick={() => setStage("choose")}
        className="group flex w-full items-center justify-between gap-4 rounded-2xl bg-sev-critical px-6 py-6 text-left text-white shadow-lg shadow-sev-critical/20 transition hover:brightness-105 sm:px-8"
        data-testid="report-incident"
      >
        <span className="flex items-center gap-4">
          <AlertOctagon className="size-9 shrink-0" />
          <span>
            <span className="block text-xl font-semibold sm:text-2xl">Cybervorfall melden</span>
            <span className="block text-sm text-white/85">Sofortmaßnahmen erhalten, Vorfall dokumentieren und Beteiligte informieren</span>
          </span>
        </span>
        <ChevronRight className="size-6 transition group-hover:translate-x-1" />
      </button>
    );
  }
  if (stage === "choose" || !type) {
    return (
      <div className="space-y-4">
        <button onClick={() => setStage("idle")} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" /> Zurück</button>
        <h2 className="text-xl font-semibold">Was ist passiert?</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {Object.values(PLAYBOOKS).map((p) => (
            <button key={p.type} onClick={() => { setType(p.type); setStage("playbook"); }} className="rounded-xl border bg-card p-4 text-left transition hover:border-sev-critical/40 hover:bg-sev-critical/[0.03]">
              <span className="block font-medium">{p.title}</span>
              <span className="mt-1 block text-sm text-muted-foreground">{p.short}</span>
            </button>
          ))}
        </div>
      </div>
    );
  }
  const pb = PLAYBOOKS[type];
  const fe = state && !state.ok ? state.fieldErrors : undefined;
  return (
    <div className="space-y-6">
      <button onClick={() => setStage("choose")} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" /> Andere Kategorie wählen</button>
      <h2 className="text-2xl font-semibold">{pb.title}</h2>
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-sev-critical/25 bg-sev-critical/[0.03] p-5">
          <h3 className="mb-3 font-semibold text-sev-critical">Sofortmaßnahmen</h3>
          <ol className="space-y-2.5 text-sm">
            {pb.immediate.map((s, i) => (
              <li key={s} className="flex gap-3"><span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-sev-critical text-[11px] font-semibold text-white">{i + 1}</span>{s}</li>
            ))}
          </ol>
        </section>
        <div className="space-y-6">
          <section className="rounded-xl border bg-card p-5">
            <h3 className="mb-3 font-semibold">Bitte vermeiden</h3>
            <ul className="space-y-2 text-sm">{pb.avoid.map((s) => <li key={s} className="flex gap-2.5"><Ban className="mt-0.5 size-4 shrink-0 text-muted-foreground" />{s}</li>)}</ul>
          </section>
          <section className="rounded-xl border bg-card p-5">
            <h3 className="mb-3 font-semibold">Wichtige Kontakte</h3>
            <ul className="space-y-2.5 text-sm">
              {expert && (
                <li className="rounded-lg bg-brand-soft/60 p-3">
                  <p className="font-medium">{expert.name} <span className="text-xs font-normal text-muted-foreground">(vertraglich angebundener Experte)</span></p>
                  {expert.phone && <a href={`tel:${expert.phone}`} className="flex items-center gap-1.5 text-brand"><Phone className="size-3.5" />{expert.phone}</a>}
                  {expert.hours && <p className="text-xs text-muted-foreground">Erreichbarkeit: {expert.hours}</p>}
                </li>
              )}
              {PUBLIC_CONTACTS.map((c) => (
                <li key={c.name}><a href={c.url} target="_blank" rel="noreferrer" className="font-medium hover:underline">{c.name}</a><p className="text-xs text-muted-foreground">{c.detail}</p></li>
              ))}
            </ul>
          </section>
        </div>
      </div>

      <form action={action} className="space-y-4 rounded-xl border bg-card p-5">
        <h3 className="font-semibold">Vorfall dokumentieren</h3>
        <input type="hidden" name="orgId" value={orgId} />
        <input type="hidden" name="type" value={type} />
        <div className="space-y-2">
          <Label>Ist der Vorfall noch im Gange?</Label>
          <div className="flex flex-wrap gap-2">
            {[["yes", "Ja"], ["no", "Nein"], ["unknown", "Weiß nicht"]].map(([v, l]) => (
              <label key={v} className={cn("flex cursor-pointer items-center gap-2 rounded-md border px-3 py-1.5 text-sm has-[:checked]:border-foreground/40 has-[:checked]:bg-accent")}>
                <input type="radio" name="ongoing" value={v} defaultChecked={v === "unknown"} className="accent-current" /> {l}
              </label>
            ))}
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="description">Was ist passiert? <span className="text-muted-foreground">({pb.document.join(", ")})</span></Label>
          <Textarea id="description" name="description" rows={5} />
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2"><Label htmlFor="reporterName">Ihr Name</Label><Input id="reporterName" name="reporterName" defaultValue={defaultName} required /><FieldError message={fe?.reporterName} /></div>
          <div className="space-y-2"><Label htmlFor="reporterPhone">Rückrufnummer</Label><Input id="reporterPhone" name="reporterPhone" type="tel" /></div>
        </div>
        <div className="space-y-2 text-sm">
          {hasPartner && <label className="flex items-center gap-2"><Checkbox name="notifyPartner" defaultChecked /> Zuständigen IT-Partner per E-Mail informieren</label>}
          {expert && <label className="flex items-center gap-2"><Checkbox name="notifyExpert" /> {expert.name} informieren</label>}
          {pb.dataProtectionHint && <p className="text-xs text-muted-foreground">Hinweis: Sind personenbezogene Daten betroffen, kann eine Meldepflicht gegenüber der Datenschutzaufsicht binnen 72 Stunden bestehen (Art. 33 DSGVO).</p>}
        </div>
        <FormError message={state && !state.ok && !fe?.reporterName ? state.error : undefined} />
        <SubmitButton className="bg-sev-critical hover:bg-sev-critical/90" pendingText="Wird gemeldet …"><CheckCircle2 /> Vorfall melden</SubmitButton>
      </form>
    </div>
  );
}

