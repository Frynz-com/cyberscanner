import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, FileText } from "lucide-react";
import { Checklist, FileUpload, NoteForm, StatusSelect } from "@/components/emergency/incident-client";
import { PLAYBOOKS, PUBLIC_CONTACTS, type IncidentType } from "@/lib/content/playbooks";
import { formatDate } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Vorfall" };
const PRIO: Record<string, { label: string; tone: string }> = { p1: { label: "Kritisch", tone: "bg-sev-critical text-white" }, p2: { label: "Hoch", tone: "bg-sev-high text-white" }, p3: { label: "Normal", tone: "bg-muted" } };

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const ctx = await requireOrg();
  const supabase = await createClient();
  const { data: inc } = await supabase.from("incidents").select("*").eq("id", id).eq("org_id", ctx.org.id).maybeSingle();
  if (!inc) notFound();
  const [{ data: events }, { data: files }] = await Promise.all([
    supabase.from("incident_events").select("*").eq("incident_id", inc.id).order("created_at"),
    supabase.from("incident_files").select("id, file_name, size_bytes, created_at").eq("incident_id", inc.id).order("created_at"),
  ]);
  const pb = PLAYBOOKS[inc.type as IncidentType];
  const done = (events ?? []).filter((e) => e.type === "checklist").map((e) => (e.message ?? "").replace(/^Erledigt: /, ""));
  const canEdit = ctx.rank >= 50;

  return (
    <div className="space-y-6">
      <Link href="/app/emergency" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" /> Emergency Desk</Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-2">
          <span className={`rounded px-2 py-0.5 text-xs font-semibold ${PRIO[inc.priority].tone}`}>Priorität {PRIO[inc.priority].label}</span>
          <h1 className="text-2xl font-semibold tracking-tight">{pb?.title ?? inc.title}</h1>
          <p className="text-sm text-muted-foreground">Gemeldet am {formatDate(inc.created_at, true)} von {inc.reporter_name}{inc.reporter_phone && ` · Rückruf: ${inc.reporter_phone}`}{inc.assigned_contact && ` · Ansprechpartner: ${inc.assigned_contact}`}</p>
        </div>
        {canEdit && <StatusSelect incidentId={inc.id} status={inc.status} />}
      </div>
      {inc.description && <p className="rounded-xl border bg-card p-5 text-sm whitespace-pre-line">{inc.description}</p>}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {pb && (
            <section className="rounded-xl border bg-card p-5">
              <h2 className="mb-3 font-semibold">Sofortmaßnahmen abhaken</h2>
              {canEdit ? <Checklist incidentId={inc.id} steps={pb.immediate} done={done} /> : <ol className="list-decimal space-y-1 pl-5 text-sm">{pb.immediate.map((s) => <li key={s}>{s}</li>)}</ol>}
            </section>
          )}
          <section className="rounded-xl border bg-card p-5">
            <h2 className="mb-4 font-semibold">Vorfall-Timeline</h2>
            <ol className="space-y-3">
              {(events ?? []).map((e) => (
                <li key={e.id} className="flex gap-3 text-sm">
                  <span className="w-28 shrink-0 text-xs text-muted-foreground tabular">{formatDate(e.created_at, true)}</span>
                  <span className="min-w-0"><span className="whitespace-pre-line">{e.message}</span>{e.actor_label && <span className="text-xs text-muted-foreground"> · {e.actor_label}</span>}</span>
                </li>
              ))}
            </ol>
            {canEdit && <div className="mt-5 border-t pt-5"><NoteForm incidentId={inc.id} /></div>}
          </section>
        </div>
        <aside className="space-y-6">
          <section className="rounded-xl border bg-card p-5">
            <h2 className="mb-3 font-semibold">Dateien & Beweise</h2>
            <ul className="mb-3 space-y-1.5 text-sm">
              {(files ?? []).map((f) => (
                <li key={f.id}><a href={`/api/incidents/files/${f.id}`} className="flex items-center gap-2 hover:underline"><FileText className="size-3.5 text-muted-foreground" /><span className="truncate">{f.file_name}</span><span className="ml-auto text-xs text-muted-foreground">{Math.ceil(f.size_bytes / 1024)} KB</span></a></li>
              ))}
              {(files ?? []).length === 0 && <li className="text-muted-foreground">Noch keine Dateien.</li>}
            </ul>
            {canEdit && <FileUpload incidentId={inc.id} disabled={ctx.org.is_demo} />}
            <p className="mt-2 text-xs text-muted-foreground">Dateien liegen in einem privaten, zugriffsgeschützten Speicher; Downloads nur über kurzlebige Links.</p>
          </section>
          <section className="rounded-xl border bg-card p-5">
            <h2 className="mb-3 font-semibold">Kontakte</h2>
            <ul className="space-y-2 text-sm">{PUBLIC_CONTACTS.map((c) => <li key={c.name}><a href={c.url} target="_blank" rel="noreferrer" className="hover:underline">{c.name}</a></li>)}</ul>
          </section>
        </aside>
      </div>
    </div>
  );
}
