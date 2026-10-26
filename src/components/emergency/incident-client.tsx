"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Paperclip, Send } from "lucide-react";
import { toast } from "sonner";
import { addIncidentNoteAction, setIncidentStatusAction, uploadIncidentFileAction } from "@/app/actions/incidents";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";

export function Checklist({ incidentId, steps, done }: { incidentId: string; steps: string[]; done: string[] }) {
  const [checked, setChecked] = useState<string[]>(done);
  const [, start] = useTransition();
  const router = useRouter();
  return (
    <ol className="space-y-2">
      {steps.map((s) => (
        <li key={s}>
          <label className="flex items-start gap-3 text-sm">
            <Checkbox
              className="mt-0.5"
              checked={checked.includes(s)}
              disabled={checked.includes(s)}
              onCheckedChange={(v) => {
                if (!v) return;
                setChecked((c) => [...c, s]);
                start(async () => {
                  await addIncidentNoteAction(incidentId, `Erledigt: ${s}`, "checklist");
                  router.refresh();
                });
              }}
            />
            <span className={checked.includes(s) ? "text-muted-foreground line-through" : ""}>{s}</span>
          </label>
        </li>
      ))}
    </ol>
  );
}

export function NoteForm({ incidentId }: { incidentId: string }) {
  const [note, setNote] = useState("");
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <div className="space-y-2">
      <Textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Beobachtung oder Maßnahme dokumentieren …" />
      <Button size="sm" disabled={pending || !note.trim()} onClick={() => start(async () => { const r = await addIncidentNoteAction(incidentId, note); if (r.ok) { setNote(""); router.refresh(); } else toast.error(r.error); })}>
        {pending ? <Loader2 className="animate-spin" /> : <Send />} Eintrag hinzufügen
      </Button>
    </div>
  );
}

export function FileUpload({ incidentId, disabled }: { incidentId: string; disabled?: boolean }) {
  const ref = useRef<HTMLInputElement>(null);
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <div>
      <input
        ref={ref}
        type="file"
        className="hidden"
        accept=".pdf,.png,.jpg,.jpeg,.txt,.csv,.eml,.msg"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const fd = new FormData();
          fd.set("incidentId", incidentId);
          fd.set("file", f);
          start(async () => {
            const r = await uploadIncidentFileAction(fd);
            if (r.ok) toast.success(r.message ?? "Hochgeladen");
            else toast.error(r.error);
            if (ref.current) ref.current.value = "";
            router.refresh();
          });
        }}
      />
      <Button size="sm" variant="outline" disabled={pending || disabled} onClick={() => ref.current?.click()}>
        {pending ? <Loader2 className="animate-spin" /> : <Paperclip />} Datei hochladen (max. 4 MB)
      </Button>
    </div>
  );
}

export function StatusSelect({ incidentId, status }: { incidentId: string; status: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <select
      value={status}
      disabled={pending}
      onChange={(e) => start(async () => { await setIncidentStatusAction(incidentId, e.target.value as "open"); router.refresh(); })}
      className="h-8 rounded-md border bg-transparent px-2 text-sm"
      aria-label="Status"
    >
      <option value="open">Offen</option>
      <option value="in_progress">In Bearbeitung</option>
      <option value="contained">Eingedämmt</option>
      <option value="closed">Abgeschlossen</option>
    </select>
  );
}
