import { formatDate } from "@/lib/labels";
import { cn } from "@/lib/utils";

const LABEL: Record<string, string> = {
  detected: "Risiko erkannt",
  seen_again: "Erneut beobachtet",
  reappeared: "Erneut aufgetreten",
  status_changed: "Status geändert",
  shared_with_partner: "IT informiert",
  partner_update: "Rückmeldung IT-Dienstleister",
  reverify_requested: "Nachprüfung angefordert",
  verified_fixed: "Behebung bestätigt",
  still_present: "Weiterhin vorhanden",
  comment: "Kommentar",
  severity_changed: "Schweregrad geändert",
  auto_resolved: "Automatisch geschlossen",
};

const DOT: Record<string, string> = {
  detected: "bg-sev-high",
  reappeared: "bg-sev-high",
  still_present: "bg-sev-high",
  verified_fixed: "bg-ok",
  shared_with_partner: "bg-brand",
  partner_update: "bg-brand",
};

export function FindingEvents({ events }: { events: Array<{ id: string; type: string; message: string | null; actor_label: string | null; actor_type: string; created_at: string }> }) {
  return (
    <ol className="space-y-4" data-testid="finding-events">
      {events.map((e, i) => (
        <li key={e.id} className="relative flex gap-3">
          {i < events.length - 1 && <span className="absolute top-3 -bottom-4 left-[3.5px] w-px bg-border" />}
          <span className={cn("relative mt-1.5 size-2 shrink-0 rounded-full", DOT[e.type] ?? "bg-sev-info")} />
          <div className="min-w-0 text-sm">
            <p className="font-medium">{LABEL[e.type] ?? e.type}</p>
            {e.message && <p className="text-muted-foreground">{e.message}</p>}
            <p className="text-xs text-muted-foreground">
              {formatDate(e.created_at, true)} · {e.actor_type === "system" ? "System" : e.actor_type === "partner" ? "IT-Dienstleister" : (e.actor_label ?? "Nutzer")}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}
