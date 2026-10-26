import { AlertTriangle, CheckCircle2, Clock, PauseCircle, ShieldAlert } from "lucide-react";
import type { MonitoringStatus } from "@/lib/core/monitoring-status";
import { relativeTime } from "@/lib/labels";
import { cn } from "@/lib/utils";

const STATE = {
  active: { icon: CheckCircle2, ring: "bg-ok", text: "text-ok", bg: "from-ok/[0.07]" },
  pending_first_scan: { icon: Clock, ring: "bg-sev-low", text: "text-sev-low", bg: "from-sev-low/[0.07]" },
  paused: { icon: PauseCircle, ring: "bg-sev-info", text: "text-muted-foreground", bg: "from-muted" },
  verification_required: { icon: ShieldAlert, ring: "bg-sev-medium", text: "text-[oklch(0.55_0.13_70)]", bg: "from-sev-medium/[0.09]" },
  scan_failed: { icon: AlertTriangle, ring: "bg-sev-critical", text: "text-sev-critical", bg: "from-sev-critical/[0.06]" },
} as const;

export function StatusHero({ status, lastScan, nextScan, actions }: { status: MonitoringStatus; lastScan: string | null; nextScan: string | null; actions?: React.ReactNode }) {
  const s = STATE[status.state];
  const Icon = s.icon;
  return (
    <section className={cn("relative overflow-hidden rounded-xl border bg-gradient-to-br to-card to-60% p-5 sm:p-6", s.bg)} data-testid="monitoring-status" data-state={status.state}>
      <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-4">
          <div className="relative mt-1 flex size-10 shrink-0 items-center justify-center rounded-full bg-card ring-1 ring-border">
            <Icon className={cn("size-5", s.text)} />
            {status.state === "active" && <span className={cn("absolute -top-0.5 -right-0.5 size-2.5 animate-pulse rounded-full ring-2 ring-card", s.ring)} />}
          </div>
          <div className="space-y-1">
            <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Überwachungsstatus</p>
            <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">{status.title}</h1>
            <p className="text-sm text-muted-foreground">{status.description}</p>
            <div className="flex flex-wrap gap-x-4 gap-y-1 pt-1 text-xs text-muted-foreground">
              <span>Letzte erfolgreiche Prüfung: <span className="font-medium text-foreground">{relativeTime(lastScan)}</span></span>
              {nextScan && status.state === "active" && <span>Nächste Prüfung: {new Date(nextScan).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short", timeZone: "Europe/Berlin" })}</span>}
              {status.integrationMissing && <span className="text-[oklch(0.55_0.13_70)]">· Nicht alle Datenquellen aktiv</span>}
            </div>
          </div>
        </div>
        {actions}
      </div>
    </section>
  );
}
