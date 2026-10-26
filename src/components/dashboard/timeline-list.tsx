import Link from "next/link";
import { AlertTriangle, CheckCircle2, FileText, Globe, History, Network, Send, ShieldAlert, ShieldCheck, Siren, UserCheck, Workflow } from "lucide-react";
import { formatDate, relativeTime } from "@/lib/labels";
import { cn } from "@/lib/utils";

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  scan_completed: ShieldCheck,
  scan_failed: AlertTriangle,
  asset_discovered: Network,
  finding_detected: ShieldAlert,
  finding_reappeared: ShieldAlert,
  breach_detected: ShieldAlert,
  shared_with_partner: Send,
  partner_update: UserCheck,
  status_changed: Workflow,
  reverify_passed: CheckCircle2,
  reverify_failed: AlertTriangle,
  report_created: FileText,
  incident_reported: Siren,
  domain_verified: Globe,
  domain_added: Globe,
  authorization_granted: ShieldCheck,
  monitoring_changed: History,
};

const TONE: Record<string, string> = {
  critical: "bg-sev-critical/10 text-sev-critical",
  high: "bg-sev-high/10 text-sev-high",
  medium: "bg-sev-medium/15 text-[oklch(0.5_0.12_70)]",
  low: "bg-sev-low/10 text-sev-low",
  info: "bg-muted text-muted-foreground",
  success: "bg-ok/10 text-ok",
};

export interface TimelineItem {
  id: string;
  type: string;
  severity: string;
  title: string;
  body: string | null;
  link: string | null;
  created_at: string;
}

export function TimelineList({ items, dense }: { items: TimelineItem[]; dense?: boolean }) {
  if (items.length === 0) {
    return <p className="py-6 text-center text-sm text-muted-foreground">Noch keine Ereignisse. Nach der ersten Prüfung erscheinen hier alle Aktivitäten.</p>;
  }
  return (
    <ol className="relative">
      {items.map((e, i) => {
        const Icon = ICONS[e.type] ?? History;
        const content = (
          <div className="min-w-0 flex-1 pb-5">
            <div className="flex items-baseline justify-between gap-3">
              <p className="truncate text-sm font-medium">{e.title}</p>
              <time className="shrink-0 text-xs text-muted-foreground tabular" title={formatDate(e.created_at, true)}>{relativeTime(e.created_at)}</time>
            </div>
            {e.body && !dense && <p className="mt-0.5 line-clamp-2 text-sm text-muted-foreground">{e.body}</p>}
          </div>
        );
        return (
          <li key={e.id} className="relative flex gap-3">
            {i < items.length - 1 && <span className="absolute top-8 bottom-0 left-[13px] w-px bg-border" />}
            <span className={cn("relative z-10 flex size-7 shrink-0 items-center justify-center rounded-full", TONE[e.severity] ?? TONE.info)}>
              <Icon className="size-3.5" />
            </span>
            {e.link ? <Link href={e.link} className="min-w-0 flex-1 rounded hover:opacity-80">{content}</Link> : content}
          </li>
        );
      })}
    </ol>
  );
}
