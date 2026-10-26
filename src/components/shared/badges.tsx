import { CERTAINTY, SEVERITY, STATUS } from "@/lib/labels";
import type { Certainty, FindingStatus, Severity } from "@/lib/core/risk/types";
import { cn } from "@/lib/utils";

const pill = "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset whitespace-nowrap";

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = SEVERITY[severity];
  return (
    <span className={cn(pill, s.soft, className)}>
      <span className={cn("size-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  );
}

export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return <span className={cn("inline-block size-2 shrink-0 rounded-full", SEVERITY[severity].dot, className)} aria-label={SEVERITY[severity].label} />;
}

export function StatusBadge({ status, className }: { status: FindingStatus; className?: string }) {
  return <span className={cn(pill, STATUS[status].tone, className)}>{STATUS[status].label}</span>;
}

export function CertaintyBadge({ certainty, className }: { certainty: Certainty; className?: string }) {
  const tone =
    certainty === "confirmed"
      ? "bg-primary/5 text-foreground ring-border"
      : certainty === "potential"
        ? "bg-sev-medium/10 text-[oklch(0.5_0.12_70)] ring-sev-medium/25"
        : "bg-muted text-muted-foreground ring-border";
  return (
    <span className={cn(pill, tone, className)} title={CERTAINTY[certainty].hint}>
      {CERTAINTY[certainty].label}
    </span>
  );
}

export function DemoBadge({ className }: { className?: string }) {
  return <span className={cn(pill, "bg-violet-500/10 text-violet-700 ring-violet-500/25 dark:text-violet-300", className)}>DEMO</span>;
}
