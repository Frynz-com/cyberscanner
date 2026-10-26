import { cn } from "@/lib/utils";

export function Kpi({ label, value, hint, tone, testId }: { label: string; value: React.ReactNode; hint?: string; tone?: "danger" | "ok" | "default"; testId?: string }) {
  return (
    <div className="rounded-xl border bg-card p-4" data-testid={testId}>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={cn("mt-1.5 text-2xl font-semibold tracking-tight tabular", tone === "danger" && "text-sev-critical", tone === "ok" && "text-ok")}>{value}</p>
      {hint && <p className="mt-0.5 truncate text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
