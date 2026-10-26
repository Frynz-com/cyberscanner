import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

export function OnboardingSteps({ steps, current }: { steps: string[]; current: number }) {
  const pct = Math.round(((current - 1) / (steps.length - 1)) * 100);
  return (
    <div>
      <div className="mb-3 flex items-center justify-between text-xs text-muted-foreground">
        <span>Schritt {current} von {steps.length}</span>
        <span>{steps[current - 1]}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full rounded-full bg-brand transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
      <ol className="mt-4 hidden justify-between sm:flex">
        {steps.map((s, i) => {
          const n = i + 1;
          const done = n < current;
          return (
            <li key={s} className={cn("flex items-center gap-1.5 text-xs", n === current ? "font-medium text-foreground" : "text-muted-foreground")}>
              <span className={cn("flex size-4 items-center justify-center rounded-full border text-[10px]", done && "border-brand bg-brand text-white", n === current && "border-foreground")}>
                {done ? <Check className="size-2.5" /> : n}
              </span>
              {s}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
