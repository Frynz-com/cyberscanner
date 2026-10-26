import { cn } from "@/lib/utils";

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden className={cn("size-7", className)}>
      <rect width="32" height="32" rx="8" className="fill-primary" />
      <path d="M16 6.5l7.5 3v6.2c0 4.6-3.1 8.4-7.5 9.8-4.4-1.4-7.5-5.2-7.5-9.8V9.5l7.5-3z" className="fill-none stroke-primary-foreground" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M12.6 15.8l2.4 2.4 4.6-4.8" className="fill-none stroke-brand" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("flex items-center gap-2.5", className)}>
      <LogoMark />
      <span className="flex flex-col leading-none">
        <span className="text-[15px] font-semibold tracking-tight">CyberSafe24</span>
        <span className="text-[11px] font-medium tracking-wide text-muted-foreground uppercase">Shield</span>
      </span>
    </span>
  );
}
