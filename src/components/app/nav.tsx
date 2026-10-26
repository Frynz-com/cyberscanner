"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { AlertOctagon, Bell, ClipboardList, FileText, Globe, History, LayoutDashboard, Network, Settings, Users } from "lucide-react";
import { cn } from "@/lib/utils";

export const NAV = [
  { href: "/app", label: "Übersicht", icon: LayoutDashboard, exact: true },
  { href: "/app/findings", label: "Befunde", icon: ClipboardList },
  { href: "/app/timeline", label: "Timeline", icon: History },
  { href: "/app/assets", label: "Assets", icon: Network },
  { href: "/app/domains", label: "Domains", icon: Globe },
  { href: "/app/partners", label: "IT-Dienstleister", icon: Users },
  { href: "/app/reports", label: "Berichte", icon: FileText },
  { href: "/app/notifications", label: "Benachrichtigungen", icon: Bell },
  { href: "/app/settings", label: "Einstellungen", icon: Settings },
];

export function SidebarNav({ unread, onNavigate }: { unread: number; onNavigate?: () => void }) {
  const path = usePathname();
  return (
    <nav className="flex flex-col gap-0.5">
      {NAV.map((item) => {
        const active = item.exact ? path === item.href : path.startsWith(item.href);
        const Icon = item.icon;
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            className={cn(
              "group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
              active ? "bg-background font-medium text-foreground shadow-xs ring-1 ring-border" : "text-muted-foreground hover:bg-accent hover:text-foreground",
            )}
          >
            <Icon className={cn("size-4", active ? "text-foreground" : "text-muted-foreground group-hover:text-foreground")} />
            <span className="flex-1">{item.label}</span>
            {item.href === "/app/notifications" && unread > 0 && (
              <span className="rounded-full bg-brand px-1.5 text-[11px] font-medium text-white tabular">{unread > 99 ? "99+" : unread}</span>
            )}
          </Link>
        );
      })}
      <Link
        href="/app/emergency"
        onClick={onNavigate}
        className={cn(
          "mt-3 flex items-center gap-2.5 rounded-md border border-sev-critical/20 bg-sev-critical/5 px-2.5 py-1.5 text-sm font-medium text-sev-critical hover:bg-sev-critical/10",
          path.startsWith("/app/emergency") && "ring-1 ring-sev-critical/30",
        )}
      >
        <AlertOctagon className="size-4" />
        Notfall melden
      </Link>
    </nav>
  );
}
