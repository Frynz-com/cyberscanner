"use client";

import { Building2, Check, LogOut, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { logoutAction } from "@/app/actions/auth";
import { switchOrganizationAction } from "@/app/actions/org";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export function UserMenu({ email, orgs, currentOrgId }: { email: string; orgs: Array<{ org_id: string; name: string; is_demo: boolean }>; currentOrgId: string }) {
  const { theme, setTheme } = useTheme();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="Benutzermenü">
        <Avatar className="size-8">
          <AvatarFallback className="bg-primary text-xs text-primary-foreground">{email.slice(0, 2).toUpperCase()}</AvatarFallback>
        </Avatar>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="font-normal">
          <p className="text-xs text-muted-foreground">Angemeldet als</p>
          <p className="truncate text-sm font-medium">{email}</p>
        </DropdownMenuLabel>
        {orgs.length > 1 && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className="text-xs text-muted-foreground">Organisation wechseln</DropdownMenuLabel>
            {orgs.map((o) => (
              <DropdownMenuItem key={o.org_id} onSelect={() => switchOrganizationAction(o.org_id)}>
                <Building2 /> <span className="flex-1 truncate">{o.name}{o.is_demo ? " (Demo)" : ""}</span>
                {o.org_id === currentOrgId && <Check />}
              </DropdownMenuItem>
            ))}
          </>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? <Sun /> : <Moon />} {theme === "dark" ? "Helles Design" : "Dunkles Design"}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => logoutAction()}>
          <LogOut /> Abmelden
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
