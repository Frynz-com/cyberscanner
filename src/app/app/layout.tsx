import Link from "next/link";
import { FlaskConical } from "lucide-react";
import { Logo } from "@/components/brand/logo";
import { MobileNav } from "@/components/app/mobile-nav";
import { SidebarNav } from "@/components/app/nav";
import { UserMenu } from "@/components/app/user-menu";
import { createClient } from "@/lib/supabase/server";
import { requireOrg, requireUser } from "@/lib/server/auth";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const user = await requireUser();
  const ctx = await requireOrg();
  const supabase = await createClient();
  const { count: unread } = await supabase.from("notifications").select("id", { count: "exact", head: true }).eq("org_id", ctx.org.id).is("read_at", null);

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[240px_1fr]">
      <aside className="sticky top-0 hidden h-dvh flex-col border-r bg-sidebar px-3 py-4 lg:flex">
        <Link href="/app" className="mb-6 px-2"><Logo /></Link>
        <div className="mb-4 rounded-md border bg-background px-2.5 py-2">
          <p className="text-[11px] tracking-wide text-muted-foreground uppercase">Organisation</p>
          <p className="truncate text-sm font-medium">{ctx.org.name}</p>
        </div>
        <SidebarNav unread={unread ?? 0} />
        <div className="mt-auto px-2 text-[11px] text-muted-foreground">
          Datenquellen u. a. <a href="https://haveibeenpwned.com" className="underline" target="_blank" rel="noreferrer">Have I Been Pwned</a> (CC BY 4.0)
        </div>
      </aside>
      <div className="min-w-0">
        {ctx.org.is_demo && (
          <div className="flex items-center justify-center gap-2 bg-violet-600 px-4 py-1.5 text-center text-xs font-medium text-white">
            <FlaskConical className="size-3.5" />
            DEMO-MODUS – alle Daten sind synthetisch und dienen nur der Vorführung. Es werden keine echten Systeme geprüft.
          </div>
        )}
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b bg-background/85 px-4 backdrop-blur sm:px-6">
          <MobileNav unread={unread ?? 0} />
          <span className="truncate text-sm font-medium lg:hidden">{ctx.org.name}</span>
          <div className="ml-auto flex items-center gap-3">
            <UserMenu email={user.email ?? ""} orgs={ctx.memberships} currentOrgId={ctx.org.id} />
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:py-8">{children}</main>
      </div>
    </div>
  );
}
