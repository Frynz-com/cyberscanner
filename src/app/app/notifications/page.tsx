import type { Metadata } from "next";
import Link from "next/link";
import { BellOff } from "lucide-react";
import { MarkReadButton } from "@/components/app/mark-read";
import { PageHeader } from "@/components/shared/page-header";
import { formatDate } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";
import { cn } from "@/lib/utils";

export const metadata: Metadata = { title: "Benachrichtigungen" };

const EMAIL: Record<string, string> = { sent: "per E-Mail gesendet", pending: "E-Mail ausstehend", skipped: "nur in der App", failed: "E-Mail fehlgeschlagen", suppressed: "E-Mail-Limit erreicht" };
const TONE: Record<string, string> = { critical: "bg-sev-critical", warning: "bg-sev-high", info: "bg-sev-low", success: "bg-ok" };

export default async function NotificationsPage() {
  const ctx = await requireOrg();
  const supabase = await createClient();
  const { data } = await supabase.from("notifications").select("*").eq("org_id", ctx.org.id).order("created_at", { ascending: false }).limit(200);
  const unread = (data ?? []).filter((n) => !n.read_at).length;
  return (
    <div className="space-y-6">
      <PageHeader title="Benachrichtigungen" description="Wichtige Ereignisse werden zusätzlich per E-Mail an Inhaber, Administratoren und die Sicherheitskontaktadresse gesendet (max. 10 pro Tag)." actions={unread > 0 ? <MarkReadButton orgId={ctx.org.id} /> : undefined} />
      {(data ?? []).length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-16 text-center">
          <BellOff className="size-6 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">Keine Benachrichtigungen.</p>
        </div>
      ) : (
        <ul className="divide-y rounded-xl border bg-card">
          {data!.map((n) => (
            <li key={n.id} className={cn("flex gap-3 p-4", !n.read_at && "bg-brand-soft/30")}>
              <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", TONE[n.severity])} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <p className="text-sm font-medium">{n.link ? <Link href={n.link} className="hover:underline">{n.title}</Link> : n.title}</p>
                  <span className="text-xs text-muted-foreground">{formatDate(n.created_at, true)}</span>
                </div>
                <p className="mt-1 text-sm whitespace-pre-line text-muted-foreground">{n.body}</p>
                <p className="mt-1 text-xs text-muted-foreground">{EMAIL[n.email_status]}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
