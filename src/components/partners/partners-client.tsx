"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Send, XCircle } from "lucide-react";
import { toast } from "sonner";
import { revokePartnerInviteAction } from "@/app/actions/partners";
import { ShareDialog } from "@/components/findings/finding-actions";
import { SeverityDot } from "@/components/shared/badges";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import type { Severity } from "@/lib/core/risk/types";

export function NewShare({ orgId, findings, isDemo }: { orgId: string; findings: Array<{ id: string; title: string; severity: Severity; asset_value: string }>; isDemo: boolean }) {
  const [selected, setSelected] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  if (findings.length === 0) return <p className="text-sm text-muted-foreground">Keine offenen Befunde zum Freigeben.</p>;
  return (
    <div className="space-y-3">
      <ul className="max-h-72 divide-y overflow-auto rounded-lg border">
        {findings.map((f) => (
          <li key={f.id}>
            <label className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-accent/50">
              <Checkbox checked={selected.includes(f.id)} onCheckedChange={(v) => setSelected((s) => (v ? [...s, f.id] : s.filter((x) => x !== f.id)))} />
              <SeverityDot severity={f.severity} />
              <span className="flex-1 truncate">{f.title}</span>
              <span className="hidden font-mono text-xs text-muted-foreground sm:inline">{f.asset_value}</span>
            </label>
          </li>
        ))}
      </ul>
      <Button disabled={selected.length === 0} onClick={() => setOpen(true)}>
        <Send /> {selected.length > 0 ? `${selected.length} Befund(e) freigeben` : "Befunde auswählen"}
      </Button>
      <ShareDialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setSelected([]); }} orgId={orgId} findingIds={selected} title="" isDemo={isDemo} />
    </div>
  );
}

export function RevokeInvite({ inviteId }: { inviteId: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Button size="sm" variant="ghost" className="text-destructive hover:text-destructive" disabled={pending} onClick={() => start(async () => { const r = await revokePartnerInviteAction(inviteId); if (r.ok) toast.success(r.message ?? "Widerrufen"); else toast.error(r.error); router.refresh(); })}>
      {pending ? <Loader2 className="animate-spin" /> : <XCircle />} Widerrufen
    </Button>
  );
}
