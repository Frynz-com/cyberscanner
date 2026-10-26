"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { adminRetryJobAction, adminSetOrgPausedAction } from "@/app/actions/admin";
import { Button } from "@/components/ui/button";

export function RetryJob({ id }: { id: string }) {
  const [p, start] = useTransition();
  const r = useRouter();
  return <Button size="xs" variant="outline" disabled={p} onClick={() => start(async () => { const x = await adminRetryJobAction(id); if (x.ok) toast.success(x.message ?? "OK"); else toast.error(x.error); r.refresh(); })}>Erneut</Button>;
}

export function PauseOrg({ id, paused }: { id: string; paused: boolean }) {
  const [p, start] = useTransition();
  const r = useRouter();
  return <Button size="xs" variant="ghost" disabled={p} onClick={() => start(async () => { await adminSetOrgPausedAction(id, !paused); r.refresh(); })}>{paused ? "Fortsetzen" : "Pausieren"}</Button>;
}
