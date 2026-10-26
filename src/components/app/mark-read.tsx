"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { CheckCheck } from "lucide-react";
import { markNotificationsReadAction } from "@/app/actions/org";
import { Button } from "@/components/ui/button";

export function MarkReadButton({ orgId }: { orgId: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Button variant="outline" size="sm" disabled={pending} onClick={() => start(async () => { await markNotificationsReadAction(orgId); router.refresh(); })}>
      <CheckCheck /> Alle als gelesen markieren
    </Button>
  );
}
