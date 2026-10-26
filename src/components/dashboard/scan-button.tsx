"use client";

import { Loader2, Play } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { toast } from "sonner";
import { requestScanAction } from "@/app/actions/domains";
import { Button } from "@/components/ui/button";

export function ScanButton({ domainId, disabled, label = "Prüfung starten", variant = "default", size = "default" }: { domainId: string; disabled?: boolean; label?: string; variant?: "default" | "outline"; size?: "default" | "sm" }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Button
      variant={variant}
      size={size}
      disabled={disabled || pending}
      onClick={() =>
        start(async () => {
          const res = await requestScanAction(domainId);
          if (res.ok) toast.success(res.message ?? "Prüfung gestartet", { description: "Ergebnisse erscheinen nach Abschluss automatisch." });
          else toast.error(res.error);
          router.refresh();
        })
      }
    >
      {pending ? <Loader2 className="animate-spin" /> : <Play />}
      {label}
    </Button>
  );
}
