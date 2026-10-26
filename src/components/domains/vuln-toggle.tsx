"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { setAssetVulnScanAction } from "@/app/actions/domains";
import { Switch } from "@/components/ui/switch";

export function VulnScanToggle({ assetId, approved, disabled }: { assetId: string; approved: boolean; disabled?: boolean }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Switch
      checked={approved}
      disabled={disabled || pending}
      aria-label="Aktive Schwachstellenprüfung freigeben"
      onCheckedChange={(v) => {
        if (v && !confirm("Aktive, nicht-destruktive Schwachstellenprüfung für dieses System freigeben? Bitte nur für Systeme, die Ihr Unternehmen selbst betreibt oder für die Sie berechtigt sind.")) return;
        start(async () => {
          const r = await setAssetVulnScanAction(assetId, v);
          if (!r.ok) toast.error(r.error);
          router.refresh();
        });
      }}
    />
  );
}
