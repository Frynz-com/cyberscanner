"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { FilePlus2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { createReportAction } from "@/app/actions/reports";
import { Button } from "@/components/ui/button";

export function CreateReportButton({ orgId }: { orgId: string }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  return (
    <Button
      disabled={pending}
      onClick={() =>
        start(async () => {
          const r = await createReportAction(orgId, 30);
          if (!r.ok) return void toast.error(r.error);
          toast.success("Bericht erstellt", { description: "Der Download startet." });
          router.refresh();
          window.location.href = `/api/reports/${r.data!.id}/pdf`;
        })
      }
    >
      {pending ? <Loader2 className="animate-spin" /> : <FilePlus2 />} Aktuellen Bericht erstellen (30 Tage)
    </Button>
  );
}
