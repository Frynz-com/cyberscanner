"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2, Loader2, PlayCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { partnerUpdateAction } from "./actions";

export function PartnerControls({ token, findingId, status }: { token: string; findingId: string; status: string }) {
  const [note, setNote] = useState("");
  const [pending, start] = useTransition();
  const router = useRouter();
  const send = (s: "in_progress" | "fixed_pending_verification") =>
    start(async () => {
      const r = await partnerUpdateAction({ token, findingId, status: s, note });
      if (r.ok) {
        toast.success(r.message ?? "Gespeichert");
        setNote("");
      } else toast.error(r.error);
      router.refresh();
    });
  if (status === "verified") return <p className="flex items-center gap-2 text-sm text-ok"><CheckCircle2 className="size-4" /> Die Behebung wurde technisch bestätigt. Vielen Dank!</p>;
  return (
    <div className="space-y-3 rounded-lg border bg-muted/40 p-4">
      <Textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Optionaler Kommentar für Ihren Kunden (z. B. umgesetzte Maßnahme)" className="bg-background" />
      <div className="flex flex-wrap gap-2">
        {status === "open" && <Button variant="outline" disabled={pending} onClick={() => send("in_progress")}>{pending ? <Loader2 className="animate-spin" /> : <PlayCircle />} Bearbeitung gestartet</Button>}
        <Button disabled={pending || status === "fixed_pending_verification"} onClick={() => send("fixed_pending_verification")}>
          {pending ? <Loader2 className="animate-spin" /> : <CheckCircle2 />} {status === "fixed_pending_verification" ? "Nachprüfung läuft" : "Maßnahme umgesetzt – jetzt nachprüfen"}
        </Button>
      </div>
    </div>
  );
}
