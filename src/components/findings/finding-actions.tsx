"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { CheckCircle2, ChevronDown, Copy, Loader2, RefreshCw, Send } from "lucide-react";
import { toast } from "sonner";
import { requestReverifyAction, setFindingStatusAction } from "@/app/actions/findings";
import { invitePartnerAction } from "@/app/actions/partners";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { FindingStatus } from "@/lib/core/risk/types";

export function FindingActions({ finding, orgId, canManage, canShare, isDemo }: { finding: { id: string; status: FindingStatus; title: string }; orgId: string; canManage: boolean; canShare: boolean; isDemo: boolean }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [shareOpen, setShareOpen] = useState(false);
  const [reasonFor, setReasonFor] = useState<null | "accepted_risk" | "false_positive">(null);
  const closed = ["resolved", "accepted_risk", "false_positive"].includes(finding.status);

  const setStatus = (status: FindingStatus, note?: string) =>
    start(async () => {
      const res = await setFindingStatusAction({ findingId: finding.id, status, note });
      if (res.ok) toast.success(res.message ?? "Gespeichert");
      else toast.error(res.error);
      setReasonFor(null);
      router.refresh();
    });

  if (!canManage) return null;
  return (
    <div className="flex flex-wrap gap-2" data-testid="finding-actions">
      {canShare && (
        <Button onClick={() => setShareOpen(true)} disabled={pending}>
          <Send /> An IT-Dienstleister senden
        </Button>
      )}
      {!closed && (
        <Button variant="outline" onClick={() => setStatus("resolved")} disabled={pending}>
          {pending ? <Loader2 className="animate-spin" /> : <CheckCircle2 />} Als behoben markieren
        </Button>
      )}
      <Button
        variant="outline"
        disabled={pending}
        onClick={() =>
          start(async () => {
            const res = await requestReverifyAction(finding.id);
            if (res.ok) toast.success(res.message ?? "Nachprüfung gestartet");
            else toast.error(res.error);
            router.refresh();
          })
        }
      >
        <RefreshCw /> Erneut überprüfen
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" disabled={pending}>Status <ChevronDown /></Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          {finding.status !== "investigating" && <DropdownMenuItem onSelect={() => setStatus("investigating")}>In Prüfung</DropdownMenuItem>}
          {finding.status !== "action_required" && <DropdownMenuItem onSelect={() => setStatus("action_required")}>Handlungsbedarf</DropdownMenuItem>}
          <DropdownMenuItem onSelect={() => setReasonFor("accepted_risk")}>Risiko akzeptieren …</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setReasonFor("false_positive")}>Als Fehlalarm markieren …</DropdownMenuItem>
          {closed && <DropdownMenuItem onSelect={() => setStatus("action_required")}>Wieder öffnen</DropdownMenuItem>}
        </DropdownMenuContent>
      </DropdownMenu>

      <ReasonDialog open={reasonFor !== null} kind={reasonFor} onClose={() => setReasonFor(null)} onSubmit={(note) => reasonFor && setStatus(reasonFor, note)} pending={pending} />
      <ShareDialog open={shareOpen} onOpenChange={setShareOpen} orgId={orgId} findingIds={[finding.id]} title={finding.title} isDemo={isDemo} />
    </div>
  );
}

function ReasonDialog({ open, kind, onClose, onSubmit, pending }: { open: boolean; kind: null | "accepted_risk" | "false_positive"; onClose: () => void; onSubmit: (note: string) => void; pending: boolean }) {
  const [note, setNote] = useState("");
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{kind === "accepted_risk" ? "Risiko bewusst akzeptieren" : "Als Fehlalarm markieren"}</DialogTitle>
          <DialogDescription>Bitte begründen Sie die Entscheidung kurz. Die Begründung wird mit Zeitstempel dokumentiert.</DialogDescription>
        </DialogHeader>
        <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="z. B. Subdomain wird von einem Dienstleister betrieben und ist bekannt." rows={4} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Abbrechen</Button>
          <Button onClick={() => onSubmit(note)} disabled={pending || note.trim().length < 5}>{pending && <Loader2 className="animate-spin" />} Speichern</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ShareDialog({ open, onOpenChange, orgId, findingIds, title, isDemo }: { open: boolean; onOpenChange: (o: boolean) => void; orgId: string; findingIds: string[]; title: string; isDemo: boolean }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [link, setLink] = useState<string | null>(null);
  const [emailSent, setEmailSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = (fd: FormData) =>
    start(async () => {
      setError(null);
      const res = await invitePartnerAction({
        orgId,
        email: String(fd.get("email") ?? ""),
        companyName: String(fd.get("companyName") ?? ""),
        contactName: String(fd.get("contactName") ?? ""),
        validDays: Number(fd.get("validDays") ?? 14),
        message: String(fd.get("message") ?? ""),
        findingIds,
      });
      if (!res.ok) return setError(res.error);
      setLink(res.data?.link ?? null);
      setEmailSent(Boolean(res.data?.emailSent));
      router.refresh();
    });
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (!o) setLink(null);
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>An IT-Dienstleister senden</DialogTitle>
          <DialogDescription>
            Ihr Dienstleister erhält einen zeitlich begrenzten Link mit technischen Details – nur zu {findingIds.length === 1 ? `„${title}“` : `${findingIds.length} ausgewählten Befunden`}. Kein Zugriff auf Ihr Konto.
          </DialogDescription>
        </DialogHeader>
        {link ? (
          <div className="space-y-3">
            <p className="text-sm">{emailSent ? "Die Einladung wurde per E-Mail versendet." : isDemo ? "Demo: Es wurde keine E-Mail versendet." : "Der E-Mail-Versand ist nicht konfiguriert. Bitte senden Sie den Link selbst."}</p>
            <div className="flex gap-2">
              <Input readOnly value={link} className="font-mono text-xs" />
              <Button variant="outline" size="icon" onClick={() => { navigator.clipboard.writeText(link); toast.success("Link kopiert"); }} aria-label="Link kopieren"><Copy /></Button>
            </div>
            <p className="text-xs text-muted-foreground">Der Link wird aus Sicherheitsgründen nur jetzt angezeigt. Sie können die Freigabe unter „IT-Dienstleister“ jederzeit widerrufen.</p>
            <DialogFooter><Button onClick={() => onOpenChange(false)}>Fertig</Button></DialogFooter>
          </div>
        ) : (
          <form action={submit} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2"><Label htmlFor="companyName">Firma</Label><Input id="companyName" name="companyName" placeholder="IT-Service Muster" /></div>
              <div className="space-y-2"><Label htmlFor="contactName">Ansprechpartner</Label><Input id="contactName" name="contactName" /></div>
            </div>
            <div className="space-y-2"><Label htmlFor="email">E-Mail</Label><Input id="email" name="email" type="email" required /></div>
            <div className="space-y-2">
              <Label htmlFor="validDays">Zugriff gültig für</Label>
              <select id="validDays" name="validDays" defaultValue="14" className="h-9 w-full rounded-md border bg-transparent px-3 text-sm">
                <option value="7">7 Tage</option><option value="14">14 Tage</option><option value="30">30 Tage</option><option value="90">90 Tage</option>
              </select>
            </div>
            <div className="space-y-2"><Label htmlFor="message">Nachricht (optional)</Label><Textarea id="message" name="message" rows={3} placeholder="Bitte bis Ende der Woche prüfen." /></div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>Abbrechen</Button>
              <Button type="submit" disabled={pending}>{pending ? <Loader2 className="animate-spin" /> : <Send />} Freigeben</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
