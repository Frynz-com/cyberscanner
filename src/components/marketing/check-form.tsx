"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";

export function CheckForm({ size = "lg" }: { size?: "lg" | "default" }) {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    if (!consent) return setError("Bitte bestätigen Sie den Hinweis zur Prüfung.");
    setPending(true);
    try {
      const fd = new FormData(e.currentTarget);
      const res = await fetch("/api/public-check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ domain, consent: true, website: fd.get("website") ?? "" }) });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? "Der Check konnte nicht gestartet werden.");
      router.push(`/check/${json.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unbekannter Fehler");
      setPending(false);
    }
  };
  return (
    <form onSubmit={submit} className="w-full space-y-3" id="check-form">
      <div className="flex flex-col gap-2 rounded-xl border bg-card p-2 shadow-sm sm:flex-row">
        <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="ihre-firma.de" aria-label="Domain" required autoCapitalize="none" spellCheck={false} className={size === "lg" ? "h-11 border-0 text-base shadow-none focus-visible:ring-0" : "border-0 shadow-none"} />
        <input type="text" name="website" tabIndex={-1} autoComplete="off" className="hidden" aria-hidden />
        <Button type="submit" size={size} disabled={pending} className={size === "lg" ? "h-11 px-5" : ""}>
          {pending ? <Loader2 className="animate-spin" /> : null}
          Kostenlosen Sicherheitscheck starten {!pending && <ArrowRight />}
        </Button>
      </div>
      <label className="flex items-start gap-2.5 text-left text-xs text-muted-foreground">
        <Checkbox checked={consent} onCheckedChange={(v) => setConsent(Boolean(v))} className="mt-0.5" aria-label="Hinweis bestätigen" />
        <span>Ich möchte diese Domain für mein Unternehmen prüfen lassen. Der Kurzcheck ruft nur öffentliche DNS-Einträge, das TLS-Zertifikat und die Startseite ab – wie ein Browser. Keine Portscans, keine Angriffe, keine Datenleck-Abfragen.</span>
      </label>
      {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
    </form>
  );
}
