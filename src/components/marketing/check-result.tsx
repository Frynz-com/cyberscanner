"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, ArrowRight, CheckCircle2, Info, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { SeverityBadge, CertaintyBadge } from "@/components/shared/badges";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type { Certainty, Severity } from "@/lib/core/risk/types";

interface Result {
  hostname: string;
  status: "queued" | "running" | "done" | "failed";
  created_at: string;
  result: null | {
    checkedAt: string;
    modules: Array<{ key: string; label: string; status: string; message: string | null }>;
    findings: Array<{ title: string; summary: string; severity: Severity; certainty: Certainty; asset: string; recommendation: string; category: string }>;
  };
}

export function CheckResult({ id }: { id: string }) {
  const [data, setData] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stop = false;
    const load = async () => {
      const res = await fetch(`/api/public-check/${id}`, { cache: "no-store" });
      if (!res.ok) {
        setError("Dieser Check wurde nicht gefunden oder ist abgelaufen.");
        return;
      }
      const json = (await res.json()) as Result;
      if (stop) return;
      setData(json);
      if (json.status === "queued" || json.status === "running") setTimeout(load, 2500);
    };
    load();
    return () => {
      stop = true;
    };
  }, [id]);

  if (error) return <p className="rounded-xl border p-8 text-center text-muted-foreground">{error}</p>;
  if (!data || data.status === "queued" || data.status === "running") {
    return (
      <div className="space-y-6" aria-busy>
        <div className="space-y-2">
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> Prüfung läuft{data ? ` für ${data.hostname}` : ""} …</p>
          <h1 className="text-3xl font-semibold tracking-tight">Ihr Sicherheits-Kurzcheck</h1>
          <p className="text-muted-foreground">Wir lesen öffentliche DNS-Einträge, das TLS-Zertifikat und die Startseite – das dauert meist unter einer Minute.</p>
        </div>
        {[0, 1, 2].map((i) => <Skeleton key={i} className="h-20 w-full rounded-xl" />)}
      </div>
    );
  }
  if (data.status === "failed" || !data.result) {
    return (
      <div className="space-y-4 rounded-xl border p-8 text-center">
        <XCircle className="mx-auto size-8 text-muted-foreground" />
        <h1 className="text-xl font-semibold">Der Check konnte nicht abgeschlossen werden</h1>
        <p className="text-muted-foreground">Möglicherweise ist die Domain derzeit nicht erreichbar. Bitte versuchen Sie es später erneut.</p>
        <Button asChild variant="outline"><Link href="/#check">Neuen Check starten</Link></Button>
      </div>
    );
  }
  const r = data.result;
  const brand = r.findings.filter((f) => f.category === "brand" && !f.title.includes("weitere"));
  const brandMore = r.findings.find((f) => f.category === "brand" && f.title.includes("weitere"));
  const relevant = r.findings.filter((f) => f.severity !== "info" && f.category !== "brand");
  const infos = r.findings.filter((f) => f.severity === "info" && f.category !== "brand");
  const high = relevant.filter((f) => f.severity === "critical" || f.severity === "high").length;
  return (
    <div className="space-y-8" data-testid="public-check-result">
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">Kurzbericht · {new Date(r.checkedAt).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" })}</p>
        <h1 className="text-3xl font-semibold tracking-tight">Ergebnis für <span className="font-mono">{data.hostname}</span></h1>
        <p className="text-muted-foreground">
          {relevant.length === 0
            ? "In den geprüften öffentlichen Konfigurationen haben wir keine Auffälligkeiten festgestellt. Das ist ein gutes Zeichen – deckt aber nur einen kleinen Ausschnitt ab."
            : `Wir haben ${relevant.length} Punkt${relevant.length === 1 ? "" : "e"} gefunden, die Sie sich ansehen sollten${high ? `, davon ${high} mit hoher Priorität` : ""}.`}
        </p>
      </div>

      <section className="grid gap-3 sm:grid-cols-3">
        {r.modules.map((m) => (
          <div key={m.key} className="flex items-start gap-3 rounded-xl border bg-card p-4">
            {m.status === "ok" ? <CheckCircle2 className="mt-0.5 size-4 text-ok" /> : m.status === "partial" ? <AlertTriangle className="mt-0.5 size-4 text-sev-medium" /> : <Info className="mt-0.5 size-4 text-muted-foreground" />}
            <div className="min-w-0">
              <p className="text-sm font-medium">{m.label}</p>
              <p className="text-xs text-muted-foreground">{m.status === "ok" ? "Geprüft" : m.status === "partial" ? "Teilweise geprüft" : m.message ?? "Nicht geprüft"}</p>
            </div>
          </div>
        ))}
      </section>

      {brand.length > 0 && (
        <section className="rounded-2xl border border-sev-high/25 bg-sev-high/[0.04] p-6" data-testid="lookalike-card">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-sev-high" />
            <div className="min-w-0 flex-1">
              <h2 className="text-lg font-semibold">Phishing-Frühwarnung: {brand.length + (brandMore ? Number(brandMore.title.match(/\d+/)?.[0] ?? 0) : 0)} ähnliche Domains sind registriert</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Diese Domains sehen Ihrer zum Verwechseln ähnlich. {brand.filter((b) => b.severity === "medium").length > 0 && <strong className="text-foreground">{brand.filter((b) => b.severity === "medium").length} davon können E-Mails versenden.</strong>} Sie können legitim sein – oder für gefälschte Rechnungen und Phishing genutzt werden.
              </p>
              <ul className="mt-4 grid gap-2 sm:grid-cols-2">
                {brand.slice(0, 6).map((b) => (
                  <li key={b.title} className="flex items-center justify-between gap-2 rounded-lg border bg-card px-3 py-2 text-sm">
                    <span className="truncate font-mono">{b.title.replace("Ähnliche Domain registriert: ", "")}</span>
                    {b.severity === "medium" && <span className="shrink-0 rounded-full bg-sev-high/10 px-2 py-0.5 text-[11px] font-medium text-sev-high">E-Mail-fähig</span>}
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-muted-foreground">Mit der kontinuierlichen Überwachung melden wir neue Domains automatisch – oft, bevor die ersten Phishing-Mails verschickt werden.</p>
            </div>
          </div>
        </section>
      )}

      {relevant.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Ergebnisse</h2>
          {relevant.map((f, i) => (
            <article key={i} className="rounded-xl border bg-card p-5">
              <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} />{f.certainty !== "confirmed" && <CertaintyBadge certainty={f.certainty} />}<span className="font-mono text-xs text-muted-foreground">{f.asset}</span></div>
              <h3 className="mt-2 font-semibold">{f.title}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{f.summary}</p>
              <p className="mt-2 text-sm"><span className="font-medium">Empfehlung:</span> {f.recommendation}</p>
            </article>
          ))}
        </section>
      )}
      {infos.length > 0 && (
        <details className="rounded-xl border bg-card px-5 py-4 text-sm">
          <summary className="cursor-pointer font-medium">{infos.length} Informationshinweis(e)</summary>
          <ul className="mt-3 space-y-1 text-muted-foreground">{infos.map((f, i) => <li key={i}>• {f.title} ({f.asset})</li>)}</ul>
        </details>
      )}

      <section className="rounded-2xl border bg-muted/40 p-6 text-sm">
        <h2 className="font-semibold">Was dieser Kurzcheck nicht abdeckt</h2>
        <p className="mt-2 text-muted-foreground">
          Ohne Nachweis, dass die Domain Ihnen gehört, prüfen wir nur öffentliche Konfigurationen der Hauptdomain. Erst nach der Verifizierung prüfen wir: infizierte Rechner mit Firmen-Zugangsdaten (Infostealer), Nennungen auf Ransomware-Leakseiten, Datenlecks mit Firmen-E-Mail-Adressen, Subdomains (z. B. Shop, Mail, VPN) und laufend alle Veränderungen.
        </p>
      </section>

      <section className="rounded-3xl bg-primary px-6 py-10 text-center text-primary-foreground">
        <ShieldCheck className="mx-auto size-7 text-brand" />
        <h2 className="mt-3 text-2xl font-semibold">Kontinuierliche Sicherheitsüberwachung aktivieren</h2>
        <p className="mx-auto mt-2 max-w-lg text-primary-foreground/70">Domain bestätigen, Prüfungen freigeben und ab sofort regelmäßig wissen, was sich verändert – 14 Tage kostenlos.</p>
        <Button size="lg" variant="secondary" className="mt-6" asChild><Link href={`/register?domain=${encodeURIComponent(data.hostname)}`}>Jetzt aktivieren <ArrowRight /></Link></Button>
      </section>
    </div>
  );
}
