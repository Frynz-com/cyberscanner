import Link from "next/link";
import { ArrowRight, BadgeCheck, Ban, Bell, CheckCircle2, FileText, Globe, KeyRound, Mail, Radar, RefreshCw, ShieldCheck, Siren, Users } from "lucide-react";
import { CheckForm } from "@/components/marketing/check-form";
import { Button } from "@/components/ui/button";
import { createAdminClient } from "@/lib/supabase/admin";

export const revalidate = 3600;

const FEATURES = [
  { icon: Radar, title: "External Security Radar", text: "Regelmäßige Prüfung von DNS, E-Mail-Schutz (SPF, DMARC), TLS-Zertifikaten und Website-Konfiguration – inklusive automatisch erkannter Subdomains." },
  { icon: KeyRound, title: "Datenleck-Überwachung", text: "Hinweise, wenn Firmen-E-Mail-Adressen in bekannten Datenlecks auftauchen – über lizenzierte Quellen wie Have I Been Pwned. Ohne Passwörter zu speichern." },
  { icon: BadgeCheck, title: "Nachvollziehbare Priorisierung", text: "Jeder Befund wird nach festen technischen Kriterien bewertet. Kein undurchsichtiger Score, sondern eine klare Begründung." },
  { icon: Users, title: "Zusammenarbeit mit Ihrem IT-Dienstleister", text: "Befunde mit einem Klick gezielt weitergeben – technische Details inklusive, ohne Zugriff auf Ihr Konto." },
  { icon: RefreshCw, title: "Fix & Verify", text: "Nach der Behebung prüfen wir automatisch nach. Als behoben gilt nur, was technisch bestätigt ist." },
  { icon: FileText, title: "Monatsbericht", text: "Ein professioneller PDF-Bericht für Geschäftsführung, Versicherung oder Prüfer – mit echten Ergebnissen und klaren Grenzen." },
  { icon: Siren, title: "Digitaler Notfallbereich", text: "Im Ernstfall: sichere Sofortmaßnahmen, Dokumentation und Benachrichtigung der richtigen Ansprechpartner." },
];

const STEPS = [
  { title: "Registrieren & Domain bestätigen", text: "Konto anlegen und per DNS-Eintrag nachweisen, dass die Domain Ihnen gehört. Dauert wenige Minuten." },
  { title: "Prüfungen freigeben", text: "Sie legen schriftlich fest, was wir prüfen dürfen. Nichts geschieht ohne Ihre Freigabe." },
  { title: "Ergebnisse verstehen", text: "Klare Erklärungen für die Geschäftsführung, technische Details für die IT – priorisiert nach Dringlichkeit." },
  { title: "Beheben & bestätigen", text: "Ihr IT-Dienstleister setzt um, wir prüfen nach. Fortschritt und Nutzen sehen Sie in der Timeline und im Monatsbericht." },
];

const FAQ = [
  { q: "Muss ich Software installieren?", a: "Nein. CyberSafe24 Shield prüft ausschließlich die von außen sichtbaren Eigenschaften Ihrer Domains. Sie benötigen nur einen Browser." },
  { q: "Ist das ein Penetrationstest?", a: "Nein. Wir führen keine Angriffe, Exploits oder Brute-Force-Versuche durch. Standardmäßig prüfen wir nur öffentliche Konfigurationen. Eine erweiterte, nicht-destruktive Schwachstellenprüfung ist optional und nur nach gesonderter Freigabe je System möglich." },
  { q: "Warum muss ich meine Domain verifizieren?", a: "Damit niemand fremde Unternehmen prüfen lassen kann. Erst nach dem DNS-Nachweis und Ihrer schriftlichen Freigabe starten wir die regelmäßige Überwachung." },
  { q: "Bedeutet ein Datenleck-Hinweis, dass wir gehackt wurden?", a: "Nein. Ein Hinweis zeigt, dass eine Firmen-E-Mail-Adresse bei einem externen Dienst in einem bekannten Datenleck auftaucht. Wir erklären, welche Schritte sinnvoll sind – z. B. Passwortwechsel und MFA-Prüfung." },
  { q: "Bieten Sie einen 24/7-Notdienst an?", a: "Die Plattform bietet digitale Notfallunterstützung. Persönliche Einsätze erfolgen nur über vertraglich angebundene Experten – ohne entsprechenden Vertrag sagen wir keine Reaktionszeiten zu." },
  { q: "Was passiert mit meinen Daten?", a: "Wir speichern so wenig wie möglich: betroffene Konten aus Datenlecks werden verschlüsselt abgelegt, Passwörter werden nie abgerufen. Sie können Ihre Daten jederzeit exportieren und Ihr Konto löschen." },
];

async function loadPlans() {
  try {
    const { data } = await createAdminClient().from("plans").select("key, name, description, price_cents, features").eq("active", true).neq("key", "trial").order("sort");
    return data ?? [];
  } catch {
    return [];
  }
}

export default async function LandingPage() {
  const plans = await loadPlans();
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 -z-10 [background:radial-gradient(60%_50%_at_50%_0%,var(--brand-soft),transparent)]" />
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 pt-16 pb-20 sm:px-6 lg:grid-cols-[1.1fr_1fr] lg:pt-24">
          <div className="space-y-7" id="check">
            <p className="inline-flex items-center gap-2 rounded-full border bg-card px-3 py-1 text-xs font-medium text-muted-foreground">
              <span className="size-1.5 rounded-full bg-brand" /> Externe Sicherheitsüberwachung für den Mittelstand
            </p>
            <h1 className="text-4xl leading-[1.1] font-semibold tracking-tight text-balance sm:text-5xl">Wissen Sie, welche Cyberrisiken von Ihrem Unternehmen öffentlich sichtbar sind?</h1>
            <p className="max-w-xl text-lg text-muted-foreground">
              Wir überwachen die extern sichtbaren Cyberrisiken Ihres Unternehmens, warnen bei bekannten Datenlecks und Sicherheitsproblemen und helfen bei der Behebung – verständlich und ohne Installation.
            </p>
            <div className="max-w-xl"><CheckForm /></div>
            <ul className="flex flex-wrap gap-x-5 gap-y-2 text-sm text-muted-foreground">
              {["Keine Installation", "Prüfung erst nach Domain-Nachweis", "Datensparsam & DSGVO-orientiert"].map((t) => (
                <li key={t} className="flex items-center gap-1.5"><CheckCircle2 className="size-4 text-brand" />{t}</li>
              ))}
            </ul>
          </div>
          <ProductPreview />
        </div>
      </section>

      {/* Free vs. Monitoring */}
      <section className="border-y bg-card">
        <div className="mx-auto grid max-w-6xl gap-6 px-4 py-14 sm:px-6 md:grid-cols-2">
          <div className="rounded-2xl border p-6">
            <p className="text-sm font-medium text-muted-foreground">Kostenloser Kurzcheck</p>
            <h2 className="mt-1 text-xl font-semibold">Ein erster, schonender Blick</h2>
            <ul className="mt-4 space-y-2 text-sm">
              {["E-Mail-Schutz (SPF, DMARC)", "DNSSEC & Zertifikatsrichtlinie (CAA)", "TLS-Zertifikat der Website", "HTTPS-Weiterleitung & Sicherheitsheader"].map((t) => <li key={t} className="flex gap-2"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-brand" />{t}</li>)}
            </ul>
            <p className="mt-4 text-xs text-muted-foreground">Ohne Verifizierung prüfen wir nur öffentliche Konfigurationen der Hauptdomain – keine Subdomains, keine Portscans, keine Datenleck-Abfragen.</p>
          </div>
          <div className="rounded-2xl border border-brand/30 bg-brand-soft/40 p-6">
            <p className="text-sm font-medium text-brand">Kontinuierliche Überwachung</p>
            <h2 className="mt-1 text-xl font-semibold">Der vollständige Überblick – dauerhaft</h2>
            <ul className="mt-4 space-y-2 text-sm">
              {["Alles aus dem Kurzcheck, regelmäßig", "Automatische Subdomain-Erkennung", "Datenleck-Hinweise zu Firmenadressen", "Bekannte offene Dienste & CVE-Hinweise (lizenzabhängig)", "Fix & Verify mit Ihrem IT-Dienstleister", "Monatlicher PDF-Bericht"].map((t) => <li key={t} className="flex gap-2"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-brand" />{t}</li>)}
            </ul>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="leistungen" className="mx-auto max-w-6xl px-4 py-20 sm:px-6">
        <div className="max-w-2xl space-y-3">
          <h2 className="text-3xl font-semibold tracking-tight">Sicherheit, die man versteht – und die nachweisbar wirkt</h2>
          <p className="text-muted-foreground">Kein weiteres kompliziertes Security-Tool. Sondern ein klarer Überblick, konkrete Maßnahmen und die Bestätigung, dass sie umgesetzt sind.</p>
        </div>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <div key={f.title} className="rounded-2xl border bg-card p-6 transition hover:shadow-sm">
              <f.icon className="size-5 text-brand" />
              <h3 className="mt-4 font-semibold">{f.title}</h3>
              <p className="mt-1.5 text-sm text-muted-foreground">{f.text}</p>
            </div>
          ))}
          <div className="rounded-2xl border border-dashed p-6">
            <Ban className="size-5 text-muted-foreground" />
            <h3 className="mt-4 font-semibold">Was wir bewusst nicht tun</h3>
            <p className="mt-1.5 text-sm text-muted-foreground">Keine Angriffe auf fremde Systeme, keine erfundenen Risiko-Scores, kein „100 % geschützt“-Siegel und keine Rund-um-die-Uhr-Versprechen ohne Vertrag.</p>
          </div>
        </div>
      </section>

      {/* Steps */}
      <section id="ablauf" className="border-y bg-card">
        <div className="mx-auto max-w-6xl px-4 py-20 sm:px-6">
          <h2 className="text-3xl font-semibold tracking-tight">So funktioniert’s</h2>
          <ol className="mt-10 grid gap-6 md:grid-cols-4">
            {STEPS.map((s, i) => (
              <li key={s.title} className="space-y-3">
                <span className="flex size-8 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">{i + 1}</span>
                <h3 className="font-semibold">{s.title}</h3>
                <p className="text-sm text-muted-foreground">{s.text}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* Pricing */}
      <section id="preise" className="mx-auto max-w-6xl px-4 py-20 sm:px-6">
        <div className="max-w-2xl space-y-3">
          <h2 className="text-3xl font-semibold tracking-tight">Transparente Preise</h2>
          <p className="text-muted-foreground">Monatlich kündbar. 14 Tage kostenlos testen – mit einer Domain und wöchentlicher Prüfung.</p>
        </div>
        <div className="mt-10 grid gap-6 md:grid-cols-2">
          {plans.map((p, i) => (
            <div key={p.key} className={`relative rounded-2xl border p-7 ${i === 1 ? "border-primary bg-primary text-primary-foreground" : "bg-card"}`}>
              {i === 1 && <span className="absolute -top-3 right-6 rounded-full bg-brand px-3 py-1 text-xs font-medium text-white">Mit Notfall-Unterstützung</span>}
              <h3 className="text-lg font-semibold">{p.name}</h3>
              <p className={`text-sm ${i === 1 ? "text-primary-foreground/70" : "text-muted-foreground"}`}>{p.description}</p>
              <p className="mt-5"><span className="text-4xl font-semibold tabular">{(p.price_cents / 100).toLocaleString("de-DE")} €</span> <span className={`text-sm ${i === 1 ? "text-primary-foreground/70" : "text-muted-foreground"}`}>netto / Monat</span></p>
              <ul className="mt-6 space-y-2 text-sm">
                {p.features.map((f) => <li key={f} className="flex gap-2"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-brand" />{f}</li>)}
              </ul>
              <Button asChild className="mt-7 w-full" variant={i === 1 ? "secondary" : "default"}><Link href="/register">14 Tage kostenlos testen</Link></Button>
            </div>
          ))}
        </div>
        <p className="mt-4 text-xs text-muted-foreground">Alle Preise zzgl. gesetzlicher USt. Die Datenleck-Überwachung setzt die Freischaltung der Domain beim Datenanbieter voraus.</p>
      </section>

      {/* FAQ */}
      <section id="faq" className="border-t bg-card">
        <div className="mx-auto max-w-3xl px-4 py-20 sm:px-6">
          <h2 className="text-3xl font-semibold tracking-tight">Häufige Fragen</h2>
          <div className="mt-8 divide-y rounded-2xl border bg-background">
            {FAQ.map((f) => (
              <details key={f.q} className="group px-5 py-4">
                <summary className="flex cursor-pointer list-none items-center justify-between font-medium">{f.q}<span className="text-muted-foreground transition group-open:rotate-45">+</span></summary>
                <p className="mt-2 text-sm text-muted-foreground">{f.a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6">
        <div className="rounded-3xl bg-primary px-6 py-14 text-center text-primary-foreground sm:px-12">
          <ShieldCheck className="mx-auto size-8 text-brand" />
          <h2 className="mt-4 text-3xl font-semibold tracking-tight">Starten Sie mit einem kostenlosen Überblick</h2>
          <p className="mx-auto mt-3 max-w-xl text-primary-foreground/70">In weniger als einer Minute sehen Sie, wie Ihre Domain von außen konfiguriert ist.</p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Button size="lg" variant="secondary" asChild><Link href="/#check">Kostenlosen Sicherheitscheck starten <ArrowRight /></Link></Button>
            <Button size="lg" variant="ghost" className="text-primary-foreground hover:bg-white/10 hover:text-primary-foreground" asChild><Link href="/demo">Demo ansehen</Link></Button>
          </div>
        </div>
      </section>
    </>
  );
}

function ProductPreview() {
  const rows = [
    { sev: "bg-sev-high", t: "Kein DMARC-Eintrag vorhanden", a: "firma.de", s: "Handlungsbedarf" },
    { sev: "bg-sev-medium", t: "TLS-Zertifikat läuft in 12 Tagen ab", a: "shop.firma.de", s: "An IT übergeben" },
    { sev: "bg-ok", t: "HSTS-Header ergänzt", a: "www.firma.de", s: "Behebung bestätigt" },
  ];
  return (
    <div className="relative" aria-label="Beispielansicht des Dashboards">
      <div className="absolute -inset-4 -z-10 rounded-[2rem] bg-gradient-to-br from-brand/10 to-transparent blur-2xl" />
      <div className="rounded-2xl border bg-card p-5 shadow-xl shadow-black/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="relative flex size-2.5"><span className="absolute inline-flex size-full animate-ping rounded-full bg-ok opacity-60" /><span className="relative inline-flex size-2.5 rounded-full bg-ok" /></span>
            <span className="text-sm font-semibold">Überwachung aktiv</span>
          </div>
          <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium tracking-wide text-muted-foreground uppercase">Beispielansicht</span>
        </div>
        <div className="mt-4 grid grid-cols-3 gap-2">
          {[["Kritisch/Hoch", "1"], ["Neu (7 Tage)", "3"], ["Bestätigt behoben", "5"]].map(([l, v]) => (
            <div key={l} className="rounded-lg border p-2.5"><p className="text-[10px] text-muted-foreground">{l}</p><p className="text-lg font-semibold tabular">{v}</p></div>
          ))}
        </div>
        <ul className="mt-4 divide-y rounded-lg border text-sm">
          {rows.map((r) => (
            <li key={r.t} className="flex items-center gap-2.5 px-3 py-2.5">
              <span className={`size-2 rounded-full ${r.sev}`} />
              <span className="min-w-0 flex-1"><span className="block truncate font-medium">{r.t}</span><span className="block font-mono text-[11px] text-muted-foreground">{r.a}</span></span>
              <span className="text-[11px] text-muted-foreground">{r.s}</span>
            </li>
          ))}
        </ul>
        <div className="mt-4 flex items-center gap-2 rounded-lg bg-brand-soft/70 px-3 py-2 text-xs"><Bell className="size-3.5 text-brand" /> Seit Ihrem letzten Bericht: 3 neue Befunde, 5 erfolgreich nachgeprüft.</div>
        <div className="mt-3 flex gap-2 text-[11px] text-muted-foreground"><Globe className="size-3.5" /> firma.de · 14 Assets · <Mail className="size-3.5" /> E-Mail-Schutz geprüft</div>
      </div>
    </div>
  );
}
