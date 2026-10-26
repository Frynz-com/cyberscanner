# Architektur – CyberSafe24 Shield

## Leitentscheidungen

1. **Ein Repository, ein Paket.** Next.js-App und Worker teilen sich den Kern unter `src/lib/core` (Adapter, Risk Engine, Netzwerk-Schutz). Kein Monorepo-Overhead.
2. **Keine Scans in der Web-Runtime.** Die Web-App legt ausschließlich Jobs in `scan_jobs` an. Netzwerkzugriffe auf Kundensysteme erfolgen nur im isolierten Worker. (Einzige Ausnahme: die DNS-TXT-Verifikation – eine Abfrage an einen festen DoH-Resolver, kein Kontakt zum Kunden-System.)
3. **Postgres als Queue.** `claim_scan_job()` mit `FOR UPDATE SKIP LOCKED` + Advisory-Lock je Organisation, Heartbeats, Stale-Recovery, Idempotenz-Schlüssel. Kein Redis nötig.
4. **Lesen über RLS, Schreiben über den Server.** Clients haben nur SELECT-Rechte (RLS). Jede Änderung läuft durch eine Server Action mit `authorizeOrg()` und Audit-Log.
5. **Deterministische Bewertung.** Regelkatalog `src/lib/core/risk/rules.ts`; Priorität = Basis(Schweregrad) × Faktor(Gewissheit) + begründete Zuschläge. Keine KI-Scores.
6. **Ehrlichkeit als Produktmerkmal.** Nicht verfügbare Integrationen werden als solche angezeigt; „behoben“ nur nach technischer Bestätigung; CVE-Hinweise immer „möglich“; kein 24/7-Versprechen ohne Vertrag.

## Verzeichnisstruktur

```
src/app/                    Next.js App Router
  (marketing)/              Landingpage, Free Check, Demo, Rechtliches
  (auth)/                   Login, Registrierung
  onboarding/               Schritte 2–7
  app/                      Kundenbereich (Dashboard, Befunde, Timeline, Assets, Domains, Partner, Berichte, Notfall, Einstellungen)
  partner/[token]/          Portal für IT-Dienstleister (tokenbasiert)
  admin/                    interner Bereich
  actions/                  Server Actions (Schreibzugriffe, Rechteprüfung)
  api/                      Stripe-Webhook, Public Check, PDF, Export, Datei-Downloads
src/lib/core/               framework-unabhängiger Kern (auch im Worker)
  net/                      DoH-Resolver, IP-Klassifizierung, SSRF-sichere Verbindungen
  scanners/                 Adapter: dns, tls, http_headers, subfinder, ct_logs, internetdb, hibp, nuclei
  risk/                     Regelkatalog, Normalisierung, Abgleich (Dedupe/Change Detection)
src/lib/server/             server-only: Auth/Rechte, Partner-Token, Stripe, Reverify
worker/                     Job-Loop, Scheduler, Persistenz, Mailer, Wartung, Monatsberichte
supabase/migrations/        Schema, RLS, Funktionen, Referenzdaten
tests/unit|integration      Vitest (Fixtures, echte lokale Supabase)
e2e/                        Playwright (Hauptnutzerfluss, Demo, Mobile)
```

## Adapter-Lebenszyklus

```
initialize(env) → checkAvailability() → validateAuthorization(ctx) → execute(ctx) [Timeout/Abbruch]
              → normalizeResults(raw) → { observations, coverage, discoveredAssets, breachRecords }
              (Fehler) → reportErrors(err)
```
`coverage` beschreibt, welche Prüfung für welches Asset vollständig lief. Nur abgedeckte, nicht mehr beobachtete Befunde gelten als technisch bestätigt behoben.

## Scan-Ablauf (domain_scan)

1. Vorbedingungen: Domain verifiziert, gültige Autorisierung, aktives Abo, kein Demo-Mandant.
2. Discovery (Subfinder, CT-Logs) → DNS-Validierung (nur existierende Subdomains, Wildcard-Erkennung, max. 2000 Kandidaten) → Asset-Bestand.
3. Host-Auswahl (Apex, www, Subdomains bis Tariflimit) → öffentliche IPs.
4. Assessment-Adapter → `scan_results`.
5. `persistFindings`: Normalisierung → `reconcile()` → create / seen_again / reappeared / verified_fixed → Events, Timeline, Benachrichtigungen (dedupliziert).

## Zustandsmodell Befund

`new → investigating → action_required → resolved | accepted_risk | false_positive`
zusätzlich `verification_state`: `unverified` (vom Kunden markiert) · `verified_fixed` (Scanner bestätigt) · `still_present` (Nachprüfung negativ).
