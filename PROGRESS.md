# PROGRESS – CyberSafe24 Shield

Stand: 26.10.2026 · Phasen 1–4 umgesetzt (MVP). Alle Angaben unten sind durch Tests bzw. echte Läufe belegt, sofern nicht anders vermerkt.

## Integrationsstatus (ehrliche Liste)

| Quelle / Scanner | Status | Getestet mit | Voraussetzung für Produktion |
|---|---|---|---|
| **DNS & E-Mail** (SPF inkl. rekursiver Lookup-Zählung, DMARC, DKIM-Selektoren, DNSSEC, CAA, NS, verwaiste CNAMEs) | ✅ aktiv | echte DoH-Abfragen (heise.de, example.com), Fixtures | – |
| **HTTP-Konfiguration** (HTTPS, HTTP→HTTPS, HSTS, CSP, XCTO, Clickjacking, Versions-Header, Cookies, security.txt) | ✅ aktiv | echte Requests (example.com, heise.de), Fixtures | – |
| **TLS** (Ablauf, Hostname, Vertrauenskette, Schlüssellänge, TLS 1.0/1.1) | ✅ implementiert | Fixtures; in der Entwicklungs-Sandbox terminiert ein Egress-Proxy TLS → Adapter erkennt das und **verwirft** die Daten (`TLS_INTERCEPT_ISSUER_PATTERN`) | Lauf auf Worker-Host ohne TLS-Proxy (dort echte Zertifikatsdaten) |
| **Subfinder** (ProjectDiscovery, MIT) | ✅ aktiv | echte Läufe lokal und im Docker-Container | optional API-Keys via `SUBFINDER_PROVIDER_CONFIG` |
| **Certificate Transparency** (crt.sh, Fallback Cert Spotter) | ✅ aktiv | echte Läufe (crt.sh lieferte zeitweise 502 → Fallback griff) | optional `CERTSPOTTER_API_KEY` |
| **CISA KEV** (gemeinfrei) | ✅ aktiv | echter Import (1.756 CVEs) | – |
| **Shodan InternetDB** | ⚠️ implementiert, **lizenzpflichtig** | echte API + Fixtures; im Evaluationsmodus nur außerhalb von Produktion | **Enterprise-Lizenz** von Shodan (laut internetdb.shodan.io nur nicht-kommerziell frei) → `SHODAN_INTERNETDB_LICENSE=enterprise` |
| **Have I Been Pwned** (Domain Search, optional Stealer Logs) | ⚠️ implementiert, **inaktiv** | Fixtures im dokumentierten API-Format, Retry/429, 401/403 | kostenpflichtiger API-Key; **jede Kundendomain muss zusätzlich im HIBP-Dashboard verifiziert sein** (sonst „nicht prüfbar“); Stealer Logs nur Pro-Tarif; Quellenangabe CC BY 4.0 ist eingebaut |
| **Nuclei** (MIT) | ⚠️ vorbereitet, **deaktiviert** | Fixtures, Argument-/Scope-Tests; Binary im Container | `NUCLEI_ENABLED=true`, kuratierte `NUCLEI_TEMPLATE_IDS`, Tarif Shield Care, Scope `vuln_scan` in Autorisierung + Asset-Freigabe durch Inhaber. UI zur Erteilung des Scopes `vuln_scan` fehlt noch |
| **Hudson Rock – Infostealer** (infizierte Mitarbeiter-/Kundengeräte, Login-URLs, Zeitpunkt, Passwortstärke; keine Zugangsdaten) | ✅ aktiv (Entwicklung) | echte API (heise.de: 5 Mitarbeitergeräte, 2.221 Kundenkonten), Fixtures | kostenloser OSINT-Endpunkt; **kommerzielle Nutzung schriftlich mit Hudson Rock klären** → `HUDSONROCK_TERMS_CONFIRMED=true` (sonst in Produktion gesperrt) |
| **ransomware.live** (Nennung auf Ransomware-Leakseiten, exakter Domain-Abgleich) | ✅ aktiv | echte API, Fixtures | kostenlos; für hohe Abfragevolumen Pro-API bzw. Absprache |
| **Nachgemachte Domains** (Typosquatting/Phishing, eigene Implementierung der dnstwist-Methodik, Eigentümer-Erkennung) | ✅ aktiv, auch im kostenlosen Kurzcheck | echte DNS-Läufe (heise.de, bechtle.com), Fixtures | – (nur öffentliche DNS-Abfragen fremder Domains) |
| **SpyCloud** | ❌ nicht implementiert | – | Enterprise-Vertrag; Adapter-Schnittstelle vorhanden |
| **Resend** (E-Mail) | ⚠️ implementiert, nicht konfiguriert | Integrationstest (ohne Schlüssel → „nicht versendet“, Limit, Demo-Sperre) | `RESEND_API_KEY`, `EMAIL_FROM`, Domain bei Resend verifizieren |
| **Stripe** | ⚠️ implementiert, nicht konfiguriert | signierte Webhooks (Integrationstest mit echter Signaturprüfung) | Secret Key, Webhook-Secret, Price-IDs |

## 24/7-Basis
- Neuer Job-Typ `intel_watch`: leichte Threat-Intel-Läufe (HIBP, Hudson Rock, ransomware.live, nachgemachte Domains) unabhängig vom Vollscan, Intervall je Tarif (Testphase 24 h, Shield 6 h, Shield Care 1 h). Neue Treffer → sofort Befund + Warnung (dedupliziert).
- Ausbaustufe für echtes Echtzeit-Monitoring: Certificate-Transparency-Stream (neue Zertifikate für Ähnlich-Domains in Minuten), Webhooks kommerzieller Anbieter (z. B. SpyCloud/Flare), menschlicher Bereitschaftsdienst über Partner (Emergency Desk ist vorbereitet).

## Fertige Funktionen

- **Multi-Tenant-Kern:** 22 Tabellen + Timeline, RLS (FORCE) auf allen Tabellen, Clients nur lesend, Schreiben über Server Actions mit DB-Rechteprüfung, Rollen (Inhaber/Admin/Mitglied/Lesezugriff), append-only Audit-Log.
- **Auth & Onboarding (7 Schritte):** Registrierung, Unternehmen, Domain (Normalisierung inkl. IDN/URL), DNS-TXT-Verifikation (DoH), schriftliche versionierte Scan-Autorisierung, erste Prüfung mit Live-Status, Dashboard. Wiederaufnahme aus DB-Zustand.
- **Scan-Infrastruktur:** Postgres-Queue (SKIP LOCKED + Advisory-Lock je Organisation), Retry mit Backoff, Heartbeat/Stale-Recovery, Abbruch, Idempotenz, Scheduler, Provider-Health, Container-Worker (non-root, read-only, ohne Capabilities).
- **SSRF-/Rebinding-Schutz:** öffentliche-IP-Prüfung aller Adressen, IP-Pinning, Redirect-Scope, Port-/Protokoll-Allowlist.
- **Asset Discovery:** Subfinder + CT, DNS-Validierung (nur existierende Subdomains, Wildcard-Erkennung, Kandidatenlimit), Neu-Erkennung mit Timeline/Benachrichtigung.
- **Risk Engine:** 38 Regeln mit deutschen Texten für Entscheider und IT, deterministische Schweregrade mit Begründung, Gewissheit (bestätigt / möglich / Info / nicht prüfbar), Priorität mit nachvollziehbaren Zuschlägen (Hauptdomain, CISA KEV, aktuelle Leaks).
- **Deduplizierung & Change Detection:** Fingerprints, `seen_again`, `reappeared`, `still_present`, `verified_fixed` nur bei vollständiger Prüfabdeckung.
- **Fix & Verify:** Warum wichtig / Was tun / technische Details / Prüfschritte / Doku-Links, Status-Workflow mit Begründungspflicht, „Als behoben markieren“ (unbestätigt) + automatische Nachprüfung, gezielte Reverify-Jobs.
- **IT-Dienstleister:** zeitlich begrenzte, widerrufbare Token-Freigaben einzelner Befunde, Partnerportal mit Rückmeldung und Nachprüfung, Verlauf („IT informiert → Bearbeitung → Nachprüfung → Ergebnis“).
- **Security Timeline** (Monatsansicht mit Nutzenkennzahlen) und Dashboard-Hinweis „Seit Ihrem letzten Bericht …“.
- **Dashboard:** ehrlicher Überwachungsstatus, KPIs, priorisierte Maßnahmen, Verlauf, Monitoring-Abdeckung je Modul (inkl. fehlender Integrationen), Schnellzugriffe, Benachrichtigungen, Auto-Refresh bei laufenden Prüfungen.
- **Benachrichtigungen:** In-App + E-Mail-Outbox, Deduplizierung, max. 10 E-Mails/Org/Tag, max. 3 Versuche, Eskalation (z. B. Zertifikatsablauf), Verifizierungsverlust (14 Tage Kulanz), Scanfehler, Monatsbericht.
- **PDF-Berichte:** Monatlich automatisch + auf Abruf; Deckblatt, Zusammenfassung, Vorperiodenvergleich, Abdeckung, Ergebnisse, Behebungen (bestätigt vs. unbestätigt), offene Maßnahmen, Methodik & Grenzen, technischer Anhang.
- **Emergency Desk:** 6 Vorfallarten mit Sofortmaßnahmen, „Bitte vermeiden“, Kontakte, Dokumentation, deterministische Priorität, Checkliste, Incident-Timeline, sicherer Upload (Typ-Allowlist, Magic Bytes, 4 MB), Benachrichtigung IT-Partner/Experte. Kein 24/7-Versprechen; vertraglicher Experte nur per Konfiguration.
- **Landingpage & Free Check:** conversion-orientiert, ohne Angstwerbung; Kurzcheck läuft ausschließlich im Worker (DNS/TLS/Header der Hauptdomain), Rate-Limits, Honeypot, Ergebnisseite mit Grenzen und CTA zur Registrierung.
- **Billing:** Tarife aus DB (Shield 249 €, Shield Care 499 €, Testphase), Limits serverseitig durchgesetzt (Domains, Subdomains, Intervall, manuelle Scans, Breach, Partner, Nuclei), Checkout, Portal, Webhooks.
- **Demo-Mandant:** synthetische Daten über die echte Regel-Engine, DEMO-Banner/-Badges/-Wasserzeichen, DB-Trigger-Trennung, keine Scans/E-Mails, Musterbericht, Partnerportal-Link.
- **Admin-Bereich:** Organisationen (nur Kennzahlen), fehlgeschlagene Jobs mit Retry, Provider-Status, Incidents, Systemlogs; alle Aktionen auditiert.
- **DSGVO:** Datenexport (JSON), Löschung mit 30-Tage-Frist inkl. Storage, Retention-Job, Feldverschlüsselung, IP-Hashing.

## Tests (zuletzt ausgeführt)

| Suite | Ergebnis |
|---|---|
| Unit (`pnpm test`) | 68/68 ✅ – Domain/IP/SSRF, DNS-Fixture-Resolver, alle Adapter mit Fixtures, Timeout/Abbruch, API-Ausfall, Risk Engine/Dedup |
| Integration (`pnpm test:integration`) | 48/48 ✅ inkl. 2 Live-Tests (`LIVE_SCANS=1`, echte Netzwerkscans) – Cross-Tenant (24), Queue/Race, Retry, Persistenz, Benachrichtigungen, Scheduler, Stripe-Webhooks, Partner-Token, PDF, Löschkonzept |
| E2E (`pnpm test:e2e`) | 6/6 ✅ – Hauptnutzerfluss (Registrierung → … → Notfall, mit echtem Scan gegen example.com), Login-Schutz, Free Check, Demo, Mobile (keine horizontale Überbreite) |
| Build / Lint / Typecheck | ✅ |
| Worker-Container | ✅ gebaut und echten Scan verarbeitet (read-only, non-root, cap_drop ALL) |

## Technische Entscheidungen

- Ein Paket statt Monorepo; Kern unter `src/lib/core` wird von Web und Worker genutzt.
- supabase-js überall; atomare Operationen als SQL-Funktionen (`claim_scan_job`, `create_organization`, `rate_limit_hit`).
- DNS über DoH (Cloudflare, Fallback Google): liefert AD-Flag für DNSSEC, funktioniert hinter Egress-Proxies.
- Free Check und alle Netzwerkprüfungen nur im Worker; Web-App erzeugt Jobs.
- Rate-Limiting in Postgres statt Redis (Serverless-tauglich, keine zusätzliche Infrastruktur).
- PDF serverseitig per `@react-pdf/renderer` aus gespeichertem Snapshot (reproduzierbar).
- Supply-Chain: `minimumReleaseAge` 24 h, `packageManager` gepinnt, Scanner-Versionen gepinnt; Basis-Images über AWS-ECR-Spiegel (keine Docker-Hub-Limits).

## Blocker / benötigte Zugänge

1. HIBP-API-Schlüssel + Domain-Verifikationen im HIBP-Dashboard (Prozess für jede Kundendomain).
2. Shodan-Enterprise-Lizenz für InternetDB (oder Modul deaktiviert lassen).
3. Stripe- und Resend-Konten, Domain für E-Mail-Versand.
4. Rechtstexte (Impressum, Datenschutz, AGB) – derzeit gekennzeichnete Vorlagen.
5. Optional: Vertrag mit Incident-Response-Dienstleister (`EMERGENCY_PARTNER_*`).

## Offene Funktionen / nächste Schritte

1. **MFA** (Supabase TOTP) – für Plattform-Admins Pflicht vor Go-Live, für Kunden anbieten.
2. Worker mit eigener Least-Privilege-DB-Rolle statt Service Role.
3. Team-Einladungen (weitere Mitglieder per E-Mail; Rollen sind im Modell vorhanden, UI zeigt nur die Liste).
4. UI zur Erteilung des Scopes `vuln_scan` + kuratierte Nuclei-Template-Liste.
5. Lead-Formular im Free Check (Tabelle `leads` vorhanden).
6. CSP mit Nonces, Sentry-Anbindung, Egress-Firewall-Automatisierung, Worker-Image verschlanken (derzeit ~1,6 GB inkl. Dev-Dependencies).
7. Optionale KI-Zusammenfassung (nur Umformulierung vorhandener Befunde) – bewusst noch nicht umgesetzt.
8. Externer Penetrationstest, juristische Prüfung (AVV, AGB, Scan-Autorisierungstext).
