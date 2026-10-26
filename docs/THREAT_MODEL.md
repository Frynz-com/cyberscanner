# Bedrohungsmodell (Entwurf) – CyberSafe24 Shield

Stand: Oktober 2026 · Methode: STRIDE je Vertrauensgrenze · Status: Entwurf, vor Go-Live extern prüfen lassen.

## 1. Systemüberblick und Vertrauensgrenzen

```
Browser (Kunde / IT-Partner / Besucher)
   │  TLS
   ▼
Next.js auf Vercel  ──(anon key + Nutzer-JWT, RLS)──►  Supabase (Postgres, Auth, Storage)
   │  (Service Role nur serverseitig, nach Rechteprüfung)        ▲
   │                                                              │ Service Role
   └── legt nur Jobs an (scan_jobs) ◄─────────────────────────────┤
                                                                   │
Scan-Worker (separater Docker-Host, non-root, read-only) ─────────┘
   │  ausgehend: DoH-Resolver, Kunden-Hosts (80/443), crt.sh/Cert Spotter,
   │             InternetDB, HIBP, CISA KEV, Resend
   ▼
Internet
```

| Grenze | Beschreibung |
|---|---|
| G1 | Internet → Web-App (öffentliche Seiten, Free Check, Partner-Links, Stripe-Webhook) |
| G2 | Web-App → Datenbank (Nutzer-JWT mit RLS bzw. Service Role) |
| G3 | Worker → Internet (Scans auf Kundensysteme, Drittanbieter-APIs) |
| G4 | Mandant ↔ Mandant (logische Trennung in einer Datenbank) |
| G5 | Kunde ↔ IT-Dienstleister (tokenbasierter Teilzugriff) |
| G6 | Plattform-Admin ↔ Kundendaten |

## 2. Schützenswerte Güter

1. Befunde und Asset-Inventar der Kunden (zeigt Angriffsfläche – hochsensibel)
2. Betroffene E-Mail-Konten aus Datenlecks (personenbezogen)
3. Vorfall-Dateien und -Beschreibungen
4. Zugangsdaten: Service-Role-Key, HIBP-/Stripe-/Resend-Schlüssel, DATA_ENCRYPTION_KEY
5. Integrität von Scan-Autorisierungen (rechtliche Absicherung)
6. Reputation: Plattform darf nicht zum Angriffswerkzeug werden

## 3. Bedrohungen und Maßnahmen (STRIDE)

### G1 – Öffentliche Schnittstellen
| Bedrohung | Maßnahme | Status |
|---|---|---|
| **Missbrauch als Scanner gegen fremde Domains** (Tampering/Elevation) | Free Check nur DNS/TLS/Startseite der Hauptdomain (wie Browser), keine Subdomains, Ports, Leaks; Rate-Limit pro IP-Hash (5/h, 15/Tag) und pro Domain (6/h); Ergebnis-Cache 10 min; Honeypot | umgesetzt |
| Vollständige Prüfungen fremder Domains | DNS-TXT-Verifikation + schriftliche, versionierte Autorisierung (Hash, Zeitstempel, IP-Hash) Pflicht; Worker prüft beides bei jedem Job erneut; periodische Re-Verifikation, Entzug nach 14 Tagen ohne Eintrag | umgesetzt |
| Credential Stuffing / Brute Force auf Login | Rate-Limit (20/15 min je IP), Supabase-Auth-Limits, Passwortrichtlinie (≥10, Buchstaben+Ziffern) | umgesetzt; MFA für Kunden: offen |
| Gefälschte Stripe-Webhooks | Signaturprüfung mit Rohdaten, Idempotenz über `stripe_events`, Freischaltung nur serverseitig | umgesetzt + getestet |
| XSS / Clickjacking | React-Escaping, CSP, `X-Frame-Options: DENY`, `frame-ancestors 'none'` | umgesetzt; CSP mit Nonces: offen (derzeit `'unsafe-inline'` für Scripts) |
| CSRF auf Server Actions | Next.js Server Actions prüfen Origin; Cookies `SameSite=Lax` | umgesetzt (Framework) |
| Enumeration öffentlicher Check-Ergebnisse | UUIDv4-IDs, nur öffentliche Konfigurationsdaten, Ablauf nach 7 Tagen | umgesetzt |

### G2/G4 – Mandantentrennung
| Bedrohung | Maßnahme | Status |
|---|---|---|
| Cross-Tenant-Lesen über PostgREST | RLS auf allen Tabellen (FORCE), Mitgliedschaftsprüfung per `security definer`-Funktion | umgesetzt, 24 Integrationstests |
| Direkte Schreibzugriffe / Rechteausweitung | `authenticated` hat **keine** INSERT/UPDATE/DELETE-Rechte (außer eigenem Profilnamen); alle Schreibvorgänge über Server Actions mit `authorizeOrg()` (DB-Prüfung von Mitgliedschaft und Rolle) | umgesetzt + getestet |
| Leak des Service-Role-Keys an Client | nur in `server-only`-Modulen, kein `NEXT_PUBLIC_`-Präfix, Build bricht bei Client-Import ab | umgesetzt |
| IDOR in Server Actions (fremde IDs) | jede Aktion lädt das Objekt, ermittelt `org_id` und prüft Mitgliedschaft/Rolle | umgesetzt; E2E-Test für fremden Befund (404) |
| Zugriff auf Storage-Dateien anderer Mandanten | privater Bucket ohne Client-Policies; Download nur über Route mit Rechteprüfung + 60-s-Signed-URL | umgesetzt + getestet |
| Vermischung Demo/Echt | `is_demo` unveränderbar, Trigger erzwingen Gleichheit, Demo-Domains nur auf `.example`, synthetische Breach-Daten nur in Demo-Orgs, Worker claimt keine Demo-Jobs, keine E-Mails | umgesetzt + getestet |

### G3 – Scan-Worker
| Bedrohung | Maßnahme | Status |
|---|---|---|
| **SSRF** auf interne Netze / Cloud-Metadaten | Auflösung über DoH; **alle** A/AAAA-Adressen müssen öffentlich sein (RFC1918, CGNAT, Loopback, Link-Local inkl. 169.254.169.254, ULA, NAT64/6to4/IPv4-mapped geprüft); sonst Abbruch | umgesetzt + getestet |
| **DNS-Rebinding** | Verbindung erfolgt fest auf die geprüfte IP (custom `lookup`, SNI = Hostname) | umgesetzt |
| Weiterleitungen auf fremde/interne Ziele | Redirects manuell, max. 5, jedes Ziel erneut geprüft; außerhalb der Domain wird gestoppt | umgesetzt |
| Fremde Ports / Protokolle | nur http:80 und https:443; URLs mit Zugangsdaten verboten | umgesetzt + getestet |
| Command Injection | `execFile` ohne Shell, Argumente als Array, Domain vorab streng validiert, minimale Umgebung | umgesetzt + getestet |
| Ressourcen-Erschöpfung | Timeouts je Adapter und Request, Body-Limit 64 KB, Concurrency-Limits, Kandidaten-Limit 2000, Container: 1 CPU, 1 GB, 256 PIDs | umgesetzt |
| Kompromittierter Worker | non-root, read-only FS, `cap_drop: ALL`, `no-new-privileges`; **Rest-Risiko:** Worker hält Service-Role-Key → empfohlen: eigene DB-Rolle mit minimalen Rechten | teilweise; offen: Least-Privilege-DB-Rolle |
| Aktive Prüfungen ohne Freigabe | Nuclei standardmäßig aus; benötigt ENV-Freigabe, Tarif, Scope `vuln_scan` **und** Asset-Freigabe durch Inhaber; nur Template-Allowlist, destruktive Tags ausgeschlossen, kein Interactsh | umgesetzt (Scope `vuln_scan` kann im UI noch nicht erteilt werden) |
| Falsche Ergebnisse durch TLS-Interception | erkennt konfigurierten Proxy-Aussteller und verwirft Daten | umgesetzt |

### G5 – IT-Dienstleister
| Bedrohung | Maßnahme | Status |
|---|---|---|
| Token-Diebstahl / Weitergabe | 256-bit-Token, nur SHA-256 gespeichert, Ablauf 1–90 Tage, Widerruf, `Referrer-Policy: no-referrer`, `no-store`, `noindex`, Zugriffszähler | umgesetzt |
| Zugriff auf nicht freigegebene Daten | Abfrage hart auf freigegebene IDs + Organisation begrenzt; jede Aktion prüft Token erneut | umgesetzt + getestet |
| Missbrauch der Nachprüfung | Rate-Limits je Befund (1/10 min) und Organisation (50/Tag) | umgesetzt |

### G6 – Plattform-Administration
| Bedrohung | Maßnahme | Status |
|---|---|---|
| Übermäßige Einsicht | Admin-UI zeigt nur Metadaten/Kennzahlen, keine Befundinhalte oder Konten | umgesetzt |
| Unbemerkte Admin-Aktionen | alle Aktionen in append-only `audit_logs` (Trigger verhindert UPDATE/DELETE) | umgesetzt |
| Admin-Konto-Übernahme | MFA für Admins | **offen** (vor Go-Live Pflicht) |

## 4. Datenschutzrelevante Risiken
- **Breach-Konten:** AES-256-GCM-verschlüsselt, HMAC für Deduplizierung, Klartext nur serverseitig für Administratoren der Organisation, Retention konfigurierbar (90–730 Tage).
- **Logs:** strukturierte Logs ohne personenbezogene Daten; IP-Adressen nur gehasht.
- **Drittlandtransfer:** HIBP (Australien), Shodan (USA), Resend/Stripe (USA) – AVV/SCC prüfen (siehe `SECURITY_PRIVACY.md`).

## 5. Offene Punkte vor Go-Live (priorisiert)
1. MFA für Plattform-Admins erzwingen; MFA für Kunden anbieten.
2. Worker mit eigener Postgres-Rolle statt Service Role (nur benötigte Tabellen/Funktionen).
3. Egress-Firewall des Worker-Hosts (Block privater Netze auf Netzwerkebene, zusätzlich zur Applikationsprüfung).
4. CSP mit Nonces statt `'unsafe-inline'`.
5. Externer Penetrationstest der Plattform.
6. Rotationskonzept für `DATA_ENCRYPTION_KEY` (Format ist versioniert: `v1.`).
