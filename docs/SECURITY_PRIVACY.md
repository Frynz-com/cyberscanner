# Sicherheit & Datenschutz (DSGVO) – Architekturentscheidungen

## Datenkategorien und Minimierung

| Daten | Zweck | Speicherung | Löschung |
|---|---|---|---|
| Konto (E-Mail, Name) | Login, Benachrichtigungen | Supabase Auth / `profiles` | mit Konto |
| Domains, Assets, Befunde | Kernleistung | `domains`, `assets`, `findings` | Organisation löschen → nach 30 Tagen kaskadierend |
| Datenleck-Konten | Hinweis an Kunden | `breach_records.account_enc` (AES-256-GCM) + HMAC; **keine Passwörter** | nach `data_retention_days` (Standard 365) ohne erneute Beobachtung |
| Scan-Rohdaten | Nachvollziehbarkeit | `scan_results.data` (nur minimierte Zusammenfassungen) | nach `data_retention_days` |
| Vorfall-Dateien | Dokumentation | privater Bucket `incident-files` | mit Organisation |
| IP-Adressen | Rate-Limits, Audit | nur als gesalzener SHA-256-Hash | Rate-Limits nach 2 Tagen |
| Kostenloser Check | Kurzbericht | `public_checks` | nach 7 Tagen |
| Leads (Tabelle vorbereitet, Formular noch nicht aktiv) | Vertrieb (nur mit Einwilligung) | `leads` | nach 12 Monaten |
| Audit-Logs | Nachweis/Sicherheit | append-only | Aufbewahrung festlegen (Empfehlung 2 Jahre, dann Archiv/Löschung per Wartungsjob durch DB-Owner) |

## Betroffenenrechte
- **Auskunft/Export (Art. 15/20):** Einstellungen → „Alle Daten exportieren“ (JSON, `GET /api/export`).
- **Löschung (Art. 17):** Inhaber löscht die Organisation (Bestätigung per Firmenname); sofortiger Stopp aller Prüfungen, endgültige Löschung nach 30 Tagen (Wartungsjob `applyRetention`).
- **Berichtigung:** Organisationsdaten in den Einstellungen.

## Technisch-organisatorische Maßnahmen (Auszug)
- Transportverschlüsselung (HSTS, TLS), Verschlüsselung at rest (Supabase), zusätzliche Feldverschlüsselung für Breach-Konten.
- Mandantentrennung per RLS + serverseitiger Rechteprüfung, getestet.
- Rollenmodell: Inhaber / Administrator / Mitglied / Lesezugriff; vollständige Breach-Adressen nur für Administratoren.
- Append-only Audit-Log aller sicherheitsrelevanten Aktionen (inkl. Admin-Aktionen).
- Ratenbegrenzung, Input-Validierung (Zod), sichere Datei-Uploads (Typ-Allowlist, Magic-Bytes, Größenlimit, zufällige Pfade).
- Secrets ausschließlich in Umgebungsvariablen / Secret-Stores; `.env*` von Git ausgeschlossen.
- Supply-Chain: `minimumReleaseAge` (24 h) für npm-Pakete, gepinnte Scanner-Versionen.

## Auftragsverarbeiter / Drittanbieter (vor Go-Live AVV abschließen)
| Anbieter | Zweck | Ort | Hinweis |
|---|---|---|---|
| Supabase | DB/Auth/Storage | EU (Frankfurt wählen) | AVV verfügbar |
| Vercel | Hosting Web | global/EU | AVV + SCC |
| Resend | E-Mail | USA | AVV + SCC |
| Stripe | Zahlungen | USA/IE | eigener Verantwortlicher für Zahlungsdaten |
| Have I Been Pwned | Breach-Daten | AUS | Übermittelt wird nur die Domain; Ergebnisse enthalten E-Mail-Aliase |
| Shodan InternetDB | Port-/CVE-Daten | USA | Übermittelt werden nur öffentliche IP-Adressen; **Enterprise-Lizenz für kommerzielle Nutzung erforderlich** |
| crt.sh / Cert Spotter | CT-Logs | UK/USA | nur Domain |

## Rechtliche Absicherung der Prüfungen
- DNS-TXT-Nachweis der Domain-Kontrolle + versionierte schriftliche Autorisierung mit Name, Funktion, Zeitstempel, SHA-256 des Erklärungstextes, IP-Hash und User-Agent.
- Prüfungen bleiben auf freigegebene Prüfarten und die verifizierte Domain beschränkt; Weiterleitungen auf fremde Domains werden nicht verfolgt.
- Aktive Schwachstellenprüfungen nur nach gesonderter Freigabe je System durch den Inhaber.
