# Deployment – CyberSafe24 Shield

Drei Komponenten:

| Komponente | Plattform | Aufgabe |
|---|---|---|
| Web-App (Next.js 16) | Vercel | UI, Server Actions, Stripe-Webhook, PDF-Erzeugung. **Führt keine Scans aus**, legt nur Jobs an. |
| Datenbank/Auth/Storage | Supabase (Region **eu-central-1 / Frankfurt** wählen) | Postgres mit RLS, Auth, private Buckets |
| Scan-Worker | eigener Docker-Host (z. B. Hetzner/IONOS in DE) | Job-Queue, Scanner, Scheduler, E-Mail-Versand, Monatsberichte, Retention |

## 1. Supabase

1. Projekt in Frankfurt anlegen, Point-in-Time-Recovery aktivieren (Pro-Plan).
2. Migrationen einspielen:
   ```bash
   supabase link --project-ref <ref>
   supabase db push
   ```
3. Auth → URL-Konfiguration: `Site URL = https://app.cybersafe24.de`, Redirect `https://app.cybersafe24.de/**`.
4. Auth → E-Mail-Bestätigung **aktiv**; E-Mail-Template „Confirm signup“ auf
   `{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=email&next={{ .RedirectTo }}` umstellen; eigenen SMTP (Resend) hinterlegen.
5. Passwortrichtlinie: min. 10 Zeichen, Buchstaben + Ziffern (in `supabase/config.toml` für lokal bereits gesetzt).
6. Typen aktualisieren nach Schemaänderungen: `pnpm db:types`.

## 2. Web-App auf Vercel

Environment Variables (Production):

| Variable | Pflicht | Hinweis |
|---|---|---|
| `APP_URL` | ✔ | `https://app.cybersafe24.de` |
| `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` | ✔ | öffentlich |
| `SUPABASE_SERVICE_ROLE_KEY` | ✔ | **Sensitive**, nie `NEXT_PUBLIC_` |
| `DATA_ENCRYPTION_KEY` | ✔ | `openssl rand -base64 32`; identisch im Worker; sicher verwahren (Verlust = Breach-Konten unlesbar) |
| `RESEND_API_KEY`, `EMAIL_FROM` | optional | ohne Werte: keine E-Mails (ehrlich als „nicht versendet“ markiert) |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_SHIELD`, `STRIPE_PRICE_SHIELD_CARE` | optional | ohne Werte: Checkout deaktiviert |
| `STRIPE_AUTOMATIC_TAX` | optional | `true`, wenn Stripe Tax eingerichtet |
| `DEMO_USER_EMAIL`, `DEMO_USER_PASSWORD` | optional | für `/demo` |
| `EMERGENCY_PARTNER_*` | optional | **nur** bei bestehendem Vertrag mit Notfall-Dienstleister |

Stripe:
1. Produkte „Shield“ (249 € netto/Monat) und „Shield Care“ (499 € netto/Monat) als wiederkehrende Preise anlegen; Price-IDs in die ENV übernehmen. Preise stehen außerdem in `plans` (Migration) – nur für die Anzeige.
2. Webhook-Endpunkt `https://app.cybersafe24.de/api/stripe/webhook` mit Events: `checkout.session.completed`, `customer.subscription.created|updated|deleted`, `invoice.payment_failed`.
3. Customer Portal aktivieren (Kündigung, Zahlungsmittel, Rechnungen).

## 3. Scan-Worker

```bash
# auf dem Worker-Host
git clone … && cd cybersafe24-shield
sudo install -m 600 /dev/null /etc/cybersafe24/worker.env   # Secrets eintragen (siehe unten)
docker compose -f deploy/docker-compose.worker.yml --env-file /etc/cybersafe24/worker.env up -d --build
docker compose -f deploy/docker-compose.worker.yml logs -f
```

`worker.env`:
```
NODE_ENV=production
SUPABASE_URL=https://<ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=…
DATA_ENCRYPTION_KEY=…            # identisch zur Web-App
APP_URL=https://app.cybersafe24.de
RESEND_API_KEY=… / EMAIL_FROM=…
HIBP_API_KEY=…                   # optional
HIBP_STEALER_LOGS=false          # true nur mit Pro-Tarif
SHODAN_INTERNETDB_LICENSE=       # "enterprise" nur mit Lizenz
NUCLEI_ENABLED=false
WORKER_CONCURRENCY=2
```

Container-Härtung (bereits in `docker-compose.worker.yml`): non-root (UID 10001), read-only Root-FS, `cap_drop: ALL`, `no-new-privileges`, 1 CPU, 1 GB RAM, 256 PIDs.

### Egress-Firewall (zusätzlich zur Applikationsprüfung)
Der Worker prüft jede Zieladresse selbst (SSRF-Schutz). Als zweite Verteidigungslinie auf dem Host:
```bash
# Ausgehenden Verkehr des Docker-Netzes in private/Metadaten-Bereiche blockieren
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8; do
  iptables -I DOCKER-USER -d $net -j DROP
done
# Ausnahme: interner DNS des Hosts nur, falls benötigt (Worker nutzt DoH über 443)
```

### Skalierung
Mehrere Worker-Instanzen sind möglich: Jobs werden per `FOR UPDATE SKIP LOCKED` + Advisory-Lock pro Organisation übernommen; Scheduler-Einträge sind über Idempotenz-Schlüssel abgesichert.

## 4. Betrieb

| Thema | Umsetzung |
|---|---|
| Monitoring | Worker loggt strukturiertes JSON (stdout) → Log-Aggregation (z. B. Better Stack, Grafana Loki). Alarm auf `level=error` und auf `provider_integrations.status in ('degraded','unavailable')`. Admin-UI zeigt fehlgeschlagene Jobs und Provider-Status. |
| Fehlerüberwachung Web | Vercel-Logs; optional Sentry (`@sentry/nextjs`) ergänzen. |
| Health | `docker compose ps`; hängende Jobs werden automatisch nach 5 min wieder eingeplant (`requeue_stale_jobs`). |
| Backups | Supabase PITR (7–28 Tage). Zusätzlich täglicher logischer Dump: `pg_dump --format=custom "$DB_URL" > backup-$(date +%F).dump`, verschlüsselt (age/gpg) an zweiten Standort in der EU. Storage-Buckets per `supabase storage` bzw. S3-API sichern. |
| Restore-Test | quartalsweise: Dump in Staging-Projekt einspielen (`pg_restore --clean --no-owner`), Stichprobe: Login, Befunde, PDF-Bericht, Entschlüsselung eines Breach-Kontos (prüft `DATA_ENCRYPTION_KEY`). |
| Demo | `pnpm demo:seed` setzt den Demo-Mandanten vollständig zurück (z. B. nächtlich per Cron). |
| Plattform-Admin | `pnpm tsx scripts/grant-admin.ts admin@cybersafe24.de` |

## 5. Lokale Entwicklung

Siehe `README.md` → Schnellstart.
