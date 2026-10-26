# CyberSafe24 Shield

External Attack Surface Monitoring, Datenleck-Hinweise und Fix & Verify für mittelständische Unternehmen.

> „Wir überwachen die extern sichtbaren Cyberrisiken Ihres Unternehmens, warnen bei bekannten Datenlecks und Sicherheitsproblemen und helfen bei der Behebung.“

**Stack:** Next.js 16 (App Router, TypeScript, Tailwind v4, shadcn/ui) · Supabase (Postgres + RLS, Auth, Storage) · Zod · Stripe · Resend · @react-pdf/renderer · Docker-Worker mit ProjectDiscovery Subfinder/Nuclei.

Dokumentation: [Architektur](docs/ARCHITECTURE.md) · [Deployment](docs/DEPLOYMENT.md) · [Bedrohungsmodell](docs/THREAT_MODEL.md) · [Sicherheit & Datenschutz](docs/SECURITY_PRIVACY.md) · [Projektstatus](PROGRESS.md)

## Schnellstart (lokal)

Voraussetzungen: Node 22, pnpm 10, Docker, Supabase CLI ≥ 2.122, optional Go ≥ 1.26 (für Subfinder).

```bash
pnpm install
supabase start -x studio,imgproxy,edge-runtime,logflare,vector,supavisor,realtime,mailpit
cp .env.example .env.local
#   NEXT_PUBLIC_SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY aus `supabase status` übernehmen
#   DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
#   DEMO_USER_PASSWORD=<zufällig>
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0   # optional

pnpm dev            # Web-App: http://localhost:3000
pnpm worker         # Scan-Worker (separates Terminal)
pnpm demo:seed      # Demo-Mandant anlegen/zurücksetzen → http://localhost:3000/demo
```

Hinweis zur Domain-Verifikation lokal: Für eine eigene Domain den angezeigten TXT-Eintrag
`_cybersafe24-verification.<domain>` anlegen. Ohne eigene Domain kann die Verifikation in der lokalen DB gesetzt werden
(`update domains set verification_status='verified' …`) – genau so verfahren die E2E-Tests.

## Skripte

| Befehl | Zweck |
|---|---|
| `pnpm dev` / `pnpm build` / `pnpm start` | Web-App |
| `pnpm worker` | Scan-Worker (Queue, Scheduler, E-Mails, Berichte, Retention) |
| `pnpm lint` / `pnpm typecheck` | Qualität |
| `pnpm test` | Unit-Tests (Adapter mit Fixtures, Risk Engine, SSRF-Schutz) |
| `pnpm test:integration` | gegen lokale Supabase: RLS/Cross-Tenant, Queue, Dedup, Webhooks, PDF (`LIVE_SCANS=1` für echte Netzwerkscans) |
| `pnpm test:e2e` | Playwright: Hauptnutzerfluss mit echtem Scanner, Free Check, Demo, Mobile |
| `pnpm demo:seed` | Demo-Mandant (synthetisch, klar gekennzeichnet) |
| `pnpm db:types` | Supabase-Typen generieren |
| `pnpm tsx scripts/grant-admin.ts <email>` | Plattform-Admin ernennen |

## Worker als Container

```bash
docker build -f deploy/worker.Dockerfile -t cybersafe24-worker .
docker compose -f deploy/docker-compose.worker.yml --env-file /etc/cybersafe24/worker.env up -d
```
