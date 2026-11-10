# Vision – Außenwache + später digitale Köder

Stand: 2026-03-10 · Status: Strategieentwurf (noch nicht implementiert)  
Produktbasis: CyberSafe24 Shield (ASM + `intel_watch` + Risk Engine + Timeline)

Zielbild: Ein Unternehmen gibt **Domain (+ Marke, Kern-IDs)** an – und wird **von außen** dauerhaft bewacht. Sobald etwas in Leaks, Darknet-Signalen, Paste-/Chat-Kanälen, Code-Repos oder der Angriffsfläche auftaucht, gibt es **sofort Bescheid** – mit Gewissheit, Kontext und Handlung. Später ergänzt die **Innenwache** (digitale Köder) denselben Alarmpfad.

---

## 1. Was „mächtig“ hier wirklich heißt

Nicht: „Wir crawlen das ganze Darknet.“  
Sondern: **Wir sind die Korrelations- und Alarm-Schicht**, die aus vielen Quellen *frühe, verlässliche, handlungsfähige* Signale macht.

Macht entsteht aus fünf Hebeln:

| Hebel | Warum entscheidend |
|---|---|
| **Watchlist statt Domain-only** | Domain ist Einstieg. Mächtig wird es mit Marke, Alias-Domains, Exec-Mails (Hash), VPN/Login-Hosts, Cloud-Buckets, Zertifikat-SANs, GitHub-Orgs. |
| **Mehrspurige Collector** | Keine einzelne Quelle deckt Leaks + Ransomware + Stealer + Paste + Telegram + Code + Tor ab. |
| **Matching mit Gewissheit** | Exakter Treffer ≠ Fuzzy ≠ Gerücht. Deterministische Scores (wie die Risk Engine heute). |
| **Change Detection + Dedup** | „Neu“, „wieder da“, „bestätigt behoben“ – das haben wir schon; darauf bauen. |
| **Ein Alarmpfad** | Außenfund und Innen-Köder landen in denselben Findings / Timeline / Emergency Desk. |

Kommerzielle Vorbilder (Flare, SpyCloud, Recorded Future) verkaufen genau das: **Watchlists + Feeds + Korrelation + Alerting** – nicht den Claim „wir besitzen das Darknet“.

---

## 2. Open-Source-Landschaft – was wir stehlen dürfen (Ideen), was wir einbinden, was wir *nicht* nachbauen

### 2.1 Analyse-/Crawl-Workbenches (nicht als SaaS-Kern forkable)

| Projekt | Stärke | Für uns |
|---|---|---|
| **[AIL Framework](https://github.com/ail-project/AIL-framework)** (CIRCL, AGPL) | Tor/I2P/Clearweb-Crawl, Telegram/Discord-Feeder, Keyword/Regex/YARA, Retro-Hunt, MISP | **Lernmodell & optionaler Self-Host-Collector hinter unserer API** – nicht in den Next.js-Kern forkieren (AGPL + Ops). |
| **[SpiderFoot](https://github.com/smicallef/spiderfoot)** (MIT) | 200+ OSINT-Module, Tor-Anbindung | Inspiration für Modul-Graph; Community-Darkweb ist begrenzt, HX ist kommerziell. |
| **[IntelOwl](https://github.com/intelowlproject/IntelOwl)** (AGPL) | Enrichment-Orchestrator | Zeigt, wie man viele Analyzer hinter einer API orchestriert – unser Adapter-Muster ist die leichtere Variante. |

### 2.2 Spezialisierte Leak-/Ransomware-Quellen (hohe Wertschöpfung, schnell integrierbar)

| Projekt / Dienst | Stärke | Für uns |
|---|---|---|
| **ransomware.live** | Opfer auf Leakseiten | ✅ schon Adapter |
| **[RansomLook](https://github.com/RansomLook/RansomLook)** | Gruppen, Posts, Screenshots, Keyword-Mail, REST API, MISP | Nächster Adapter + optional eigener Mirror für Resilienz |
| **[Hudson Rock Cavalier](https://www.hudsonrock.com/)** | Infostealer nach Domain | ✅ schon Adapter |
| **Have I Been Pwned** | Domain-/Account-Breaches, Stealer | ✅ Adapter; Produktion braucht Key + Domain-Verify |
| **[LeakIX](https://leakix.net/)** | Öffentlich exponierte Services + Misconfig-Leaks (Git-Config, ES, …) | Sehr starker Außen-Adapter (scope=leak + hostname/domain) |
| **[PasteHunter](https://github.com/kevthehermit/PasteHunter)** | Paste-Sites + YARA | Pattern: Watchlist-YARA gegen Pastes (eigene, schlanke Pipeline) |
| **[deepdarkCTI](https://github.com/fastfire/deepdarkCTI)** | Kuratierte Telegram/Forum/Onion-Quellenliste | **Seed-Index**, kein Crawler – Futter für Lane „Chat/Tor“ |
| **[darkwatch](https://pypi.org/project/darkwatch/)** / **[NASO](https://github.com/fabriziosalmi/naso)** | Watchlist → mehrere Quellen → Score/Alert | Produktidee validiert; wir haben schon Multi-Tenant + Risk Engine |

### 2.3 Innenwache (Phase B, später)

| Projekt | Rolle |
|---|---|
| **[Canarytokens](https://github.com/thinkst/canarytokens)** | Digitale Köder (DNS, URL, Docs, AWS-Keys…) – Alarm bei Berührung |
| **[OpenCanary](https://github.com/thinkst/opencanary)** | Netzwerk-Honeypot (SSH/HTTP/DB…) – laterale Bewegung |

---

## 3. Die smarte Architektur: **Watchlist Cortex**

```
┌─────────────────────────────────────────────────────────────────┐
│  Kunde: Domain verifiziert + Watchlist (Marke, Aliase, IDs)     │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  ENTITY GRAPH (org-scoped)                                      │
│  domain · brand · email_hmac · host · asn · github_org · …      │
│  expanders: CT-SANs, Subdomains, Lookalikes, Login-URLs         │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
        ┌────────────── intel_watch / continuous lanes ──────────────┐
        │  L1 Curated feeds   L2 Index APIs   L3 Code/Cloud          │
        │  L4 Chat OSINT      L5 Tor hunts    L6 ASM delta           │
        └───────────────────────────┬────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  MATCHER → CONFIDENCE → Risk Rules → Findings / Timeline / Mail │
│  (fingerprint, seen_again, reappeared, verified_fixed)          │
└─────────────────────────────────────────────────────────────────┘
```

Passt **exakt** auf den bestehenden Stack:

- Adapter-Interface (`ScannerAdapter`) bleibt der Integrationsvertrag.
- `intel_watch` bleibt der leichte Dauerjob; neue Lanes = neue Adapter + Scheduler-Gewichte.
- `persistFindings` / Dedup / Notifications bleiben die Wahrheitsquelle für „Bescheid geben“.
- Kein Scan in der Web-Runtime; Tor-/Crawl-Worker ggf. **separater Container** mit eigenem Netz (nur L5).

### 3.1 Die sechs Außen-Lanes (Priorität)

| Lane | Was sie findet | Quellen (Beispiele) | Latenz-Ziel | Bauaufwand |
|---|---|---|---|---|
| **L1 Curated Ransom/Leak Feeds** | Opfer-Nennungen, Leak-Site-Posts | ransomware.live ✅, RansomLook, Ransomwatch-Derivate | Minuten–Stunden | niedrig |
| **L2 Breach & Stealer Indexes** | bekannte Breaches, Infostealer | HIBP ⚠️, Hudson Rock ✅, später SpyCloud/DeHashed | Stunden | niedrig–mittel |
| **L3 Exposed Surface Leaks** | offene DBs, `.git`, Panels, Credentials in Banner | LeakIX, InternetDB ⚠️, eigene Nuclei-Allowlist | Stunden | mittel |
| **L4 Code & Secret Exposure** | Secrets/Configs in GitHub/Gists/Public Repos | GitHub Code Search API, Gist-Feed, gitleaks-Regeln (nur Matching) | Stunden | mittel |
| **L5 Chat & Tor Mentions** | Domain/Marke in Telegram/Onion-Texten | deepdarkCTI-Seeds → Preview/Index; Ahmia; optional AIL-Feeder | Stunden–Tage | hoch (Ops/Recht) |
| **L6 ASM Delta** | neue Subdomains, Certs, Lookalikes, Header/TLS-Drift | Subfinder/CT/Lookalike ✅ + CT-Stream | Minuten (CT) / Stunden | mittel |

**Reihenfolge zum Bau:** L1→L3→L4→L6-Stream→L2-Vertiefung→L5.  
L5 ist das „Darknet-Gefühl“ – aber **ohne** L1–L4 ist es Show ohne Substanz.

### 3.2 Warum wir *nicht* „das Darknet selbst crawlen“ als Kern

1. **Ops:** Tor-Exit-Stabilität, Captchas, Mirror-Rotation, Screenshot-Pipelines = eigenes Produkt (AIL/RansomLook).
2. **Recht:** Unkontrolliertes Scraping von kriminellen Foren + Speicherung personenbezogener Leak-Daten = Haftung/DSGVO-Sprengstoff.
3. **Signal/Rausch:** Rohes Onion-HTML ohne Watchlist-Matcher erzeugt False Positives und Analysten-Müll.
4. **Differenzierung:** Kunden zahlen für **„meine Firma wurde genannt / geleakt / imitiert – was tun?“**, nicht für einen Tor-Browser mit Suche.

Strategie: **kuratierte Indizes + gezielte Hunts auf der Watchlist**. Optional später: self-hosted AIL/RansomLook als *unsere* Collector-Flotte hinter der gleichen Adapter-API.

---

## 4. Watchlist-Modell (Daten)

Minimaler Ausbau über das heutige `domains`-Modell:

```
watch_entities
  org_id, kind, value_normalized, value_hmac?, label, source, active, created_at
  kind ∈ domain | brand | email | host | github_org | bin_string | asn | keyword

watch_expansions (materialisiert, aus Scans)
  entity_id → derived (subdomain, lookalike, ct_san, login_url, …)

intel_observations (roh, vor Finding)
  lane, provider, raw_ref, matched_entity_id, match_type, confidence,
  observed_at, content_fingerprint, evidence_enc?
```

**Match-Typen (deterministisch):**

| match_type | Beispiel | confidence |
|---|---|---|
| `exact_domain` | `kunde.de` in Victim-Liste | confirmed |
| `exact_host` | `vpn.kunde.de` in Stealer-URL | confirmed |
| `brand_token` | Marke in Post-Titel (Token-Boundaries) | possible |
| `email_hmac` | Hash-Treffer in Breach | confirmed (nur Admins Klartext) |
| `fuzzy_victim` | „Kunde Beispiel GmbH“ ≈ Org-Name | possible → manuelle Bestätigung |
| `lookalike_active` | `kundee.de` resolved + Web | confirmed/possible je nach Signals |

Keine KI-Scores als Wahrheit – optional später nur für **Text-Zusammenfassung** vorhandener Evidenz (wie in PROGRESS schon angedacht).

---

## 5. Alarm-UX: „sobald es aufpoppt“

Bereits vorhanden: `intel_watch`-Intervall je Tarif, Dedup, E-Mail-Outbox, In-App, Emergency Desk.

Ausbaustufen:

1. **Sofort-Lane:** L1 + kritische L3 bei Treffer → Priority 1 Job + Push (Webhook/Slack später).
2. **Digest:** tägliche Zusammenfassung „neu / eskaliert / still_present“.
3. **CT-Near-Realtime:** Certificate-Transparency-Stream für Apex + Lookalikes (Minuten statt Stunden).
4. **Partner-Eskalation:** bestehendes Partner-Token + Emergency Desk bei `intel.ransomware_listing` / frischen Stealer-Employees.

Produktversprechen ehrlich halten: **kontinuierliche Überwachung bekannter Kanäle**, kein magisches 24/7 ohne Bereitschaftsvertrag.

---

## 6. Mapping auf den bestehenden Code

| Heute | Nächster Schritt |
|---|---|
| `INTEL_ADAPTERS = hibp, hudsonrock, ransomware_live, lookalike` | + `ransomlook`, `leakix`, `github_exposure`, `paste_watch` |
| `ScannerAdapter` + Risk Rules | neue `intel.*` / `leak.*` Regeln mit deutschen Entscheider-Texten |
| `PLANNED_PROVIDERS` (SpyCloud) | erweitern um LeakIX, RansomLook, optional AIL-bridge |
| Postgres-Queue | Lane-spezifische `kind` oder `priority` + `lane` Metadaten am Job |
| Worker-Container | optional zweiter Image-Tag `worker-tor` nur für L5 (Tor-Daemon, kein Kunden-Scan) |
| Findings / Timeline / PDF | Lane als Quelle in Abdeckungsmatrix; Methodik-Kapitel erweitern |

**Nicht anfassen ohne Bedarf:** Auth, RLS, Billing – die Außenwache hängt als Adapter + Entities + Scheduler dran.

---

## 7. Phase B – digitale Köder (Innenwache)

Erst nach stabiler Außenwache. Dieselben Findings:

| Köder-Typ | OSS-Vorbild | Signal |
|---|---|---|
| DNS-/URL-Token, Fake-Doc, Fake-AWS-Key | Canarytokens | Datenexfil / Neugier im Intranet |
| Decoy-SSH/HTTP/DB im Kundennnetz | OpenCanary | Scanning / Lateral Movement |
| Breadcrumbs (Links auf Decoys in echten Shares) | See–Think–Do (Sanders) | damit Angreifer sie *finden* |

Architektur: Canary-Events → Webhook in unsere API → Finding `deception.triggered` → Emergency Desk.  
Wir bauen **Orchestrierung + Alerting + Mandantenfähigkeit**, nicht zwingend den Token-Issuer von Null (Self-host Canarytokens oder Managed).

---

## 8. Roadmap (technisch, ohne Kalenderversprechen)

### Phase A0 – Schärfung des Bestehenden (kurz)
- HIBP produktiv schalten (Key + Domain-Verify-Prozess).
- RansomLook-Adapter (zweite Victim-Quelle, Dedup über Fingerprint).
- Watchlist v0: Marke + Org-Name für Fuzzy-Victim-Matching bei Ransomware.
- CT-Polling dichter / Stream-PoC für Lookalikes.

### Phase A1 – Leak Surface (der „krasse“ Außen-Check)
- LeakIX-Adapter: `hostname`/`domain` + scope=leak → Findings (offenes `.git`, ES, Configs).
- GitHub Code Search / öffentliche Gists auf Domain, `@domain`, typische Secret-Patterns (ohne Secrets zu speichern – nur Nachweis-Hashes/URLs).
- Erweiterter Free Check: „öffentliche Leak-Hinweise“ klar als Grenzen kennzeichnen.

### Phase A2 – Continuous Mention Watch
- Paste-Lane (YARA/Watchlist gegen öffentliche Pastes).
- Telegram-Lane über kuratierte deepdarkCTI-Kanäle (Preview/Index, keine Account-Übernahme).
- Optional: AIL als interner Collector (AGPL-isoliert), Ergebnisse nur als Observations über HTTP an den Shield-Worker.

### Phase A3 – Produktisierung
- Lane-Abdeckungs-UI („was wir wirklich sehen / nicht sehen“).
- Webhooks, Slack, SIEM-Export.
- Confidence-Calibration + False-Positive-Workflow schärfen.

### Phase B – Deception
- Canary-Token-Provisioning im Kundenportal.
- OpenCanary-Deploy-Guide / Partner-Appliance.
- Einheitliche Incident-Timeline Außen↔Innen.

---

## 9. Was uns gegen „nur ein weiterer Scanner“ gewinnt

1. **Ehrlichkeit als Feature** – Abdeckungsmatrix, „nicht prüfbar“, Methodik im PDF (schon DNA des Produkts).
2. **Fix & Verify** – Treffer ohne Behebungsweg sind Analysten-Spam; wir haben den Workflow.
3. **Mittelstand-UX** – deutsche Entscheider-Texte, IT-Partner-Portal, Emergency Desk.
4. **Determinismus** – nachvollziehbare Priorität statt Blackbox-AI-Threat-Score.
5. **Zwei Seiten einer Medaille** – Außenwache findet den Leak; Innenwache schlägt Alarm, wenn jemand schon drin ist.

---

## 10. Guardrails (verbindlich)

- Keine Speicherung von Klartext-Passwörtern aus Leaks; Accounts weiter AES-GCM + HMAC.
- Tor-/Forum-Crawl nur auf Watchlist-Treffer; Raw-Dumps nicht an Kunden durchreichen.
- Keine Nutzung der Plattform zum Angriff auf Dritte (bestehendes Threat Model G1/G3).
- Lizenzen klären vor Produktion: Hudson Rock, Shodan InternetDB, HIBP, LeakIX-Pläne, AGPL-Collector-Isolation.
- L5 nie im gleichen Container wie Kunden-ASM-Scans.

---

## 11. Empfohlene erste Bauentscheidung

**Nächster konkreter Slice:** Watchlist-Entity `brand` + Adapter `ransomlook` + Adapter `leakix` + Risk-Rules + Aufnahme in `INTEL_ADAPTERS`.

Damit wird aus „Domain eingeben → periodisch Intel“ eine echte **Außenwache**: Ransomware-Nennungen aus zwei Feeds, exponierte Leak-Oberflächen, und Marken-Treffer – ohne Darknet-Theater und ohne den bestehenden Kern zu zerlegen.

Phase B (Köder) bewusst danach: derselbe Alarmpfad, neuer Event-Producer.
