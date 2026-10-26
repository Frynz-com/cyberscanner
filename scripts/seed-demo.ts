/**
 * Erstellt bzw. setzt den Demo-Mandanten zurück.
 *   pnpm demo:seed
 * Alle Daten sind synthetisch, als DEMO gekennzeichnet und technisch von Kundendaten getrennt
 * (organizations.is_demo, Domains auf reservierter TLD .example, DB-Trigger, Worker scannt nie Demo-Mandanten).
 */
import "../worker/load-env";
import { createHmac } from "node:crypto";
import { createServiceClient } from "../worker/deps";
import { encryptField, hmac, sha256 } from "../src/lib/core/crypto";
import { buildReportSnapshot } from "../src/lib/core/report-data";
import { normalizeObservation } from "../src/lib/core/risk/engine";
import type { Observation } from "../src/lib/core/risk/types";

const env = process.env as Record<string, string | undefined>;
const db = createServiceClient(env);
const APEX = "muster-maschinenbau.example";
const ORG_NAME = "Muster Maschinenbau GmbH (DEMO)";
const DAY = 86_400_000;
const ago = (days: number, hours = 9) => new Date(Date.now() - days * DAY + (hours - 12) * 3600_000).toISOString();

export function demoPartnerToken(): string {
  return createHmac("sha256", env.DATA_ENCRYPTION_KEY ?? "demo").update("cybersafe24-demo-partner").digest("base64url").slice(0, 43);
}

async function ensureDemoUser(): Promise<string> {
  const email = env.DEMO_USER_EMAIL;
  const password = env.DEMO_USER_PASSWORD;
  if (!email || !password) throw new Error("DEMO_USER_EMAIL und DEMO_USER_PASSWORD müssen gesetzt sein");
  const { data: list } = await db.auth.admin.listUsers({ perPage: 1000 });
  const existing = list.users.find((u) => u.email === email);
  if (existing) {
    await db.auth.admin.updateUserById(existing.id, { password, app_metadata: { demo: true } });
    return existing.id;
  }
  const { data, error } = await db.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name: "Demo Vertrieb" }, app_metadata: { demo: true } });
  if (error || !data.user) throw new Error(`Demo-Nutzer: ${error?.message}`);
  return data.user.id;
}

async function main() {
  const userId = await ensureDemoUser();
  // Zurücksetzen: Demo-Organisation(en) vollständig löschen (Kaskade)
  const { data: old } = await db.from("organizations").select("id").eq("is_demo", true);
  for (const o of old ?? []) await db.from("organizations").delete().eq("id", o.id);

  const { data: org, error: orgErr } = await db
    .from("organizations")
    .insert({ name: ORG_NAME, industry: "Maschinenbau", employee_range: "50-249", contact_email: "it@muster-maschinenbau.example", is_demo: true, onboarding_step: 7, created_at: ago(45) })
    .select("id")
    .single();
  if (orgErr) throw orgErr;
  const orgId = org.id;
  await db.from("memberships").insert({ org_id: orgId, user_id: userId, role: "admin" });
  await db.from("subscriptions").insert({ org_id: orgId, plan_key: "shield_care", status: "active", current_period_end: new Date(Date.now() + 20 * DAY).toISOString() });

  const { data: domain } = await db
    .from("domains")
    .insert({ org_id: orgId, hostname: APEX, is_demo: true, verification_status: "verified", verified_at: ago(44), verification_last_checked_at: ago(1), scan_interval_hours: 24, last_scan_at: ago(0, 6), next_scan_at: new Date(Date.now() + 18 * 3600_000).toISOString(), created_at: ago(45) })
    .select("id")
    .single();
  const domainId = domain!.id;
  await db.from("verification_challenges").insert({ org_id: orgId, domain_id: domainId, record_name: `_cybersafe24-verification.${APEX}`, token: "cs24-verify=DEMO", consumed_at: ago(44), last_result: "present" });
  await db.from("scan_authorizations").insert({
    org_id: orgId, domain_id: domainId, scopes: ["passive", "config"], include_subdomains: true, statement_version: "2026-10-v1",
    statement_sha256: sha256("demo"), signer_name: "Petra Muster", signer_role: "Geschäftsführerin", granted_by: userId, granted_at: ago(44),
  });

  // Assets (synthetisch, reservierte TLD / Dokumentations-IPs)
  const subs = ["www", "mail", "shop", "portal", "vpn", "alt-shop", "b2b", "autodiscover"];
  const assets = [
    { kind: "domain", value: APEX, sources: ["customer"], first: 44 },
    ...subs.map((s, i) => ({ kind: "subdomain", value: `${s}.${APEX}`, sources: i % 2 ? ["subfinder:crtsh", "ct:crt.sh"] : ["subfinder:anubis"], first: s === "b2b" ? 3 : 43 })),
    { kind: "ip", value: "203.0.113.10", sources: ["dns"], first: 43 },
    { kind: "ip", value: "203.0.113.25", sources: ["dns"], first: 43 },
  ];
  await db.from("assets").insert(assets.map((a) => ({ org_id: orgId, domain_id: domainId, kind: a.kind, value: a.value, sources: a.sources, is_demo: true, first_seen_at: ago(a.first), last_seen_at: ago(0, 6), metadata: a.value.startsWith("alt-shop") ? { dangling: true } : {} })));

  // Prüfläufe (synthetische Historie)
  const jobIds: string[] = [];
  for (const d of [42, 35, 28, 21, 14, 7, 1, 0]) {
    const { data: j } = await db
      .from("scan_jobs")
      .insert({ org_id: orgId, domain_id: domainId, kind: "domain_scan", trigger: d === 42 ? "onboarding" : "schedule", status: "succeeded", idempotency_key: `demo:${d}`, attempts: 1, created_at: ago(d, 6), started_at: ago(d, 6), finished_at: ago(d, 6), summary: { demo: true } })
      .select("id")
      .single();
    jobIds.push(j!.id);
  }
  const lastJob = jobIds[jobIds.length - 1];
  const adapters = ["subfinder", "ct_logs", "dns", "tls", "http_headers", "internetdb", "hibp", "hudsonrock", "ransomware_live", "lookalike"];
  await db.from("scan_results").insert(adapters.map((a) => ({ job_id: lastJob, org_id: orgId, domain_id: domainId, adapter: a, status: "ok", started_at: ago(0, 6), finished_at: ago(0, 6), duration_ms: 1000 + Math.round(Math.random() * 20000), targets: [APEX], checks: [], message: "DEMO – synthetisches Ergebnis", data: { demo: true } })));
  await db.from("scan_results").insert({ job_id: lastJob, org_id: orgId, domain_id: domainId, adapter: "nuclei", status: "not_authorized", started_at: ago(0, 6), finished_at: ago(0, 6), duration_ms: 1, message: "Keine Assets für aktive Prüfung freigegeben", data: {} });

  // Befunde – über die echte Regel-Engine erzeugt, damit Texte und Bewertung identisch zur Produktion sind
  type Spec = { o: Observation; source: string; firstSeen: number; status: string; resolvedDaysAgo?: number; verification?: string | null; shared?: boolean };
  const specs: Spec[] = [
    { o: { ruleId: "email.dmarc.missing", asset: APEX, facts: { hasMx: true }, evidence: {} }, source: "dns", firstSeen: 42, status: "resolved", resolvedDaysAgo: 33, verification: "verified_fixed", shared: true },
    { o: { ruleId: "email.dmarc.policy_none", asset: APEX, facts: { record: "v=DMARC1; p=none; rua=mailto:dmarc@muster-maschinenbau.example" }, evidence: { record: "v=DMARC1; p=none; rua=mailto:dmarc@muster-maschinenbau.example" } }, source: "dns", firstSeen: 33, status: "investigating" },
    { o: { ruleId: "web.headers.hsts_missing", asset: `www.${APEX}`, facts: { url: `https://www.${APEX}/` }, evidence: { url: `https://www.${APEX}/` } }, source: "http_headers", firstSeen: 42, status: "resolved", resolvedDaysAgo: 14, verification: "verified_fixed", shared: true },
    { o: { ruleId: "tls.cert.expiring", asset: `shop.${APEX}`, facts: { daysLeft: 12, validTo: new Date(Date.now() + 12 * DAY).toISOString().slice(0, 10), subject: `shop.${APEX}`, issuer: "R11" }, evidence: { daysLeft: 12 } }, source: "tls", firstSeen: 18, status: "action_required", shared: true },
    { o: { ruleId: "dns.dangling_cname", asset: `alt-shop.${APEX}`, discriminator: "muster-alt.shopsystem.example", facts: { target: "muster-alt.shopsystem.example" }, evidence: { target: "muster-alt.shopsystem.example" } }, source: "dns", firstSeen: 7, status: "action_required" },
    { o: { ruleId: "exposure.risky_service", asset: "203.0.113.25", discriminator: "3389", facts: { port: 3389 }, evidence: { ports: [443, 3389], hostnames: [`vpn.${APEX}`], source: "Shodan InternetDB (DEMO)" } }, source: "internetdb", firstSeen: 21, status: "new" },
    { o: { ruleId: "exposure.cve_hint", asset: "203.0.113.25", discriminator: "CVE-2019-0708", facts: { cve: "CVE-2019-0708", kev: true }, evidence: { cpes: ["cpe:/o:microsoft:windows"], source: "Shodan InternetDB (DEMO)" }, sourceRef: "https://nvd.nist.gov/vuln/detail/CVE-2019-0708" }, source: "internetdb", firstSeen: 21, status: "new" },
    { o: { ruleId: "breach.accounts_exposed", asset: APEX, discriminator: "Canva", facts: { accountCount: 3, breachKey: "Canva", breachTitle: "Canva", breachDate: "2019-05-24", addedDate: "2019-08-09", dataClasses: ["Email addresses", "Names", "Passwords", "Usernames"], breachAgeDays: 2700, isSpamList: false }, evidence: { breach: "Canva", accountCount: 3, source: "DEMO – synthetische Testdaten" } }, source: "hibp", firstSeen: 40, status: "action_required" },
    { o: { ruleId: "breach.stealer_log", asset: APEX, discriminator: "stealer", facts: { accountCount: 1 }, evidence: { websites: ["portal.lieferant.example", "login.microsoftonline.example"], source: "DEMO – synthetische Testdaten" } }, source: "hibp", firstSeen: 2, status: "new" },
    { o: { ruleId: "intel.infostealer_employees", asset: APEX, discriminator: "employees", facts: { employees: 3, ageDays: 19, lastCompromised: ago(19).slice(0, 10), urls: [`https://vpn.${APEX}/remote/login`, `https://outlook.office.com (${APEX}-Konten)`, `https://portal.${APEX}/login`], passwordStrength: "2 von 3 schwach", families: "Lumma, RedLine", recentBreach: true }, evidence: { employees: 3, source: "DEMO – synthetische Testdaten" } }, source: "hudsonrock", firstSeen: 4, status: "new" },
    { o: { ruleId: "brand.lookalike_domain", asset: APEX, discriminator: "rnuster-maschinenbau.example", facts: { lookalike: "rnuster-maschinenbau.example", technique: "Verwechslungszeichen", hasMx: true, a: ["203.0.113.66"], mx: ["10 mx.rnuster-maschinenbau.example"] }, evidence: { lookalike: "rnuster-maschinenbau.example" } }, source: "lookalike", firstSeen: 1, status: "new" },
    { o: { ruleId: "brand.lookalike_domain", asset: APEX, discriminator: "muster-maschinenbau-rechnung.example", facts: { lookalike: "muster-maschinenbau-rechnung.example", technique: "Zusatzwort", hasMx: true, a: ["203.0.113.67"], mx: ["10 mail.muster-maschinenbau-rechnung.example"] }, evidence: { lookalike: "muster-maschinenbau-rechnung.example" } }, source: "lookalike", firstSeen: 6, status: "action_required" },
    { o: { ruleId: "email.dkim.not_checkable", asset: APEX, facts: {}, evidence: { selectorsTried: ["selector1", "selector2", "google", "default"] } }, source: "dns", firstSeen: 42, status: "new" },
    { o: { ruleId: "web.headers.csp_missing", asset: `shop.${APEX}`, facts: { url: `https://shop.${APEX}/` }, evidence: { url: `https://shop.${APEX}/` } }, source: "http_headers", firstSeen: 42, status: "accepted_risk" },
    { o: { ruleId: "web.security_txt.missing", asset: APEX, facts: { status: 404 }, evidence: { status: 404 } }, source: "http_headers", firstSeen: 42, status: "new" },
    { o: { ruleId: "dns.caa.missing", asset: APEX, facts: {}, evidence: {} }, source: "dns", firstSeen: 42, status: "resolved", resolvedDaysAgo: 2, verification: "unverified" },
    { o: { ruleId: "web.redirect.no_https", asset: `portal.${APEX}`, facts: { status: 200 }, evidence: { status: 200 } }, source: "http_headers", firstSeen: 28, status: "resolved", resolvedDaysAgo: 20, verification: "verified_fixed" },
  ];

  const { data: invite } = await db
    .from("service_provider_invites")
    .insert({ org_id: orgId, email: "service@it-partner-nord.example", contact_name: "Jan Beispiel", company_name: "IT-Partner Nord (DEMO)", token_hash: sha256(demoPartnerToken()), expires_at: new Date(Date.now() + 60 * DAY).toISOString(), created_by: userId, created_at: ago(39), last_access_at: ago(1) })
    .select("id")
    .single();

  for (const s of specs) {
    const n = normalizeObservation(s.o, s.source, APEX);
    const { data: f, error } = await db
      .from("findings")
      .insert({
        org_id: orgId, domain_id: domainId, asset_value: n.asset, fingerprint: n.fingerprint, rule_id: n.ruleId, check_key: n.check, category: n.category,
        source: n.source, source_ref: n.sourceRef, title: n.title, summary: n.summary, business_impact: n.businessImpact, recommendation: n.recommendation,
        technical_details: n.technicalDetails, verification_steps: n.verificationSteps, docs: JSON.parse(JSON.stringify(n.docs)), evidence: JSON.parse(JSON.stringify(n.evidence)),
        severity: n.severity, certainty: n.certainty, confidence: n.confidence, priority_score: n.priorityScore, priority_reasons: n.priorityReasons,
        status: s.status as never, verification_state: s.verification ?? null, is_demo: true, first_seen_at: ago(s.firstSeen, 6),
        last_seen_at: s.status === "resolved" ? ago(s.resolvedDaysAgo ?? 0, 6) : ago(0, 6), resolved_at: s.resolvedDaysAgo !== undefined ? ago(s.resolvedDaysAgo, 7) : null, created_at: ago(s.firstSeen, 6),
      })
      .select("id")
      .single();
    if (error) throw error;
    const events: Array<Record<string, unknown>> = [{ type: "detected", to_status: "new", actor_type: "system", actor_label: s.source, message: "Erstmals erkannt (DEMO)", created_at: ago(s.firstSeen, 6) }];
    if (s.shared && invite) {
      await db.from("service_provider_shares").insert({ invite_id: invite.id, finding_id: f.id, org_id: orgId });
      const actionStatus = s.verification === "verified_fixed" ? "verified" : "in_progress";
      await db.from("actions").insert({ org_id: orgId, finding_id: f.id, invite_id: invite.id, status: actionStatus, created_by: userId, created_at: ago(s.firstSeen - 2) });
      events.push({ type: "shared_with_partner", actor_type: "user", actor_label: "Petra Muster", message: "An IT-Partner Nord (DEMO) übergeben", created_at: ago(s.firstSeen - 2) });
      events.push({ type: "partner_update", actor_type: "partner", actor_label: "IT-Partner Nord (DEMO)", message: "Bearbeitung gestartet", created_at: ago(s.firstSeen - 3) });
    }
    if (s.verification === "verified_fixed") {
      events.push({ type: "partner_update", actor_type: "partner", actor_label: "IT-Partner Nord (DEMO)", message: "Maßnahme umgesetzt – Nachprüfung angefordert", created_at: ago(s.resolvedDaysAgo!, 6) });
      events.push({ type: "reverify_requested", actor_type: "partner", message: "Nachprüfung angefordert", created_at: ago(s.resolvedDaysAgo!, 6) });
      events.push({ type: "verified_fixed", from_status: "action_required", to_status: "resolved", actor_type: "system", message: "Nachprüfung erfolgreich: Problem nicht mehr festgestellt.", created_at: ago(s.resolvedDaysAgo!, 7) });
    }
    if (s.verification === "unverified") events.push({ type: "status_changed", from_status: "new", to_status: "resolved", actor_type: "user", actor_label: "Petra Muster", message: "Als behoben markiert – Bestätigung durch Nachprüfung ausstehend", created_at: ago(s.resolvedDaysAgo!, 8) });
    if (s.status === "accepted_risk") events.push({ type: "status_changed", from_status: "new", to_status: "accepted_risk", actor_type: "user", actor_label: "Petra Muster", message: "Shop-System des Anbieters erlaubt derzeit keine CSP; Risiko bis zum Relaunch akzeptiert.", created_at: ago(30) });
    if (s.status === "investigating") events.push({ type: "status_changed", from_status: "new", to_status: "investigating", actor_type: "user", actor_label: "Petra Muster", message: "DMARC-Berichte werden ausgewertet, danach Umstellung auf quarantine.", created_at: ago(25) });
    await db.from("finding_events").insert(events.map((e) => ({ org_id: orgId, finding_id: f.id, ...e })) as never);

    if (n.category === "breach") {
      const accounts = n.ruleId === "breach.stealer_log" ? ["einkauf"] : ["vertrieb", "m.beispiel", "praktikum"];
      await db.from("breach_records").insert(accounts.map((a) => ({
        org_id: orgId, domain_id: domainId, finding_id: f.id, provider: "demo", account_hmac: hmac(`${a}@${APEX}`), account_enc: encryptField(`${a}@${APEX}`),
        breach_key: n.ruleId === "breach.stealer_log" ? "stealer-logs" : "Canva", breach_title: n.ruleId === "breach.stealer_log" ? "Infostealer-Logs (DEMO)" : "Canva", breach_date: n.ruleId === "breach.stealer_log" ? null : "2019-05-24",
        data_classes: n.ruleId === "breach.stealer_log" ? ["Infostealer"] : ["Email addresses", "Names", "Passwords"], is_stealer_log: n.ruleId === "breach.stealer_log", is_synthetic: true, first_observed_at: ago(s.firstSeen),
      })));
    }

    const tl: Array<Record<string, unknown>> = [];
    if (n.severity !== "info") tl.push({ type: n.category === "breach" ? "breach_detected" : "finding_detected", severity: n.severity, title: n.title, body: `${n.asset} · DEMO`, link: `/app/findings/${f.id}`, finding_id: f.id, created_at: ago(s.firstSeen, 6) });
    if (s.shared) tl.push({ type: "shared_with_partner", severity: "info", title: `An IT-Partner Nord (DEMO) übergeben: ${n.title}`, link: `/app/findings/${f.id}`, finding_id: f.id, created_at: ago(s.firstSeen - 2) });
    if (s.verification === "verified_fixed") tl.push({ type: "reverify_passed", severity: "success", title: `Behebung bestätigt: ${n.title}`, link: `/app/findings/${f.id}`, finding_id: f.id, created_at: ago(s.resolvedDaysAgo!, 7) });
    if (tl.length) await db.from("timeline_events").insert(tl.map((t) => ({ org_id: orgId, domain_id: domainId, is_demo: true, ...t })) as never);
  }

  const scanTl = [42, 35, 28, 21, 14, 7, 1, 0].map((d) => ({ org_id: orgId, domain_id: domainId, is_demo: true, type: "scan_completed", severity: "success", title: `Prüfung von ${APEX} abgeschlossen`, body: "10 Hosts geprüft · DEMO", link: "/app", created_at: ago(d, 6) }));
  await db.from("timeline_events").insert([
    ...scanTl,
    { org_id: orgId, domain_id: domainId, is_demo: true, type: "domain_verified", severity: "success", title: `Domain ${APEX} verifiziert`, created_at: ago(44) },
    { org_id: orgId, domain_id: domainId, is_demo: true, type: "asset_discovered", severity: "info", title: "1 neue Subdomain entdeckt", body: `b2b.${APEX}`, link: "/app/assets", created_at: ago(3, 6) },
  ]);

  // Notfall-Beispiel
  const { data: inc } = await db
    .from("incidents")
    .insert({ org_id: orgId, type: "phishing", priority: "p2", status: "contained", title: "Phishing-Vorfall", description: "Mitarbeiterin aus dem Einkauf hat auf einen Link in einer gefälschten Lieferanten-E-Mail geklickt und Zugangsdaten eingegeben. (DEMO)", reporter_name: "Petra Muster", is_demo: true, created_at: ago(10), reported_by: userId })
    .select("id")
    .single();
  await db.from("incident_events").insert([
    { org_id: orgId, incident_id: inc!.id, type: "created", message: "Vorfall gemeldet (Hoch).", actor_label: "Petra Muster", created_at: ago(10) },
    { org_id: orgId, incident_id: inc!.id, type: "checklist", message: "Erledigt: Wurden Zugangsdaten eingegeben: Passwort sofort ändern und Sitzungen abmelden.", actor_label: "Petra Muster", created_at: ago(10, 10) },
    { org_id: orgId, incident_id: inc!.id, type: "notification_sent", message: "Benachrichtigung an IT-Partner Nord (DEMO) – im Demo-Modus nicht versendet", created_at: ago(10, 10) },
    { org_id: orgId, incident_id: inc!.id, type: "status_changed", message: "Status: Eingedämmt", actor_label: "Petra Muster", created_at: ago(9) },
  ]);
  await db.from("timeline_events").insert({ org_id: orgId, is_demo: true, type: "incident_reported", severity: "high", title: "Vorfall gemeldet: Phishing-Vorfall", link: `/app/emergency/${inc!.id}`, created_at: ago(10) });

  // Benachrichtigungen (nur In-App; Demo-Mandanten erhalten nie E-Mails)
  await db.from("notifications").insert([
    { org_id: orgId, type: "breach", severity: "warning", title: "Neuer Befund: Hinweis auf Infostealer-Infektion (1 Konto/Konten)", body: "DEMO – synthetischer Hinweis.", link: "/app/findings", dedupe_key: "demo-1", email_status: "skipped", created_at: ago(2) },
    { org_id: orgId, type: "asset", severity: "info", title: `Neue Subdomain(s) für ${APEX}`, body: `b2b.${APEX}`, link: "/app/assets", dedupe_key: "demo-2", email_status: "skipped", created_at: ago(3) },
    { org_id: orgId, type: "report", severity: "info", title: "Ihr Sicherheitsbericht ist verfügbar", body: "DEMO", link: "/app/reports", dedupe_key: "demo-3", email_status: "skipped", created_at: ago(25), read_at: ago(24) },
  ]);

  // Musterbericht aus den Demo-Daten (Vormonat)
  const now = new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) - 1);
  const snapshot = await buildReportSnapshot(db, orgId, start, end);
  await db.from("reports").insert({ org_id: orgId, kind: "monthly", period_start: start.toISOString(), period_end: end.toISOString(), snapshot: JSON.parse(JSON.stringify(snapshot)), is_demo: true, created_at: ago(25) });
  await db.from("timeline_events").insert({ org_id: orgId, is_demo: true, type: "report_created", severity: "info", title: "Monatsbericht erstellt", link: "/app/reports", created_at: ago(25) });

  console.log(JSON.stringify({ ok: true, orgId, demoUser: env.DEMO_USER_EMAIL, partnerLink: `${env.APP_URL ?? "http://localhost:3000"}/partner/${demoPartnerToken()}` }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
