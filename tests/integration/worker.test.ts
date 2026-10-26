import { beforeAll, describe, expect, it } from "vitest";
import type { AdapterRun } from "@/lib/core/scanners/runner";
import type { AdapterOutput } from "@/lib/core/scanners/types";
import { persistFindings } from "../../worker/persist";
import { processEmailOutbox, MAX_EMAILS_PER_ORG_PER_DAY } from "../../worker/mailer";
import { enqueueDueScans } from "../../worker/scheduler";
import { processJob } from "../../worker/index";
import { createOrgWithDomain, createUser, log, service } from "./helpers";

const deps = () => ({ db: service, env: process.env as Record<string, string | undefined>, log, workerId: "test" });

function run(adapter: string, out: Partial<AdapterOutput>): AdapterRun {
  return { adapter, startedAt: new Date(), finishedAt: new Date(), output: { status: "ok", observations: [], coverage: [], discoveredAssets: [], targets: [], data: {}, ...out } };
}

describe("Job-Queue (Postgres, SKIP LOCKED)", () => {
  let org: { orgId: string; domainId: string };
  beforeAll(async () => {
    // Fremde Jobs aus anderen Tests aus dem Weg räumen
    await service.from("scan_jobs").update({ status: "cancelled" }).in("status", ["queued", "running"]);
    const u = await createUser("queue");
    org = await createOrgWithDomain(u.id, "Queue GmbH", `queue-${Date.now()}.de`);
  });

  it("parallele Worker erhalten nie denselben Job; max. ein laufender Job pro Organisation", async () => {
    const u2 = await createUser("queue2");
    const org2 = await createOrgWithDomain(u2.id, "Queue2 GmbH", `queue2-${Date.now()}.de`);
    const ids: string[] = [];
    for (const [o, k] of [[org, "a"], [org, "b"], [org2, "c"]] as const) {
      const { data } = await service.from("scan_jobs").insert({ org_id: o.orgId, domain_id: o.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: `q-${k}-${Date.now()}` }).select("id").single();
      ids.push(data!.id);
    }
    // Mehrere Polling-Runden mit je 6 parallelen Workern (wie im Betrieb)
    const claimed: Array<{ id: string; org_id: string }> = [];
    for (let round = 0; round < 3; round++) {
      const claims = await Promise.all(Array.from({ length: 6 }, (_, i) => service.rpc("claim_scan_job", { p_worker: `w${i}`, p_kinds: ["domain_scan"] })));
      claimed.push(...claims.flatMap((c) => (c.data as Array<{ id: string; org_id: string }>) ?? []));
    }
    expect(new Set(claimed.map((c) => c.id)).size).toBe(claimed.length);
    expect(claimed.filter((c) => c.org_id === org.orgId)).toHaveLength(1);
    expect(claimed.filter((c) => c.org_id === org2.orgId)).toHaveLength(1);
    await service.from("scan_jobs").update({ status: "cancelled" }).in("id", ids);
  });

  it("Idempotenz-Schlüssel verhindert doppelte Jobs", async () => {
    const key = `idem-${Date.now()}`;
    await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: key, status: "cancelled" });
    const dup = await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: key });
    expect(dup.error?.code).toBe("23505");
  });

  it("Demo-Mandanten werden nie gescannt", async () => {
    const { data: demo } = await service.from("organizations").insert({ name: "Demo Q", is_demo: true }).select("id").single();
    await service.from("scan_jobs").insert({ org_id: demo!.id, kind: "domain_scan", trigger: "manual", idempotency_key: `demo-${Date.now()}` });
    const { data } = await service.rpc("claim_scan_job", { p_worker: "w", p_kinds: ["domain_scan"] });
    expect(((data as Array<{ org_id: string }>) ?? []).some((j) => j.org_id === demo!.id)).toBe(false);
    await service.from("organizations").delete().eq("id", demo!.id);
  });

  it("hängende Jobs werden wieder eingeplant bzw. endgültig fehlgeschlagen", async () => {
    const old = new Date(Date.now() - 3600_000).toISOString();
    const { data: j1 } = await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: `stale1-${Date.now()}`, status: "running", attempts: 1, heartbeat_at: old }).select("id").single();
    const { data: j2 } = await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: `stale2-${Date.now()}`, status: "running", attempts: 3, heartbeat_at: old }).select("id").single();
    await service.rpc("requeue_stale_jobs", { p_stale_seconds: 300 });
    const { data } = await service.from("scan_jobs").select("id, status").in("id", [j1!.id, j2!.id]);
    expect(data!.find((j) => j.id === j1!.id)!.status).toBe("queued");
    expect(data!.find((j) => j.id === j2!.id)!.status).toBe("failed");
    await service.from("scan_jobs").update({ status: "cancelled" }).eq("id", j1!.id);
  });

  it("nicht wiederholbare Fehler -> failed + Benachrichtigung; sonst Retry mit Backoff", async () => {
    // Domain ohne Autorisierung -> NonRetryableError
    await service.from("scan_authorizations").update({ revoked_at: new Date().toISOString() }).eq("domain_id", org.domainId);
    const { data: job } = await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: `na-${Date.now()}`, status: "running", attempts: 1 }).select("*").single();
    await processJob(job!, deps());
    const { data: after } = await service.from("scan_jobs").select("status, error").eq("id", job!.id).single();
    expect(after!.status).toBe("failed");
    expect(after!.error).toMatch(/Autorisierung/);
    const { data: notes } = await service.from("notifications").select("type").eq("org_id", org.orgId).eq("type", "scan_failed");
    expect(notes!.length).toBe(1);

    const { data: job2 } = await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "reverify", trigger: "manual", idempotency_key: `rt-${Date.now()}`, status: "running", attempts: 1, payload: {} }).select("*").single();
    await processJob(job2!, deps()); // ungültiger Reverify -> NonRetryable
    expect((await service.from("scan_jobs").select("status").eq("id", job2!.id).single()).data!.status).toBe("failed");
  });
});

describe("Persistenz: Deduplizierung, Änderungserkennung, Nachprüfung, Benachrichtigungen", () => {
  let org: { orgId: string; domainId: string };
  let jobId: string;
  const apex = `persist-${Date.now()}.de`;
  beforeAll(async () => {
    const u = await createUser("persist");
    org = await createOrgWithDomain(u.id, "Persist GmbH", apex);
    const { data } = await service.from("scan_jobs").insert({ org_id: org.orgId, domain_id: org.domainId, kind: "domain_scan", trigger: "manual", idempotency_key: `p-${Date.now()}`, status: "cancelled" }).select("id").single();
    jobId = data!.id;
  });

  const dmarcMissing = () => ({ ruleId: "email.dmarc.missing", asset: apex, facts: { hasMx: true }, evidence: {} });
  const dangling = () => ({ ruleId: "dns.dangling_cname", asset: `old.${apex}`, discriminator: "t.example", facts: { target: "t.example" }, evidence: {} });
  const cov = [{ asset: apex, check: "email.dmarc" }, { asset: `old.${apex}`, check: "dns.dangling" }];
  const persist = (observations: ReturnType<typeof dmarcMissing>[], coverage = cov) =>
    persistFindings(service, { orgId: org.orgId, domainId: org.domainId, apex, jobId, runs: [run("dns", { observations, coverage })] });

  it("erster Lauf erzeugt Befunde, Ereignisse, Timeline und genau eine Warnung je hohem Befund", async () => {
    const s = await persist([dmarcMissing(), dangling()]);
    expect(s.created).toBe(2);
    const { data: n } = await service.from("notifications").select("title").eq("org_id", org.orgId);
    expect(n!.length).toBe(1); // nur der hohe Befund (dangling) löst eine Warnung aus
  });

  it("identischer Lauf erzeugt keine neuen Befunde oder Benachrichtigungen", async () => {
    const s = await persist([dmarcMissing(), dangling()]);
    expect(s.created).toBe(0);
    const { count } = await service.from("findings").select("id", { count: "exact", head: true }).eq("org_id", org.orgId);
    expect(count).toBe(2);
    const { data: n } = await service.from("notifications").select("id").eq("org_id", org.orgId);
    expect(n!.length).toBe(1);
  });

  it("vom Kunden als behoben markiert, aber weiterhin vorhanden -> wieder offen + 'weiterhin vorhanden'", async () => {
    await service.from("findings").update({ status: "resolved", verification_state: "unverified" }).eq("org_id", org.orgId).eq("rule_id", "email.dmarc.missing");
    const s = await persist([dmarcMissing(), dangling()]);
    expect(s.stillPresent).toBe(1);
    const { data: f } = await service.from("findings").select("status, verification_state, reopened_count").eq("org_id", org.orgId).eq("rule_id", "email.dmarc.missing").single();
    expect(f).toMatchObject({ status: "action_required", verification_state: "still_present", reopened_count: 1 });
  });

  it("nicht mehr beobachtet UND Prüfung lief -> technisch bestätigt behoben", async () => {
    const s = await persist([dangling()]);
    expect(s.verifiedFixed).toBe(1);
    const { data: f } = await service.from("findings").select("status, verification_state").eq("org_id", org.orgId).eq("rule_id", "email.dmarc.missing").single();
    expect(f).toMatchObject({ status: "resolved", verification_state: "verified_fixed" });
    const { data: ev } = await service.from("timeline_events").select("type").eq("org_id", org.orgId).eq("type", "reverify_passed");
    expect(ev!.length).toBe(1);
  });

  it("ohne Abdeckung (Prüfung fehlgeschlagen) bleibt der Status unverändert", async () => {
    const s = await persistFindings(service, { orgId: org.orgId, domainId: org.domainId, apex, jobId, runs: [run("dns", { status: "error", observations: [], coverage: [] })] });
    expect(s.verifiedFixed).toBe(0);
    const { data: f } = await service.from("findings").select("status").eq("org_id", org.orgId).eq("rule_id", "dns.dangling_cname").single();
    expect(f!.status).toBe("new");
  });

  it("Breach-Konten werden verschlüsselt und pseudonymisiert gespeichert", async () => {
    await persistFindings(service, {
      orgId: org.orgId,
      domainId: org.domainId,
      apex,
      jobId,
      runs: [run("hibp", {
        observations: [{ ruleId: "breach.accounts_exposed", asset: apex, discriminator: "Adobe", facts: { accountCount: 1, breachTitle: "Adobe", dataClasses: ["Passwords"], breachAgeDays: 3000 }, evidence: {} }],
        coverage: [{ asset: apex, check: "breach.domain" }],
        breachRecords: [{ provider: "hibp", account: `anna@${apex}`, breachKey: "Adobe", breachTitle: "Adobe", breachDate: "2013-10-04", breachAddedAt: null, dataClasses: ["Passwords"], isStealerLog: false, isSynthetic: false, findingRuleId: "breach.accounts_exposed", findingDiscriminator: "Adobe" }],
      })],
    });
    const { data } = await service.from("breach_records").select("account_enc, account_hmac, finding_id").eq("org_id", org.orgId).single();
    expect(data!.account_enc).not.toContain("anna");
    expect(data!.account_hmac).toMatch(/^[0-9a-f]{64}$/);
    expect(data!.finding_id).not.toBeNull();
  });
});

describe("E-Mail-Benachrichtigungen", () => {
  it("ohne Konfiguration: nichts versenden, ehrlich markieren", async () => {
    const u = await createUser("mail");
    const { orgId } = await createOrgWithDomain(u.id, "Mail GmbH", `mail-${Date.now()}.de`);
    await service.from("notifications").insert({ org_id: orgId, type: "x", severity: "warning", title: "T", body: "B", dedupe_key: "m1", email_status: "pending" });
    await processEmailOutbox({ ...deps(), env: { ...process.env, RESEND_API_KEY: "" } });
    const { data } = await service.from("notifications").select("email_status").eq("org_id", orgId).single();
    expect(data!.email_status).toBe("skipped");
  });
  it("Tageslimit und Demo-Sperre (mit simuliertem Versand)", async () => {
    const u = await createUser("mail2");
    const { orgId } = await createOrgWithDomain(u.id, "Mail2 GmbH", `mail2-${Date.now()}.de`);
    const rows = Array.from({ length: MAX_EMAILS_PER_ORG_PER_DAY }, (_, i) => ({ org_id: orgId, type: "x", severity: "warning", title: "T", body: "B", dedupe_key: `s${i}`, email_status: "sent", email_sent_at: new Date().toISOString() }));
    await service.from("notifications").insert(rows);
    await service.from("notifications").insert({ org_id: orgId, type: "x", severity: "warning", title: "T", body: "B", dedupe_key: "over", email_status: "pending" });
    const { data: demo } = await service.from("organizations").insert({ name: "Demo Mail", is_demo: true }).select("id").single();
    await service.from("notifications").insert({ org_id: demo!.id, type: "x", severity: "warning", title: "T", body: "B", dedupe_key: "d", email_status: "pending" });
    await processEmailOutbox({ ...deps(), env: { ...process.env, RESEND_API_KEY: "re_test", EMAIL_FROM: "x@example.org" } });
    expect((await service.from("notifications").select("email_status").eq("org_id", orgId).eq("dedupe_key", "over").single()).data!.email_status).toBe("suppressed");
    expect((await service.from("notifications").select("email_status").eq("org_id", demo!.id).single()).data!.email_status).toBe("skipped");
    await service.from("organizations").delete().eq("id", demo!.id);
  });
  it("Deduplizierung über dedupe_key", async () => {
    const u = await createUser("dedupe");
    const { orgId } = await createOrgWithDomain(u.id, "Dedupe GmbH", `dd-${Date.now()}.de`);
    const { notify } = await import("@/lib/core/events");
    expect(await notify(service, { orgId, type: "x", severity: "info", title: "a", body: "b", dedupeKey: "same" })).toBe(true);
    expect(await notify(service, { orgId, type: "x", severity: "info", title: "a", body: "b", dedupeKey: "same" })).toBe(false);
  });
});

describe("Scheduler", () => {
  it("plant fällige Prüfungen idempotent ein und überspringt Domains ohne Autorisierung", async () => {
    await service.from("domains").update({ next_scan_at: new Date(Date.now() + 86_400_000).toISOString() }).not("id", "is", null);
    const u = await createUser("sched");
    const a = await createOrgWithDomain(u.id, "Sched GmbH", `sched-${Date.now()}.de`);
    const u2 = await createUser("sched2");
    const b = await createOrgWithDomain(u2.id, "Sched2 GmbH", `sched2-${Date.now()}.de`);
    await service.from("scan_authorizations").update({ revoked_at: new Date().toISOString() }).eq("domain_id", b.domainId);
    const due = new Date(Date.now() - 1000).toISOString();
    await service.from("domains").update({ next_scan_at: due }).in("id", [a.domainId, b.domainId]);
    expect(await enqueueDueScans(deps())).toBe(1);
    expect(await enqueueDueScans(deps())).toBe(0);
    const { data } = await service.from("scan_jobs").select("domain_id").eq("trigger", "schedule").in("domain_id", [a.domainId, b.domainId]);
    expect(data!.map((d) => d.domain_id)).toEqual([a.domainId]);
    await service.from("scan_jobs").update({ status: "cancelled" }).eq("domain_id", a.domainId);
  });
});
