import { beforeAll, describe, expect, it } from "vitest";
import { encryptField, hmac } from "@/lib/core/crypto";
import { createOrgWithDomain, createUser, service } from "./helpers";

/**
 * Mandantentrennung: Nutzer A darf unter keinen Umständen Daten von Organisation B lesen oder ändern.
 * Tests laufen gegen die echte lokale Supabase (PostgREST + RLS + Storage).
 */
describe("Cross-Tenant-Isolation (RLS)", () => {
  let a: Awaited<ReturnType<typeof createUser>>;
  let b: Awaited<ReturnType<typeof createUser>>;
  let orgA: { orgId: string; domainId: string };
  let orgB: { orgId: string; domainId: string };
  let findingB: string;
  let incidentB: string;

  beforeAll(async () => {
    a = await createUser("tenant-a");
    b = await createUser("tenant-b");
    orgA = await createOrgWithDomain(a.id, "Firma A", `a-${Date.now()}.de`);
    orgB = await createOrgWithDomain(b.id, "Firma B", `b-${Date.now()}.de`);
    const { data: f } = await service
      .from("findings")
      .insert({ org_id: orgB.orgId, domain_id: orgB.domainId, asset_value: "b.de", fingerprint: `fp-${Date.now()}`, rule_id: "dns.caa.missing", check_key: "dns.caa", category: "dns", source: "dns", title: "Geheim B", summary: "s", business_impact: "b", recommendation: "r", technical_details: "t", severity: "low", certainty: "confirmed", confidence: "high" })
      .select("id")
      .single();
    findingB = f!.id;
    await service.from("breach_records").insert({ org_id: orgB.orgId, domain_id: orgB.domainId, finding_id: findingB, provider: "hibp", account_hmac: hmac("x@b.de"), account_enc: encryptField("x@b.de"), breach_key: "Adobe" });
    const { data: inc } = await service.from("incidents").insert({ org_id: orgB.orgId, type: "phishing", priority: "p2", title: "Vorfall B" }).select("id").single();
    incidentB = inc!.id;
    await service.from("notifications").insert({ org_id: orgB.orgId, type: "x", title: "Nachricht B", body: "b", dedupe_key: `k-${Date.now()}` });
    await service.from("timeline_events").insert({ org_id: orgB.orgId, type: "scan_completed", title: "B" });
    await service.storage.from("incident-files").upload(`${orgB.orgId}/${incidentB}/geheim.txt`, Buffer.from("geheim"), { contentType: "text/plain" });
  });

  it("A sieht eigene, aber keine fremden Organisationen", async () => {
    const { data } = await a.client.from("organizations").select("id, name");
    expect(data!.map((o) => o.id)).toEqual([orgA.orgId]);
  });

  it.each(["domains", "findings", "finding_events", "incidents", "notifications", "timeline_events", "scan_authorizations", "subscriptions", "memberships", "assets", "scan_jobs", "reports", "actions", "breach_records"] as const)(
    "A kann %s von B nicht lesen",
    async (table) => {
      const { data, error } = await a.client.from(table).select("org_id").eq("org_id", orgB.orgId);
      expect(error).toBeNull();
      expect(data).toEqual([]);
    },
  );

  it("B sieht eigene Befunde, aber nie verschlüsselte Konto-Rohdaten", async () => {
    const { data } = await b.client.from("findings").select("id").eq("id", findingB);
    expect(data).toHaveLength(1);
    const { error } = await b.client.from("breach_records").select("account_enc");
    expect(error).not.toBeNull(); // Spaltenrecht verweigert
    const { data: meta } = await b.client.from("breach_records").select("breach_key").eq("org_id", orgB.orgId);
    expect(meta).toEqual([{ breach_key: "Adobe" }]);
  });

  it("A kann nichts schreiben – weder fremd noch eigen (Schreiben nur serverseitig)", async () => {
    const ins = await a.client.from("domains").insert({ org_id: orgB.orgId, hostname: "evil.de" });
    expect(ins.error).not.toBeNull();
    const own = await a.client.from("domains").insert({ org_id: orgA.orgId, hostname: "own.de" });
    expect(own.error).not.toBeNull();
    const upd = await a.client.from("findings").update({ status: "resolved" }).eq("id", findingB).select();
    expect(upd.data ?? []).toHaveLength(0);
    const del = await a.client.from("incidents").delete().eq("id", incidentB).select();
    expect(del.data ?? []).toHaveLength(0);
    const { data: still } = await service.from("incidents").select("id").eq("id", incidentB);
    expect(still).toHaveLength(1);
  });

  it("A kann sich nicht selbst in Organisation B eintragen (Rechteausweitung)", async () => {
    const { error } = await a.client.from("memberships").insert({ org_id: orgB.orgId, user_id: a.id, role: "owner" });
    expect(error).not.toBeNull();
    const { error: subErr } = await a.client.from("subscriptions").update({ status: "active", plan_key: "shield_care" }).eq("org_id", orgA.orgId);
    const { data: sub } = await service.from("subscriptions").select("status").eq("org_id", orgA.orgId).single();
    expect(subErr !== null || sub!.status === "trialing").toBe(true);
    expect(sub!.status).toBe("trialing");
  });

  it("Privilegierte RPCs sind für Clients gesperrt", async () => {
    for (const [fn, args] of [
      ["claim_scan_job", { p_worker: "x", p_kinds: ["domain_scan"] }],
      ["create_organization", { p_user: a.id, p_name: "X", p_industry: "", p_employee_range: "", p_contact_email: "" }],
      ["rate_limit_hit", { p_key: "x", p_window_seconds: 60, p_max: 1 }],
      ["requeue_stale_jobs", { p_stale_seconds: 1 }],
    ] as const) {
      const { error } = await a.client.rpc(fn as never, args as never);
      expect(error, fn).not.toBeNull();
    }
  });

  it("Sensible Systemtabellen sind unlesbar", async () => {
    for (const t of ["stripe_events", "leads", "public_checks", "rate_limits"] as const) {
      const { data, error } = await a.client.from(t).select("*").limit(1);
      expect(error !== null || (data ?? []).length === 0, t).toBe(true);
    }
    const { error } = await a.client.from("service_provider_invites").select("token_hash");
    expect(error).not.toBeNull();
  });

  it("Storage: fremde Vorfall-Dateien sind weder auflistbar noch abrufbar", async () => {
    const { data: list } = await a.client.storage.from("incident-files").list(`${orgB.orgId}/${incidentB}`);
    expect(list ?? []).toHaveLength(0);
    const { data: dl } = await a.client.storage.from("incident-files").download(`${orgB.orgId}/${incidentB}/geheim.txt`);
    expect(dl).toBeNull();
    const up = await a.client.storage.from("incident-files").upload(`${orgB.orgId}/x.txt`, Buffer.from("x"));
    expect(up.error).not.toBeNull();
  });

  it("Anonyme Nutzer sehen nichts", async () => {
    const { createClient } = await import("@supabase/supabase-js");
    const anon = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
    const { data } = await anon.from("findings").select("id").limit(1);
    expect(data ?? []).toHaveLength(0);
  });

  it("Audit-Log ist unveränderbar – selbst für die Service Role", async () => {
    const { data } = await service.from("audit_logs").insert({ org_id: orgA.orgId, actor_type: "system", action: "test" }).select("id").single();
    const { error } = await service.from("audit_logs").update({ action: "manipuliert" }).eq("id", data!.id);
    expect(error?.message).toMatch(/append-only/);
    const { error: delErr } = await service.from("audit_logs").delete().eq("id", data!.id);
    expect(delErr?.message).toMatch(/append-only/);
  });
});

describe("Demo-Trennung (Datenbank-Constraints)", () => {
  it("verhindert Demo-Daten in Kundenorganisationen und umgekehrt", async () => {
    const u = await createUser("demo-sep");
    const { orgId, domainId } = await createOrgWithDomain(u.id, "Echt GmbH", `echt-${Date.now()}.de`);
    const demoFinding = await service.from("findings").insert({ org_id: orgId, domain_id: domainId, asset_value: "x", fingerprint: "demo-x", rule_id: "dns.caa.missing", check_key: "dns.caa", category: "dns", source: "dns", title: "t", summary: "s", business_impact: "b", recommendation: "r", technical_details: "t", severity: "low", certainty: "confirmed", confidence: "high", is_demo: true });
    expect(demoFinding.error?.message).toMatch(/demo separation/);
    const demoDomain = await service.from("domains").insert({ org_id: orgId, hostname: "fake.example" });
    expect(demoDomain.error).not.toBeNull();
    const synthetic = await service.from("breach_records").insert({ org_id: orgId, domain_id: domainId, provider: "demo", account_hmac: "h", account_enc: "e", breach_key: "k", is_synthetic: true });
    expect(synthetic.error?.message).toMatch(/synthetic/);
    const flip = await service.from("organizations").update({ is_demo: true }).eq("id", orgId);
    expect(flip.error?.message).toMatch(/immutable/);
  });
});
