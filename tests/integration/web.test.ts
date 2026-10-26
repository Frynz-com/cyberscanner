import { beforeAll, describe, expect, it } from "vitest";
import Stripe from "stripe";
import { renderToBuffer } from "@react-pdf/renderer";
import { createElement } from "react";
import { randomToken, sha256 } from "@/lib/core/crypto";
import { buildReportSnapshot } from "@/lib/core/report-data";
import { ReportDocument } from "@/lib/pdf/report-document";
import { resolvePartnerToken } from "@/lib/server/partner";
import { createOrgWithDomain, createUser, service } from "./helpers";

process.env.STRIPE_SECRET_KEY = "sk_test_dummy";
process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_secret";
process.env.STRIPE_PRICE_SHIELD = "price_shield_test";
process.env.STRIPE_PRICE_SHIELD_CARE = "price_care_test";

const stripe = new Stripe("sk_test_dummy");

async function postWebhook(payload: object, secret = process.env.STRIPE_WEBHOOK_SECRET!) {
  const { POST } = await import("@/app/api/stripe/webhook/route");
  const body = JSON.stringify(payload);
  const header = stripe.webhooks.generateTestHeaderString({ payload: body, secret });
  return POST(new Request("http://localhost/api/stripe/webhook", { method: "POST", body, headers: { "stripe-signature": header } }));
}

describe("Stripe-Webhook", () => {
  let orgId: string;
  const cus = `cus_${Date.now()}`;
  const subId = `sub_${Date.now()}`;
  beforeAll(async () => {
    const u = await createUser("stripe");
    ({ orgId } = await createOrgWithDomain(u.id, "Stripe GmbH", `stripe-${Date.now()}.de`));
  });
  const subEvent = (id: string, status: string, price = "price_care_test") => ({
    id,
    object: "event",
    type: "customer.subscription.updated",
    data: { object: { id: subId, object: "subscription", customer: cus, status, cancel_at_period_end: false, metadata: { org_id: orgId }, items: { data: [{ price: { id: price }, current_period_end: Math.floor(Date.now() / 1000) + 2592000 }] } } },
  });

  it("lehnt ungültige Signaturen ab", async () => {
    const res = await postWebhook(subEvent(`evt_bad_${Date.now()}`, "active"), "whsec_falsch");
    expect(res.status).toBe(400);
    const { data } = await service.from("subscriptions").select("status").eq("org_id", orgId).single();
    expect(data!.status).toBe("trialing");
  });

  it("schaltet Tarif und Status serverseitig frei – idempotent", async () => {
    const id = `evt_${Date.now()}`;
    expect((await postWebhook(subEvent(id, "active"))).status).toBe(200);
    const { data } = await service.from("subscriptions").select("status, plan_key, stripe_subscription_id").eq("org_id", orgId).single();
    expect(data).toMatchObject({ status: "active", plan_key: "shield_care", stripe_subscription_id: subId });
    const dup = await postWebhook(subEvent(id, "canceled"));
    expect(await dup.json()).toMatchObject({ duplicate: true });
    expect((await service.from("subscriptions").select("status").eq("org_id", orgId).single()).data!.status).toBe("active");
  });

  it("Zahlungsfehler und Kündigung erzeugen Benachrichtigungen", async () => {
    await postWebhook({ id: `evt_pf_${Date.now()}`, object: "event", type: "invoice.payment_failed", data: { object: { id: `in_${Date.now()}`, object: "invoice", customer: cus } } });
    await postWebhook({ ...subEvent(`evt_del_${Date.now()}`, "canceled"), type: "customer.subscription.deleted" });
    const { data } = await service.from("notifications").select("title").eq("org_id", orgId).eq("type", "billing");
    expect(data!.map((d) => d.title).sort()).toEqual(["Abonnement beendet", "Zahlung fehlgeschlagen"]);
    expect((await service.from("subscriptions").select("status").eq("org_id", orgId).single()).data!.status).toBe("canceled");
  });
});

describe("IT-Dienstleister-Freigaben", () => {
  let orgId: string;
  let findingId: string;
  const token = randomToken(32);
  beforeAll(async () => {
    const u = await createUser("partner");
    const o = await createOrgWithDomain(u.id, "Partner GmbH", `partner-${Date.now()}.de`);
    orgId = o.orgId;
    const { data: f } = await service.from("findings").insert({ org_id: orgId, domain_id: o.domainId, asset_value: "x", fingerprint: `pf-${Date.now()}`, rule_id: "dns.caa.missing", check_key: "dns.caa", category: "dns", source: "dns", title: "t", summary: "s", business_impact: "b", recommendation: "r", technical_details: "t", severity: "low", certainty: "confirmed", confidence: "high" }).select("id").single();
    findingId = f!.id;
    const { data: inv } = await service.from("service_provider_invites").insert({ org_id: orgId, email: "it@partner.example", token_hash: sha256(token), expires_at: new Date(Date.now() + 86_400_000).toISOString() }).select("id").single();
    await service.from("service_provider_shares").insert({ invite_id: inv!.id, finding_id: findingId, org_id: orgId });
  });
  it("gültiges Token gewährt nur Zugriff auf freigegebene Befunde", async () => {
    const s = await resolvePartnerToken(token);
    expect(s).toMatchObject({ orgId, findingIds: [findingId] });
  });
  it("falsche, abgelaufene und widerrufene Tokens werden abgelehnt", async () => {
    expect(await resolvePartnerToken(randomToken(32))).toBeNull();
    expect(await resolvePartnerToken("../../etc")).toBeNull();
    await service.from("service_provider_invites").update({ expires_at: new Date(Date.now() - 1000).toISOString() }).eq("token_hash", sha256(token));
    expect(await resolvePartnerToken(token)).toBeNull();
    await service.from("service_provider_invites").update({ expires_at: new Date(Date.now() + 86_400_000).toISOString(), revoked_at: new Date().toISOString() }).eq("token_hash", sha256(token));
    expect(await resolvePartnerToken(token)).toBeNull();
  });
});

describe("PDF-Bericht", () => {
  it("erzeugt ein gültiges PDF aus echten gespeicherten Daten", async () => {
    const u = await createUser("pdf");
    const { orgId, domainId } = await createOrgWithDomain(u.id, "PDF Müller & Söhne GmbH", `pdf-${Date.now()}.de`);
    await service.from("findings").insert({ org_id: orgId, domain_id: domainId, asset_value: "pdf.de", fingerprint: `pdf-${Date.now()}`, rule_id: "tls.cert.expiring", check_key: "tls.cert", category: "tls", source: "tls", title: "Zertifikat läuft ab (≤ 7 Tage) → handeln", summary: "s", business_impact: "b", recommendation: "r", technical_details: "t", severity: "high", certainty: "confirmed", confidence: "high" });
    const snap = await buildReportSnapshot(service, orgId, new Date(Date.now() - 30 * 86_400_000), new Date());
    expect(snap.counts.open).toBe(1);
    expect(snap.organization.name).toBe("PDF Müller & Söhne GmbH");
    const pdf = await renderToBuffer(createElement(ReportDocument, { snap }) as never);
    expect(pdf.subarray(0, 4).toString()).toBe("%PDF");
    expect(pdf.length).toBeGreaterThan(5000);
  });
});
