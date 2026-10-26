"use server";

import { redirect } from "next/navigation";
import { z } from "zod";
import { auditUser, authorizeOrg } from "@/lib/server/auth";
import { getStripe, priceIdForPlan, stripeConfigured } from "@/lib/server/stripe";
import { runAction, UserError, type ActionResult } from "@/lib/server/action";

export async function startCheckoutAction(orgId: string, planKey: string): Promise<ActionResult> {
  let url: string | null = null;
  const res = await runAction<undefined>(async () => {
    const { admin, user, isDemo } = await authorizeOrg(z.uuid().parse(orgId), "owner");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    if (!stripeConfigured()) throw new UserError("Die Zahlungsabwicklung ist noch nicht eingerichtet. Bitte kontaktieren Sie uns.");
    const { data: plan } = await admin.from("plans").select("key, stripe_price_env, active").eq("key", z.string().parse(planKey)).single();
    const price = plan?.active ? priceIdForPlan(plan.stripe_price_env) : null;
    if (!price) throw new UserError("Dieser Tarif ist nicht buchbar.");
    const stripe = getStripe();
    const { data: sub } = await admin.from("subscriptions").select("stripe_customer_id").eq("org_id", orgId).maybeSingle();
    const { data: org } = await admin.from("organizations").select("name, contact_email").eq("id", orgId).single();
    let customer = sub?.stripe_customer_id ?? null;
    if (!customer) {
      const c = await stripe.customers.create({ name: org?.name, email: user.email ?? org?.contact_email ?? undefined, metadata: { org_id: orgId } });
      customer = c.id;
      await admin.from("subscriptions").update({ stripe_customer_id: customer }).eq("org_id", orgId);
    }
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer,
      client_reference_id: orgId,
      line_items: [{ price, quantity: 1 }],
      subscription_data: { metadata: { org_id: orgId } },
      metadata: { org_id: orgId },
      billing_address_collection: "required",
      tax_id_collection: { enabled: true },
      automatic_tax: { enabled: process.env.STRIPE_AUTOMATIC_TAX === "true" },
      customer_update: { address: "auto", name: "auto" },
      locale: "de",
      success_url: `${process.env.APP_URL}/app/settings?billing=success`,
      cancel_url: `${process.env.APP_URL}/app/settings?billing=cancelled`,
    });
    await auditUser(orgId, user.id, "billing.checkout_started", undefined, { plan: planKey });
    url = session.url;
    return { ok: true as const };
  });
  if (res.ok && url) redirect(url);
  return res;
}

export async function openBillingPortalAction(orgId: string): Promise<ActionResult> {
  let url: string | null = null;
  const res = await runAction<undefined>(async () => {
    const { admin, isDemo } = await authorizeOrg(z.uuid().parse(orgId), "owner");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    if (!stripeConfigured()) throw new UserError("Die Zahlungsabwicklung ist noch nicht eingerichtet.");
    const { data: sub } = await admin.from("subscriptions").select("stripe_customer_id").eq("org_id", orgId).maybeSingle();
    if (!sub?.stripe_customer_id) throw new UserError("Es besteht noch kein Kundenkonto bei unserem Zahlungsdienstleister.");
    const s = await getStripe().billingPortal.sessions.create({ customer: sub.stripe_customer_id, return_url: `${process.env.APP_URL}/app/settings`, locale: "de" });
    url = s.url;
    return { ok: true as const };
  });
  if (res.ok && url) redirect(url);
  return res;
}
