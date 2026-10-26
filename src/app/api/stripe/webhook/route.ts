import { NextResponse } from "next/server";
import type Stripe from "stripe";
import { audit, notify } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { getStripe, planKeyForPrice } from "@/lib/server/stripe";

export const runtime = "nodejs";

const STATUSES = new Set(["trialing", "active", "past_due", "canceled", "unpaid", "incomplete", "incomplete_expired", "paused"]);

/**
 * Stripe-Webhook: Signaturprüfung mit Rohdaten, idempotent über stripe_events.
 * Leistungen werden ausschließlich hier (serverseitig) freigeschaltet.
 */
export async function POST(req: Request) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret || !process.env.STRIPE_SECRET_KEY) return NextResponse.json({ error: "not configured" }, { status: 503 });
  const sig = req.headers.get("stripe-signature");
  const raw = await req.text();
  let event: Stripe.Event;
  try {
    event = getStripe().webhooks.constructEvent(raw, sig ?? "", secret);
  } catch {
    return NextResponse.json({ error: "invalid signature" }, { status: 400 });
  }
  const admin = createAdminClient();
  const { error: dup } = await admin.from("stripe_events").insert({ id: event.id, type: event.type });
  if (dup) {
    if (dup.code === "23505") return NextResponse.json({ received: true, duplicate: true });
    return NextResponse.json({ error: "db" }, { status: 500 });
  }
  try {
    await handleEvent(event);
  } catch (err) {
    // Event wieder freigeben, damit Stripe erneut zustellt
    await admin.from("stripe_events").delete().eq("id", event.id);
    console.error(JSON.stringify({ level: "error", msg: "stripe webhook failed", type: event.type, error: String(err) }));
    return NextResponse.json({ error: "handler failed" }, { status: 500 });
  }
  return NextResponse.json({ received: true });
}

async function handleEvent(event: Stripe.Event) {
  const admin = createAdminClient();
  if (event.type === "checkout.session.completed") {
    const s = event.data.object as Stripe.Checkout.Session;
    const orgId = s.client_reference_id ?? s.metadata?.org_id;
    if (!orgId) return;
    await admin.from("subscriptions").update({ stripe_customer_id: typeof s.customer === "string" ? s.customer : s.customer?.id, stripe_subscription_id: typeof s.subscription === "string" ? s.subscription : s.subscription?.id }).eq("org_id", orgId);
    await audit(admin, { orgId, actorType: "stripe", action: "billing.checkout_completed" });
    return;
  }
  if (event.type.startsWith("customer.subscription.")) {
    const sub = event.data.object as Stripe.Subscription;
    const orgId = sub.metadata?.org_id;
    if (!orgId) return;
    const { data: plans } = await admin.from("plans").select("key, stripe_price_env");
    const priceId = sub.items.data[0]?.price.id;
    const planKey = priceId ? planKeyForPrice(priceId, plans ?? []) : null;
    const status = event.type === "customer.subscription.deleted" ? "canceled" : STATUSES.has(sub.status) ? sub.status : "incomplete";
    const periodEnd = sub.items.data[0]?.current_period_end;
    await admin
      .from("subscriptions")
      .update({
        stripe_subscription_id: sub.id,
        stripe_customer_id: typeof sub.customer === "string" ? sub.customer : sub.customer.id,
        status,
        ...(planKey ? { plan_key: planKey } : {}),
        current_period_end: periodEnd ? new Date(periodEnd * 1000).toISOString() : null,
        cancel_at_period_end: sub.cancel_at_period_end,
        updated_at: new Date().toISOString(),
      })
      .eq("org_id", orgId);
    await audit(admin, { orgId, actorType: "stripe", action: `billing.${event.type.split(".").pop()}`, data: { status, plan: planKey } });
    if (event.type === "customer.subscription.deleted") {
      await notify(admin, { orgId, type: "billing", severity: "warning", title: "Abonnement beendet", body: "Ihr Abonnement wurde beendet. Die regelmäßige Überwachung ist pausiert.", link: "/app/settings", dedupeKey: `billing:deleted:${sub.id}` });
    }
    return;
  }
  if (event.type === "invoice.payment_failed") {
    const inv = event.data.object as Stripe.Invoice;
    const customer = typeof inv.customer === "string" ? inv.customer : inv.customer?.id;
    if (!customer) return;
    const { data: sub } = await admin.from("subscriptions").select("org_id").eq("stripe_customer_id", customer).maybeSingle();
    if (!sub) return;
    await notify(admin, { orgId: sub.org_id, type: "billing", severity: "warning", title: "Zahlung fehlgeschlagen", body: "Die letzte Zahlung konnte nicht eingezogen werden. Bitte aktualisieren Sie Ihre Zahlungsdaten, damit die Überwachung nicht unterbrochen wird.", link: "/app/settings", dedupeKey: `billing:failed:${inv.id}` });
    await audit(admin, { orgId: sub.org_id, actorType: "stripe", action: "billing.payment_failed" });
  }
}
