import "server-only";
import Stripe from "stripe";

let client: Stripe | null = null;

export function stripeConfigured(): boolean {
  return Boolean(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_WEBHOOK_SECRET);
}

export function getStripe(): Stripe {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error("Stripe ist nicht konfiguriert");
  client ??= new Stripe(process.env.STRIPE_SECRET_KEY, { appInfo: { name: "CyberSafe24 Shield" } });
  return client;
}

/** Preise kommen ausschließlich aus Stripe/ENV – nie aus Client-Angaben. */
export function priceIdForPlan(stripePriceEnv: string | null): string | null {
  return stripePriceEnv ? (process.env[stripePriceEnv] ?? null) : null;
}

export function planKeyForPrice(priceId: string, plans: Array<{ key: string; stripe_price_env: string | null }>): string | null {
  return plans.find((p) => p.stripe_price_env && process.env[p.stripe_price_env] === priceId)?.key ?? null;
}
