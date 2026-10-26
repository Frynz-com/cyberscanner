import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "../database.types";
import { INACTIVE_LIMITS, subscriptionIsActive, type PlanLimits } from "./plans";

export interface Entitlements {
  active: boolean;
  planKey: string | null;
  planName: string | null;
  status: string | null;
  trialEndsAt: string | null;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  limits: PlanLimits;
}

/**
 * Leistungsumfang ausschließlich aus serverseitigen Daten (Stripe-Webhook -> subscriptions).
 * Muss mit einem Service-Client oder RLS-Client des Mitglieds aufgerufen werden.
 */
export async function getEntitlements(db: SupabaseClient<Database>, orgId: string): Promise<Entitlements> {
  const { data: sub } = await db
    .from("subscriptions")
    .select("plan_key, status, trial_ends_at, current_period_end, cancel_at_period_end, plans(name, limits)")
    .eq("org_id", orgId)
    .maybeSingle();
  const active = subscriptionIsActive(sub ? { status: sub.status, trial_ends_at: sub.trial_ends_at } : null);
  const plan = sub?.plans as unknown as { name: string; limits: PlanLimits } | null;
  return {
    active,
    planKey: sub?.plan_key ?? null,
    planName: plan?.name ?? null,
    status: sub?.status ?? null,
    trialEndsAt: sub?.trial_ends_at ?? null,
    currentPeriodEnd: sub?.current_period_end ?? null,
    cancelAtPeriodEnd: sub?.cancel_at_period_end ?? false,
    limits: active && plan ? { ...INACTIVE_LIMITS, ...plan.limits } : INACTIVE_LIMITS,
  };
}
