import { allAdapters } from "../src/lib/core/scanners/registry";
import type { AdapterRunStatus } from "../src/lib/core/scanners/types";
import type { Db } from "./deps";

/** Aktualisiert den Integrationsstatus nach einem Adapterlauf (Provider Health). */
export async function recordProviderOutcome(db: Db, key: string, status: AdapterRunStatus, message?: string) {
  const now = new Date().toISOString();
  if (status === "ok" || status === "partial") {
    await db
      .from("provider_integrations")
      .update({ status: "available", status_message: message ?? null, last_checked_at: now, last_success_at: now, consecutive_failures: 0, updated_at: now })
      .eq("key", key);
  } else if (status === "error") {
    const { data } = await db.from("provider_integrations").select("consecutive_failures").eq("key", key).single();
    const failures = (data?.consecutive_failures ?? 0) + 1;
    await db
      .from("provider_integrations")
      .update({ status: failures >= 3 ? "degraded" : "available", status_message: message ?? null, last_checked_at: now, last_error_at: now, consecutive_failures: failures, updated_at: now })
      .eq("key", key);
  }
}

/** Prüft regelmäßig die Verfügbarkeit aller Integrationen (Konfiguration, Lizenz, Binaries). */
export async function refreshProviderHealth(db: Db, env: Record<string, string | undefined>) {
  const now = new Date().toISOString();
  for (const adapter of allAdapters(env)) {
    let res: { status: string; message?: string };
    try {
      res = await adapter.checkAvailability();
    } catch (err) {
      res = { status: "unavailable", message: String(err) };
    }
    const { data: cur } = await db.from("provider_integrations").select("status, consecutive_failures").eq("key", adapter.key).single();
    // "degraded" (wiederholte Laufzeitfehler) nicht durch reine Konfigurationsprüfung überschreiben
    const status = res.status === "available" && cur?.status === "degraded" && (cur.consecutive_failures ?? 0) >= 3 ? "degraded" : res.status;
    await db.from("provider_integrations").update({ status, status_message: res.message ?? null, last_checked_at: now, updated_at: now }).eq("key", adapter.key);
  }
  const email = env.RESEND_API_KEY && env.EMAIL_FROM;
  await db.from("provider_integrations").update({ status: email ? "available" : "not_configured", status_message: email ? null : "RESEND_API_KEY/EMAIL_FROM fehlen", last_checked_at: now }).eq("key", "resend");
  const stripe = env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET;
  await db.from("provider_integrations").update({ status: stripe ? "available" : "not_configured", status_message: stripe ? null : "STRIPE_SECRET_KEY/STRIPE_WEBHOOK_SECRET fehlen", last_checked_at: now }).eq("key", "stripe");
}
