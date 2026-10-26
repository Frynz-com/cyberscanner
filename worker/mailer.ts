import { emailConfigured, sendEmail } from "../src/lib/core/email";
import type { WorkerDeps } from "./deps";

export const MAX_EMAILS_PER_ORG_PER_DAY = 10;

/** Empfänger: Inhaber/Admins der Organisation + hinterlegte Kontaktadresse. */
export async function orgRecipients(deps: WorkerDeps, orgId: string): Promise<string[]> {
  const { db } = deps;
  const { data: members } = await db.from("memberships").select("user_id").eq("org_id", orgId).in("role", ["owner", "admin"]);
  const emails = new Set<string>();
  for (const m of members ?? []) {
    const { data } = await db.auth.admin.getUserById(m.user_id);
    if (data.user?.email) emails.add(data.user.email.toLowerCase());
  }
  const { data: org } = await db.from("organizations").select("contact_email").eq("id", orgId).single();
  if (org?.contact_email) emails.add(org.contact_email.toLowerCase());
  return [...emails];
}

/**
 * Versendet ausstehende Benachrichtigungen. Begrenzung je Organisation verhindert E-Mail-Fluten;
 * jede Benachrichtigung wird höchstens dreimal versucht (keine Endlosschleifen).
 */
export async function processEmailOutbox(deps: WorkerDeps) {
  const { db, env } = deps;
  const { data: pending } = await db
    .from("notifications")
    .select("id, org_id, title, body, link, email_attempts")
    .eq("email_status", "pending")
    .order("created_at")
    .limit(25);
  if (!pending?.length) return { sent: 0 };
  if (!emailConfigured(env)) {
    await db.from("notifications").update({ email_status: "skipped", email_error: "E-Mail-Versand nicht konfiguriert" }).in("id", pending.map((p) => p.id));
    return { sent: 0 };
  }
  let sent = 0;
  const since = new Date(Date.now() - 86_400_000).toISOString();
  for (const n of pending) {
    const { data: org } = await db.from("organizations").select("is_demo").eq("id", n.org_id).single();
    if (!org || org.is_demo) {
      await db.from("notifications").update({ email_status: "skipped", email_error: "Demo-Mandant – kein E-Mail-Versand" }).eq("id", n.id);
      continue;
    }
    const { count } = await db.from("notifications").select("id", { count: "exact", head: true }).eq("org_id", n.org_id).eq("email_status", "sent").gte("email_sent_at", since);
    if ((count ?? 0) >= MAX_EMAILS_PER_ORG_PER_DAY) {
      await db.from("notifications").update({ email_status: "suppressed", email_error: "Tageslimit erreicht – nur in der App sichtbar" }).eq("id", n.id);
      continue;
    }
    const to = await orgRecipients(deps, n.org_id);
    if (to.length === 0) {
      await db.from("notifications").update({ email_status: "skipped", email_error: "Keine Empfänger" }).eq("id", n.id);
      continue;
    }
    const appUrl = env.APP_URL ?? "http://localhost:3000";
    const res = await sendEmail(
      { to, subject: `[CyberSafe24 Shield] ${n.title}`, text: `${n.body}${n.link ? `\n\nDetails: ${appUrl}${n.link}` : ""}`, idempotencyKey: `notification-${n.id}` },
      env,
    );
    if (res.status === "sent") {
      sent++;
      await db.from("notifications").update({ email_status: "sent", email_sent_at: new Date().toISOString(), email_attempts: n.email_attempts + 1 }).eq("id", n.id);
    } else {
      const attempts = n.email_attempts + 1;
      await db
        .from("notifications")
        .update({ email_status: attempts >= 3 || res.status === "skipped" ? "failed" : "pending", email_attempts: attempts, email_error: res.status === "failed" ? res.error : res.reason })
        .eq("id", n.id);
    }
  }
  return { sent };
}
