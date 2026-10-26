import { Resend } from "resend";

export interface EmailMessage {
  to: string | string[];
  subject: string;
  text: string;
  html?: string;
  idempotencyKey?: string;
}

export type EmailResult = { status: "sent"; id: string | null } | { status: "skipped"; reason: string } | { status: "failed"; error: string };

let client: Resend | null = null;

export function emailConfigured(env: Record<string, string | undefined> = process.env): boolean {
  return Boolean(env.RESEND_API_KEY && env.EMAIL_FROM);
}

/** Versand über Resend. Ohne Konfiguration wird nichts versendet und dies ehrlich gemeldet. */
export async function sendEmail(msg: EmailMessage, env: Record<string, string | undefined> = process.env): Promise<EmailResult> {
  if (!emailConfigured(env)) return { status: "skipped", reason: "E-Mail-Versand nicht konfiguriert (RESEND_API_KEY/EMAIL_FROM)" };
  client ??= new Resend(env.RESEND_API_KEY);
  try {
    const { data, error } = await client.emails.send(
      { from: env.EMAIL_FROM!, to: msg.to, subject: msg.subject, text: msg.text, html: msg.html ?? textToHtml(msg.text) },
      msg.idempotencyKey ? { idempotencyKey: msg.idempotencyKey } : undefined,
    );
    if (error) return { status: "failed", error: error.message };
    return { status: "sent", id: data?.id ?? null };
  } catch (err) {
    return { status: "failed", error: err instanceof Error ? err.message : String(err) };
  }
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function textToHtml(text: string): string {
  const body = escapeHtml(text)
    .replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" style="color:#0f766e">$1</a>')
    .replace(/\n/g, "<br>");
  return `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:15px;line-height:1.6;color:#1f2937;max-width:560px">
<div style="font-weight:600;font-size:16px;margin-bottom:16px">CyberSafe24 Shield</div>${body}
<div style="margin-top:24px;font-size:12px;color:#6b7280">CyberSafe24 GmbH · Diese Nachricht wurde automatisch erstellt.</div></div>`;
}
