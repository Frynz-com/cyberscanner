"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { randomToken, sha256 } from "@/lib/core/crypto";
import { sendEmail } from "@/lib/core/email";
import { getEntitlements } from "@/lib/core/entitlements";
import { addTimeline } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg, rateLimit } from "@/lib/server/auth";
import { runAction, UserError, type ActionResult } from "@/lib/server/action";

const inviteSchema = z.object({
  orgId: z.uuid(),
  email: z.email("Bitte geben Sie eine gültige E-Mail-Adresse ein."),
  contactName: z.string().trim().max(120).optional().default(""),
  companyName: z.string().trim().max(120).optional().default(""),
  findingIds: z.array(z.uuid()).min(1, "Bitte wählen Sie mindestens einen Befund aus.").max(50),
  validDays: z.coerce.number().int().min(1).max(90),
  message: z.string().trim().max(2000).optional().default(""),
});

/**
 * Lädt einen IT-Dienstleister ein und gibt gezielt ausgewählte Befunde frei.
 * Der Link ist zeitlich begrenzt, widerrufbar und gewährt keinen Kontozugriff.
 */
export async function invitePartnerAction(input: z.input<typeof inviteSchema>): Promise<ActionResult<{ link: string; emailSent: boolean }>> {
  return runAction<{ link: string; emailSent: boolean }>(async () => {
    const p = inviteSchema.parse(input);
    const { admin, user, isDemo } = await authorizeOrg(p.orgId, "admin");
    if (!(await rateLimit(`invite:${p.orgId}`, 86400, 20))) throw new UserError("Tageslimit für Einladungen erreicht.");
    const ent = await getEntitlements(admin, p.orgId);
    const { count } = await admin.from("service_provider_invites").select("id", { count: "exact", head: true }).eq("org_id", p.orgId).is("revoked_at", null).gt("expires_at", new Date().toISOString());
    if (!isDemo && (count ?? 0) >= ent.limits.partner_invites) throw new UserError(`Ihr Tarif erlaubt ${ent.limits.partner_invites} aktive Freigabe(n).`);
    // Befunde müssen zur selben Organisation gehören
    const { data: findings } = await admin.from("findings").select("id, title, domain_id").eq("org_id", p.orgId).in("id", p.findingIds);
    if (!findings || findings.length !== p.findingIds.length) throw new UserError("Ungültige Befundauswahl.");

    const token = randomToken(32);
    const expires = new Date(Date.now() + p.validDays * 86_400_000).toISOString();
    const { data: invite, error } = await admin
      .from("service_provider_invites")
      .insert({ org_id: p.orgId, email: p.email.toLowerCase(), contact_name: p.contactName || null, company_name: p.companyName || null, token_hash: sha256(token), expires_at: expires, created_by: user.id })
      .select("id")
      .single();
    if (error) throw new Error(error.message);
    await admin.from("service_provider_shares").insert(findings.map((f) => ({ invite_id: invite.id, finding_id: f.id, org_id: p.orgId })));
    await admin.from("actions").insert(findings.map((f) => ({ org_id: p.orgId, finding_id: f.id, invite_id: invite.id, status: "open", created_by: user.id, note: p.message || null })));
    const partnerLabel = p.companyName || p.email;
    for (const f of findings) {
      await admin.from("finding_events").insert({ org_id: p.orgId, finding_id: f.id, type: "shared_with_partner", actor_type: "user", actor_id: user.id, actor_label: user.email ?? null, message: `An ${partnerLabel} übergeben (gültig bis ${new Date(expires).toLocaleDateString("de-DE")})` });
      await admin.from("findings").update({ status: "action_required" }).eq("id", f.id).eq("status", "new");
    }
    await addTimeline(admin, { orgId: p.orgId, type: "shared_with_partner", title: `${findings.length} Befund(e) an ${partnerLabel} übergeben`, link: "/app/partners" });

    const link = `${process.env.APP_URL}/partner/${token}`;
    let emailSent = false;
    if (!isDemo) {
      const { data: org } = await admin.from("organizations").select("name").eq("id", p.orgId).single();
      const res = await sendEmail({
        to: p.email,
        subject: `${org?.name ?? "Ein Kunde"} bittet um Unterstützung bei ${findings.length} Sicherheitsbefund(en)`,
        text: [
          `Guten Tag${p.contactName ? ` ${p.contactName}` : ""},`,
          ``,
          `${org?.name} hat Ihnen über CyberSafe24 Shield ${findings.length} Sicherheitsbefund(e) zur Bearbeitung freigegeben:`,
          ...findings.map((f) => `- ${f.title}`),
          p.message ? `\nNachricht: ${p.message}` : "",
          ``,
          `Technische Details, Prüfschritte und Empfehlungen finden Sie hier (gültig bis ${new Date(expires).toLocaleDateString("de-DE")}):`,
          link,
          ``,
          `Der Link gewährt ausschließlich Zugriff auf die freigegebenen Befunde. Bitte geben Sie ihn nicht weiter.`,
        ].join("\n"),
      });
      emailSent = res.status === "sent";
    }
    await auditUser(p.orgId, user.id, "partner.invited", { type: "service_provider_invite", id: invite.id }, { findings: findings.length, validDays: p.validDays, emailSent });
    revalidatePath("/app", "layout");
    return { ok: true as const, data: { link, emailSent } };
  });
}

export async function revokePartnerInviteAction(inviteId: string): Promise<ActionResult> {
  return runAction(async () => {
    const { data: inv } = await createAdminClient().from("service_provider_invites").select("id, org_id").eq("id", z.uuid().parse(inviteId)).maybeSingle();
    if (!inv) throw new UserError("Freigabe nicht gefunden");
    const { admin, user } = await authorizeOrg(inv.org_id, "admin");
    await admin.from("service_provider_invites").update({ revoked_at: new Date().toISOString() }).eq("id", inv.id);
    await admin.from("actions").update({ status: "cancelled" }).eq("invite_id", inv.id).in("status", ["open", "in_progress"]);
    await auditUser(inv.org_id, user.id, "partner.revoked", { type: "service_provider_invite", id: inv.id });
    revalidatePath("/app/partners");
    return { ok: true as const, message: "Freigabe widerrufen" };
  });
}
