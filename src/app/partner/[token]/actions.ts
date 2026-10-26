"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { addTimeline, audit, notify } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { clientIpHash, rateLimit } from "@/lib/server/auth";
import { resolvePartnerToken } from "@/lib/server/partner";
import { enqueueReverify } from "@/lib/server/reverify";
import { runAction, UserError, type ActionResult } from "@/lib/server/action";

const schema = z.object({
  token: z.string().min(40).max(64),
  findingId: z.uuid(),
  status: z.enum(["in_progress", "fixed_pending_verification"]),
  note: z.string().trim().max(2000).optional().default(""),
});

/**
 * Rückmeldung des IT-Dienstleisters. Das Token wird bei jedem Aufruf neu geprüft;
 * nur ausdrücklich freigegebene Befunde können bearbeitet werden.
 */
export async function partnerUpdateAction(input: z.input<typeof schema>): Promise<ActionResult> {
  return runAction(async () => {
    const p = schema.parse(input);
    if (!(await rateLimit(`partner:${await clientIpHash()}`, 3600, 60))) throw new UserError("Zu viele Anfragen. Bitte später erneut versuchen.");
    const session = await resolvePartnerToken(p.token, false);
    if (!session) throw new UserError("Dieser Link ist ungültig, abgelaufen oder wurde widerrufen.");
    if (!session.findingIds.includes(p.findingId)) throw new UserError("Kein Zugriff auf diesen Befund.");
    const admin = createAdminClient();
    const { data: finding } = await admin.from("findings").select("id, org_id, title, domain_id, status").eq("id", p.findingId).eq("org_id", session.orgId).single();
    if (!finding) throw new UserError("Befund nicht gefunden.");
    const who = session.companyName || session.email;

    await admin.from("actions").update({ status: p.status, note: p.note || null }).eq("invite_id", session.inviteId).eq("finding_id", finding.id);
    if (p.status === "in_progress" && finding.status === "new") await admin.from("findings").update({ status: "investigating" }).eq("id", finding.id);
    await admin.from("finding_events").insert({
      org_id: session.orgId,
      finding_id: finding.id,
      type: "partner_update",
      actor_type: "partner",
      actor_label: who,
      message: (p.status === "in_progress" ? "Bearbeitung gestartet" : "Maßnahme umgesetzt – Nachprüfung angefordert") + (p.note ? `: ${p.note}` : ""),
    });
    await addTimeline(admin, {
      orgId: session.orgId,
      type: "partner_update",
      severity: "info",
      title: `${who}: ${p.status === "in_progress" ? "Bearbeitung gestartet" : "Maßnahme umgesetzt"} – ${finding.title}`,
      link: `/app/findings/${finding.id}`,
      findingId: finding.id,
      domainId: finding.domain_id,
    });
    await notify(admin, {
      orgId: session.orgId,
      type: "partner",
      severity: "info",
      title: `${who} hat ein Update zu „${finding.title}“`,
      body: p.status === "in_progress" ? "Die Bearbeitung wurde gestartet." : "Die Maßnahme wurde laut Dienstleister umgesetzt. Wir prüfen das automatisch nach.",
      link: `/app/findings/${finding.id}`,
      dedupeKey: `partner:${session.inviteId}:${finding.id}:${p.status}`,
    });
    let message = "Rückmeldung gespeichert.";
    if (p.status === "fixed_pending_verification") {
      try {
        const r = await enqueueReverify(session.orgId, finding, "", "partner");
        message = "demo" in r ? "Rückmeldung gespeichert (Demo – keine echte Nachprüfung)." : "Rückmeldung gespeichert. Die Nachprüfung wurde gestartet.";
      } catch (err) {
        message = `Rückmeldung gespeichert. Nachprüfung derzeit nicht möglich: ${err instanceof Error ? err.message : ""}`;
      }
    }
    await audit(admin, { orgId: session.orgId, actorType: "partner", action: `partner.${p.status}`, targetType: "finding", targetId: finding.id, data: { invite: session.inviteId }, ipHash: await clientIpHash() });
    revalidatePath(`/partner/${p.token}`);
    return { ok: true as const, message };
  });
}
