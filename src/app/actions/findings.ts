"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { addTimeline } from "@/lib/core/events";
import type { FindingStatus } from "@/lib/core/risk/types";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg } from "@/lib/server/auth";
import { enqueueReverify } from "@/lib/server/reverify";
import { runAction, UserError, type ActionResult } from "@/lib/server/action";

const STATUS_LABEL: Record<FindingStatus, string> = {
  new: "Neu",
  investigating: "In Prüfung",
  action_required: "Handlungsbedarf",
  resolved: "Behoben",
  accepted_risk: "Risiko akzeptiert",
  false_positive: "Fehlalarm",
};

async function loadFinding(findingId: string) {
  const { data } = await createAdminClient()
    .from("findings")
    .select("id, org_id, status, title, domain_id, asset_value, check_key, verification_state")
    .eq("id", z.uuid().parse(findingId))
    .maybeSingle();
  if (!data) throw new UserError("Befund nicht gefunden");
  return data;
}

const statusSchema = z.object({
  findingId: z.uuid(),
  status: z.enum(["new", "investigating", "action_required", "resolved", "accepted_risk", "false_positive"]),
  note: z.string().trim().max(2000).optional().default(""),
});

export async function setFindingStatusAction(input: { findingId: string; status: FindingStatus; note?: string }): Promise<ActionResult<{ reverifyQueued: boolean }>> {
  return runAction<{ reverifyQueued: boolean }>(async () => {
    const parsed = statusSchema.parse(input);
    const finding = await loadFinding(parsed.findingId);
    const { admin, user } = await authorizeOrg(finding.org_id, "member");
    if ((parsed.status === "accepted_risk" || parsed.status === "false_positive") && parsed.note.length < 5)
      throw new UserError("Bitte begründen Sie kurz, warum das Risiko akzeptiert wird bzw. ein Fehlalarm vorliegt.");
    if (finding.status === parsed.status) return { ok: true as const, data: { reverifyQueued: false } };

    const resolving = parsed.status === "resolved";
    await admin
      .from("findings")
      .update({
        status: parsed.status,
        // Vom Kunden als behoben markiert ≠ technisch bestätigt
        verification_state: resolving ? "unverified" : parsed.status === "action_required" ? finding.verification_state : null,
        resolved_at: resolving ? new Date().toISOString() : null,
      })
      .eq("id", finding.id);
    await admin.from("finding_events").insert({
      org_id: finding.org_id,
      finding_id: finding.id,
      type: "status_changed",
      from_status: finding.status,
      to_status: parsed.status,
      actor_type: "user",
      actor_id: user.id,
      actor_label: user.email ?? null,
      message: parsed.note || `Status geändert: ${STATUS_LABEL[finding.status]} → ${STATUS_LABEL[parsed.status]}`,
    });
    await addTimeline(admin, {
      orgId: finding.org_id,
      type: "status_changed",
      severity: "info",
      title: `${finding.title}: ${STATUS_LABEL[parsed.status]}`,
      link: `/app/findings/${finding.id}`,
      findingId: finding.id,
      domainId: finding.domain_id,
    });
    await auditUser(finding.org_id, user.id, "finding.status_changed", { type: "finding", id: finding.id }, { from: finding.status, to: parsed.status });

    let reverifyQueued = false;
    if (resolving) {
      try {
        const r = await enqueueReverify(finding.org_id, finding, user.id, "reverify");
        reverifyQueued = !("demo" in r);
      } catch {
        // Markierung bleibt bestehen; Nachprüfung erfolgt spätestens beim nächsten regulären Scan
      }
    }
    revalidatePath("/app", "layout");
    return {
      ok: true as const,
      data: { reverifyQueued },
      message: resolving
        ? reverifyQueued
          ? "Als behoben markiert. Wir prüfen das jetzt automatisch nach."
          : "Als behoben markiert. Die Bestätigung erfolgt bei der nächsten Prüfung."
        : "Status aktualisiert",
    };
  });
}

export async function requestReverifyAction(findingId: string): Promise<ActionResult> {
  return runAction(async () => {
    const finding = await loadFinding(findingId);
    const { user } = await authorizeOrg(finding.org_id, "member");
    const r = await enqueueReverify(finding.org_id, finding, user.id, "reverify");
    if ("demo" in r) return { ok: true as const, message: "Demo-Modus: Es werden keine echten Prüfungen ausgeführt." };
    await auditUser(finding.org_id, user.id, "finding.reverify_requested", { type: "finding", id: finding.id });
    revalidatePath(`/app/findings/${finding.id}`);
    return { ok: true as const, message: "Nachprüfung gestartet. Das Ergebnis erscheint in wenigen Minuten." };
  });
}

export async function addFindingCommentAction(findingId: string, comment: string): Promise<ActionResult> {
  return runAction(async () => {
    const finding = await loadFinding(findingId);
    const { admin, user } = await authorizeOrg(finding.org_id, "member");
    const text = z.string().trim().min(1, "Bitte geben Sie einen Kommentar ein.").max(2000).parse(comment);
    await admin.from("finding_events").insert({
      org_id: finding.org_id,
      finding_id: finding.id,
      type: "comment",
      actor_type: "user",
      actor_id: user.id,
      actor_label: user.email ?? null,
      message: text,
    });
    revalidatePath(`/app/findings/${finding.id}`);
    return { ok: true as const };
  });
}
