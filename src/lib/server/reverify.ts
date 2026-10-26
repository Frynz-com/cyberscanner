import "server-only";
import { getEntitlements } from "@/lib/core/entitlements";
import { createAdminClient } from "@/lib/supabase/admin";
import { rateLimit } from "./auth";
import { UserError } from "./action";

/** Nachprüfungs-Job einplanen. Aufrufer MUSS vorher die Berechtigung geprüft haben. */
export async function enqueueReverify(orgId: string, finding: { id: string; domain_id: string | null }, userId: string, trigger: "reverify" | "partner") {
  const admin = createAdminClient();
  if (!finding.domain_id) throw new UserError("Für diesen Befund ist keine Nachprüfung möglich.");
  const { data: org } = await admin.from("organizations").select("is_demo").eq("id", orgId).single();
  if (org?.is_demo) {
    return { demo: true };
  }
  const ent = await getEntitlements(admin, orgId);
  if (!ent.active) throw new UserError("Ihr Abonnement ist nicht aktiv.");
  if (!(await rateLimit(`reverify:${finding.id}`, 600, 1))) throw new UserError("Eine Nachprüfung wurde gerade erst angefordert. Bitte warten Sie einige Minuten.");
  if (!(await rateLimit(`reverify-org:${orgId}`, 86400, 50))) throw new UserError("Tageslimit für Nachprüfungen erreicht.");
  const { data: running } = await admin.from("scan_jobs").select("id").eq("kind", "reverify").in("status", ["queued", "running"]).contains("payload", { finding_id: finding.id }).limit(1).maybeSingle();
  if (running) return { jobId: running.id };
  const { data: job, error } = await admin
    .from("scan_jobs")
    .insert({
      org_id: orgId,
      domain_id: finding.domain_id,
      kind: "reverify",
      trigger,
      priority: 20,
      payload: { finding_id: finding.id },
      requested_by: trigger === "partner" ? null : userId,
      idempotency_key: `reverify:${finding.id}:${Math.floor(Date.now() / 60_000)}`,
    })
    .select("id")
    .single();
  if (error) throw new Error(error.message);
  await admin.from("finding_events").insert({
    org_id: orgId,
    finding_id: finding.id,
    type: "reverify_requested",
    actor_type: trigger === "partner" ? "partner" : "user",
    actor_id: trigger === "partner" ? null : userId,
    message: "Nachprüfung angefordert",
  });
  return { jobId: job.id };
}

