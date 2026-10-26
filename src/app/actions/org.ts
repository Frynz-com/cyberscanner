"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";
import { addTimeline } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg, getOrgContext, ORG_COOKIE, rateLimit, requireUser } from "@/lib/server/auth";
import { formToObject, runAction, UserError, type ActionResult } from "@/lib/server/action";

const orgSchema = z.object({
  name: z.string().trim().min(2, "Bitte geben Sie den Firmennamen ein.").max(120),
  industry: z.string().trim().max(80).optional().default(""),
  employeeRange: z.enum(["", "1-9", "10-49", "50-249", "250-999", "1000+"]).optional().default(""),
  contactEmail: z.union([z.literal(""), z.email("Bitte geben Sie eine gültige E-Mail-Adresse ein.")]).optional().default(""),
});

export async function createOrganizationAction(_: unknown, formData: FormData): Promise<ActionResult> {
  const result = await runAction(async () => {
    const user = await requireUser();
    const input = orgSchema.parse(formToObject(formData));
    if (user.app_metadata?.demo) throw new UserError("Im Demo-Konto können keine echten Organisationen angelegt werden.");
    if (!(await rateLimit(`create-org:${user.id}`, 86400, 5))) throw new UserError("Tageslimit für neue Organisationen erreicht.");
    const existing = await getOrgContext();
    if (existing && existing.memberships.some((m) => !m.is_demo)) throw new UserError("Sie haben bereits eine Organisation angelegt.");
    const admin = createAdminClient();
    const { data: orgId, error } = await admin.rpc("create_organization", {
      p_user: user.id,
      p_name: input.name,
      p_industry: input.industry,
      p_employee_range: input.employeeRange,
      p_contact_email: input.contactEmail || user.email || "",
    });
    if (error || !orgId) throw new Error(error?.message ?? "Organisation konnte nicht angelegt werden");
    (await cookies()).set(ORG_COOKIE, orgId, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
    await auditUser(orgId, user.id, "organization.created", { type: "organization", id: orgId });
    return { ok: true as const };
  });
  if (result.ok) redirect("/onboarding");
  return result;
}

const updateSchema = orgSchema.extend({
  orgId: z.uuid(),
  contactPhone: z.string().trim().max(40).optional().default(""),
  retentionDays: z.coerce.number().int().min(30).max(1825),
});

export async function updateOrganizationAction(_: unknown, formData: FormData): Promise<ActionResult> {
  return runAction(async () => {
    const input = updateSchema.parse(formToObject(formData));
    const { user, admin, isDemo } = await authorizeOrg(input.orgId, "admin");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    const { error } = await admin
      .from("organizations")
      .update({
        name: input.name,
        industry: input.industry || null,
        employee_range: input.employeeRange || null,
        contact_email: input.contactEmail || null,
        contact_phone: input.contactPhone || null,
        data_retention_days: input.retentionDays,
      })
      .eq("id", input.orgId);
    if (error) throw new Error(error.message);
    await auditUser(input.orgId, user.id, "organization.updated", { type: "organization", id: input.orgId });
    revalidatePath("/app/settings");
    return { ok: true as const, message: "Gespeichert" };
  });
}

export async function switchOrganizationAction(orgId: string) {
  const user = await requireUser();
  const admin = createAdminClient();
  const { data } = await admin.from("memberships").select("org_id").eq("org_id", orgId).eq("user_id", user.id).maybeSingle();
  if (data) (await cookies()).set(ORG_COOKIE, orgId, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
  redirect("/app");
}

export async function setMonitoringPausedAction(orgId: string, paused: boolean): Promise<ActionResult> {
  return runAction(async () => {
    const { user, admin, isDemo } = await authorizeOrg(orgId, "admin");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    await admin.from("organizations").update({ monitoring_paused: paused }).eq("id", orgId);
    await addTimeline(admin, { orgId, type: "monitoring_changed", title: paused ? "Überwachung pausiert" : "Überwachung fortgesetzt", severity: "info" });
    await auditUser(orgId, user.id, paused ? "monitoring.paused" : "monitoring.resumed");
    revalidatePath("/app", "layout");
    return { ok: true as const };
  });
}

export async function markNotificationsReadAction(orgId: string): Promise<ActionResult> {
  return runAction(async () => {
    const { admin } = await authorizeOrg(orgId, "viewer");
    await admin.from("notifications").update({ read_at: new Date().toISOString() }).eq("org_id", orgId).is("read_at", null);
    revalidatePath("/app", "layout");
    return { ok: true as const };
  });
}

/** Löschkonzept: Organisation zur Löschung vormerken (endgültig nach 30 Tagen durch den Worker). */
export async function deleteOrganizationAction(_: unknown, formData: FormData): Promise<ActionResult> {
  const res = await runAction(async () => {
    const orgId = z.uuid().parse(formData.get("orgId"));
    const confirm = String(formData.get("confirm") ?? "");
    const { user, admin, isDemo } = await authorizeOrg(orgId, "owner");
    if (isDemo) throw new UserError("Der Demo-Mandant kann nicht gelöscht werden.");
    const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).single();
    if (!org || confirm.trim() !== org.name) throw new UserError("Bitte geben Sie zur Bestätigung den exakten Firmennamen ein.");
    await admin.from("organizations").update({ deleted_at: new Date().toISOString(), monitoring_paused: true }).eq("id", orgId);
    await admin.from("domains").update({ monitoring_enabled: false }).eq("org_id", orgId);
    await admin.from("scan_jobs").update({ cancel_requested: true }).eq("org_id", orgId).in("status", ["queued", "running"]);
    await auditUser(orgId, user.id, "organization.deletion_requested");
    (await cookies()).delete(ORG_COOKIE);
    return { ok: true as const };
  });
  if (res.ok) redirect("/onboarding");
  return res;
}
