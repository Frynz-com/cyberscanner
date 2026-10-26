"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { addTimeline } from "@/lib/core/events";
import { buildReportSnapshot } from "@/lib/core/report-data";
import { auditUser, authorizeOrg, rateLimit } from "@/lib/server/auth";
import { runAction, UserError, type ActionResult } from "@/lib/server/action";

export async function createReportAction(orgId: string, days: number = 30): Promise<ActionResult<{ id: string }>> {
  return runAction<{ id: string }>(async () => {
    const { admin, user, isDemo } = await authorizeOrg(z.uuid().parse(orgId), "member");
    const span = z.number().int().min(7).max(365).parse(days);
    if (!(await rateLimit(`report:${orgId}`, 3600, 10))) throw new UserError("Bitte warten Sie etwas, bevor Sie weitere Berichte erstellen.");
    const end = new Date();
    const start = new Date(end.getTime() - span * 86_400_000);
    const snapshot = await buildReportSnapshot(admin, orgId, start, end);
    const { data, error } = await admin
      .from("reports")
      .insert({ org_id: orgId, kind: "on_demand", period_start: start.toISOString(), period_end: end.toISOString(), snapshot: JSON.parse(JSON.stringify(snapshot)), created_by: user.id, is_demo: isDemo })
      .select("id")
      .single();
    if (error) throw new Error(error.message);
    await addTimeline(admin, { orgId, type: "report_created", title: `Sicherheitsbericht (${span} Tage) erstellt`, link: "/app/reports" });
    await auditUser(orgId, user.id, "report.created", { type: "report", id: data.id });
    revalidatePath("/app/reports");
    return { ok: true as const, data: { id: data.id } };
  });
}
