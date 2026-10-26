"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { audit } from "@/lib/core/events";
import { requirePlatformAdmin } from "@/lib/server/auth";
import { runAction, UserError, type ActionResult } from "@/lib/server/action";

export async function adminRetryJobAction(jobId: string): Promise<ActionResult> {
  return runAction(async () => {
    const { user, admin } = await requirePlatformAdmin();
    const { data: job } = await admin.from("scan_jobs").select("id, org_id, status").eq("id", z.uuid().parse(jobId)).single();
    if (!job || job.status !== "failed") throw new UserError("Nur fehlgeschlagene Jobs können erneut gestartet werden.");
    await admin.from("scan_jobs").update({ status: "queued", attempts: 0, error: null, run_after: new Date().toISOString(), finished_at: null }).eq("id", job.id);
    await audit(admin, { orgId: job.org_id, actorType: "admin", actorId: user.id, action: "admin.job_retried", targetType: "scan_job", targetId: job.id });
    revalidatePath("/admin");
    return { ok: true as const, message: "Job neu eingeplant" };
  });
}

export async function adminSetOrgPausedAction(orgId: string, paused: boolean): Promise<ActionResult> {
  return runAction(async () => {
    const { user, admin } = await requirePlatformAdmin();
    await admin.from("organizations").update({ monitoring_paused: paused }).eq("id", z.uuid().parse(orgId));
    await audit(admin, { orgId, actorType: "admin", actorId: user.id, action: paused ? "admin.monitoring_paused" : "admin.monitoring_resumed" });
    revalidatePath("/admin");
    return { ok: true as const };
  });
}
