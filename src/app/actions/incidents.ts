"use server";

import { randomUUID } from "node:crypto";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";
import { contractedExpert, PLAYBOOKS, type IncidentType } from "@/lib/content/playbooks";
import { sha256 } from "@/lib/core/crypto";
import { sendEmail } from "@/lib/core/email";
import { addTimeline, notify } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg, rateLimit } from "@/lib/server/auth";
import { formToObject, runAction, UserError, type ActionResult } from "@/lib/server/action";

const PRIORITY_LABEL = { p1: "Kritisch", p2: "Hoch", p3: "Normal" } as const;

const createSchema = z.object({
  orgId: z.uuid(),
  type: z.enum(["account_compromise", "ransomware", "phishing", "data_exfiltration", "suspicious_activity", "other"]),
  ongoing: z.enum(["yes", "no", "unknown"]).default("unknown"),
  description: z.string().trim().max(8000).optional().default(""),
  reporterName: z.string().trim().min(2, "Bitte geben Sie Ihren Namen an.").max(120),
  reporterPhone: z.string().trim().max(40).optional().default(""),
  notifyPartner: z.string().optional(),
  notifyExpert: z.string().optional(),
});

export async function createIncidentAction(_: unknown, formData: FormData): Promise<ActionResult<{ id: string }>> {
  let createdId: string | null = null;
  const res = await runAction<{ id: string }>(async () => {
    const input = createSchema.parse(formToObject(formData));
    const { admin, user, isDemo } = await authorizeOrg(input.orgId, "member");
    if (!(await rateLimit(`incident:${input.orgId}`, 3600, 10))) throw new UserError("Zu viele Meldungen in kurzer Zeit. Bitte kontaktieren Sie uns direkt.");
    const pb = PLAYBOOKS[input.type as IncidentType];
    // Priorität deterministisch: Playbook-Standard, bei laufendem Vorfall eine Stufe höher
    const priority = input.ongoing === "yes" && pb.defaultPriority !== "p1" ? (pb.defaultPriority === "p3" ? "p2" : "p1") : pb.defaultPriority;
    const { data: org } = await admin.from("organizations").select("name").eq("id", input.orgId).single();
    const { data: inc, error } = await admin
      .from("incidents")
      .insert({
        org_id: input.orgId,
        type: input.type,
        priority,
        title: pb.title,
        description: input.description || null,
        reporter_name: input.reporterName,
        reporter_phone: input.reporterPhone || null,
        reported_by: user.id,
        is_demo: isDemo,
        assigned_contact: input.notifyExpert === "on" && contractedExpert() ? contractedExpert()!.name : null,
      })
      .select("id")
      .single();
    if (error) throw new Error(error.message);
    createdId = inc.id;
    await admin.from("incident_events").insert({
      org_id: input.orgId,
      incident_id: inc.id,
      type: "created",
      actor_id: user.id,
      actor_label: input.reporterName,
      message: `Vorfall gemeldet (${PRIORITY_LABEL[priority]}). Vorfall aktuell andauernd: ${{ yes: "ja", no: "nein", unknown: "unbekannt" }[input.ongoing]}.`,
    });
    await addTimeline(admin, { orgId: input.orgId, type: "incident_reported", severity: priority === "p1" ? "critical" : "high", title: `Vorfall gemeldet: ${pb.title}`, link: `/app/emergency/${inc.id}` });
    await notify(admin, {
      orgId: input.orgId,
      type: "incident",
      severity: "critical",
      title: `Sicherheitsvorfall gemeldet: ${pb.title}`,
      body: `${input.reporterName} hat einen Vorfall gemeldet (Priorität ${PRIORITY_LABEL[priority]}).${input.description ? `\n\n${input.description.slice(0, 1000)}` : ""}`,
      link: `/app/emergency/${inc.id}`,
      dedupeKey: `incident:${inc.id}`,
      email: true,
    });

    if (!isDemo) {
      const summary = [
        `Organisation: ${org?.name}`,
        `Vorfall: ${pb.title} (Priorität ${PRIORITY_LABEL[priority]})`,
        `Gemeldet von: ${input.reporterName}${input.reporterPhone ? `, Tel. ${input.reporterPhone}` : ""}`,
        `Andauernd: ${{ yes: "ja", no: "nein", unknown: "unbekannt" }[input.ongoing]}`,
        input.description ? `\nBeschreibung:\n${input.description.slice(0, 3000)}` : "",
      ].join("\n");
      const recipients: string[] = [];
      if (input.notifyPartner === "on") {
        const { data: partners } = await admin.from("service_provider_invites").select("email").eq("org_id", input.orgId).is("revoked_at", null).gt("expires_at", new Date().toISOString());
        recipients.push(...new Set((partners ?? []).map((p) => p.email)));
      }
      const expert = input.notifyExpert === "on" ? contractedExpert() : null;
      if (expert?.email) recipients.push(expert.email);
      for (const to of recipients) {
        const r = await sendEmail({ to, subject: `[Notfall] ${org?.name}: ${pb.title}`, text: `${summary}\n\nDiese Nachricht wurde über CyberSafe24 Shield ausgelöst.` });
        await admin.from("incident_events").insert({
          org_id: input.orgId,
          incident_id: inc.id,
          type: "notification_sent",
          message: r.status === "sent" ? `Benachrichtigung an ${to} gesendet` : `Benachrichtigung an ${to} nicht gesendet (${r.status === "failed" ? r.error : r.reason})`,
        });
      }
    }
    await auditUser(input.orgId, user.id, "incident.created", { type: "incident", id: inc.id }, { type: input.type, priority });
    return { ok: true as const, data: { id: inc.id } };
  });
  if (res.ok && createdId) redirect(`/app/emergency/${createdId}`);
  return res;
}

async function loadIncident(incidentId: string) {
  const { data } = await createAdminClient().from("incidents").select("id, org_id, status").eq("id", z.uuid().parse(incidentId)).maybeSingle();
  if (!data) throw new UserError("Vorfall nicht gefunden");
  return data;
}

export async function addIncidentNoteAction(incidentId: string, note: string, kind: "note" | "checklist" = "note"): Promise<ActionResult> {
  return runAction(async () => {
    const inc = await loadIncident(incidentId);
    const { admin, user } = await authorizeOrg(inc.org_id, "member");
    const text = z.string().trim().min(1, "Bitte Text eingeben.").max(4000).parse(note);
    await admin.from("incident_events").insert({ org_id: inc.org_id, incident_id: inc.id, type: kind, message: text, actor_id: user.id, actor_label: user.email ?? null });
    await admin.from("incidents").update({ status: inc.status === "open" ? "in_progress" : inc.status }).eq("id", inc.id);
    revalidatePath(`/app/emergency/${inc.id}`);
    return { ok: true as const };
  });
}

export async function setIncidentStatusAction(incidentId: string, status: "open" | "in_progress" | "contained" | "closed"): Promise<ActionResult> {
  return runAction(async () => {
    const inc = await loadIncident(incidentId);
    const { admin, user } = await authorizeOrg(inc.org_id, "member");
    const s = z.enum(["open", "in_progress", "contained", "closed"]).parse(status);
    await admin.from("incidents").update({ status: s, closed_at: s === "closed" ? new Date().toISOString() : null }).eq("id", inc.id);
    await admin.from("incident_events").insert({ org_id: inc.org_id, incident_id: inc.id, type: "status_changed", message: `Status: ${{ open: "Offen", in_progress: "In Bearbeitung", contained: "Eingedämmt", closed: "Abgeschlossen" }[s]}`, actor_id: user.id, actor_label: user.email ?? null });
    await auditUser(inc.org_id, user.id, "incident.status_changed", { type: "incident", id: inc.id }, { status: s });
    revalidatePath(`/app/emergency/${inc.id}`);
    return { ok: true as const };
  });
}

const ALLOWED_TYPES: Record<string, string> = {
  "application/pdf": "pdf",
  "image/png": "png",
  "image/jpeg": "jpg",
  "text/plain": "txt",
  "text/csv": "csv",
  "message/rfc822": "eml",
  "application/vnd.ms-outlook": "msg",
};
const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;

/** Sicherer Upload: Größen- und Typprüfung, Magic-Byte-Prüfung, zufälliger Speicherpfad, privater Bucket. */
export async function uploadIncidentFileAction(formData: FormData): Promise<ActionResult> {
  return runAction(async () => {
    const inc = await loadIncident(String(formData.get("incidentId") ?? ""));
    const { admin, user, isDemo } = await authorizeOrg(inc.org_id, "member");
    if (isDemo) throw new UserError("Im Demo-Modus werden keine Dateien gespeichert.");
    const file = formData.get("file");
    if (!(file instanceof File) || file.size === 0) throw new UserError("Bitte wählen Sie eine Datei aus.");
    if (file.size > MAX_UPLOAD_BYTES) throw new UserError("Die Datei ist größer als 4 MB.");
    const ext = ALLOWED_TYPES[file.type];
    if (!ext) throw new UserError("Dateityp nicht erlaubt (PDF, PNG, JPG, TXT, CSV, EML, MSG).");
    const buf = Buffer.from(await file.arrayBuffer());
    const magicOk =
      (ext === "pdf" && buf.subarray(0, 4).toString() === "%PDF") ||
      (ext === "png" && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) ||
      (ext === "jpg" && buf[0] === 0xff && buf[1] === 0xd8) ||
      (ext === "msg" && buf.subarray(0, 4).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0]))) ||
      (["txt", "csv", "eml"].includes(ext) && !buf.subarray(0, 4096).includes(0));
    if (!magicOk) throw new UserError("Der Dateiinhalt passt nicht zum Dateityp.");
    if (!(await rateLimit(`upload:${inc.org_id}`, 3600, 30))) throw new UserError("Upload-Limit erreicht.");
    const safeName = file.name.replace(/[^\w.\- ()äöüÄÖÜß]/g, "_").slice(0, 120);
    const path = `${inc.org_id}/${inc.id}/${randomUUID()}.${ext}`;
    const { error } = await admin.storage.from("incident-files").upload(path, buf, { contentType: file.type, upsert: false });
    if (error) throw new Error(error.message);
    await admin.from("incident_files").insert({ org_id: inc.org_id, incident_id: inc.id, storage_path: path, file_name: safeName, content_type: file.type, size_bytes: file.size, sha256: sha256(buf), uploaded_by: user.id });
    await admin.from("incident_events").insert({ org_id: inc.org_id, incident_id: inc.id, type: "file_added", message: `Datei hinzugefügt: ${safeName}`, actor_id: user.id, actor_label: user.email ?? null });
    await auditUser(inc.org_id, user.id, "incident.file_uploaded", { type: "incident", id: inc.id }, { sha256: sha256(buf), size: file.size });
    revalidatePath(`/app/emergency/${inc.id}`);
    return { ok: true as const, message: "Datei sicher gespeichert" };
  });
}
