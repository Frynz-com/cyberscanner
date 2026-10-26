import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg } from "@/lib/server/auth";

/** Download über kurzlebige signierte URL – nur für Mitglieder der Organisation. */
export async function GET(_: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return NextResponse.json({ error: "not found" }, { status: 404 });
  const admin = createAdminClient();
  const { data: file } = await admin.from("incident_files").select("id, org_id, storage_path, file_name").eq("id", id).maybeSingle();
  if (!file) return NextResponse.json({ error: "not found" }, { status: 404 });
  try {
    const { user } = await authorizeOrg(file.org_id, "member");
    const { data, error } = await admin.storage.from("incident-files").createSignedUrl(file.storage_path, 60, { download: file.file_name });
    if (error || !data) return NextResponse.json({ error: "unavailable" }, { status: 500 });
    await auditUser(file.org_id, user.id, "incident.file_downloaded", { type: "incident_file", id: file.id });
    return NextResponse.redirect(data.signedUrl);
  } catch {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
}
