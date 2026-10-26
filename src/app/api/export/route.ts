import { NextResponse } from "next/server";
import { auditUser, authorizeOrg, getOrgContext } from "@/lib/server/auth";

/** DSGVO-Datenexport (Art. 20) der aktuellen Organisation als JSON. Nur Inhaber/Administratoren. */
export async function GET() {
  const ctx = await getOrgContext();
  if (!ctx) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  let admin, userId: string;
  try {
    const a = await authorizeOrg(ctx.org.id, "admin");
    admin = a.admin;
    userId = a.user.id;
  } catch {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const orgId = ctx.org.id;
  const tables = ["domains", "scan_authorizations", "assets", "findings", "finding_events", "actions", "incidents", "incident_events", "notifications", "reports", "timeline_events", "audit_logs"] as const;
  const out: Record<string, unknown> = { exportedAt: new Date().toISOString(), format: "cybersafe24-export-v1" };
  const { data: org } = await admin.from("organizations").select("*").eq("id", orgId).single();
  out.organization = org;
  for (const t of tables) {
    const { data } = await admin.from(t).select("*").eq("org_id", orgId).limit(20000);
    out[t] = data ?? [];
  }
  // Breach-Daten ohne verschlüsselte Rohwerte (Konten sind in der App einsehbar)
  const { data: breaches } = await admin.from("breach_records").select("breach_key, breach_title, breach_date, data_classes, is_stealer_log, first_observed_at, last_observed_at").eq("org_id", orgId);
  out.breach_records = breaches ?? [];
  await auditUser(orgId, userId, "data.exported");
  return new NextResponse(JSON.stringify(out, null, 2), {
    headers: { "content-type": "application/json; charset=utf-8", "content-disposition": `attachment; filename="cybersafe24-export-${new Date().toISOString().slice(0, 10)}.json"` },
  });
}
