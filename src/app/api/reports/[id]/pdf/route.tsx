import { renderToBuffer } from "@react-pdf/renderer";
import { NextResponse } from "next/server";
import type { ReportSnapshot } from "@/lib/core/report-data";
import { ReportDocument } from "@/lib/pdf/report-document";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg } from "@/lib/server/auth";

export const runtime = "nodejs";

export async function GET(_: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return NextResponse.json({ error: "not found" }, { status: 404 });
  const admin = createAdminClient();
  const { data: report } = await admin.from("reports").select("id, org_id, snapshot, period_start, kind").eq("id", id).maybeSingle();
  if (!report) return NextResponse.json({ error: "not found" }, { status: 404 });
  let userId: string;
  try {
    ({ user: { id: userId } } = await authorizeOrg(report.org_id, "viewer"));
  } catch {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  const snap = report.snapshot as unknown as ReportSnapshot;
  const pdf = await renderToBuffer(<ReportDocument snap={snap} />);
  await auditUser(report.org_id, userId, "report.downloaded", { type: "report", id: report.id });
  const name = `CyberSafe24-Sicherheitsbericht-${snap.organization.name.replace(/[^\w-]+/g, "_")}-${report.period_start.slice(0, 10)}.pdf`;
  return new NextResponse(new Uint8Array(pdf), {
    headers: { "content-type": "application/pdf", "content-disposition": `attachment; filename="${name}"`, "cache-control": "no-store" },
  });
}
