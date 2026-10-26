import { NextResponse } from "next/server";
import { z } from "zod";
import { normalizeHostname } from "@/lib/core/domain";
import { audit } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { clientIpHash, rateLimit } from "@/lib/server/auth";

const schema = z.object({
  domain: z.string().min(1).max(300),
  consent: z.literal(true, { error: "Bitte bestätigen Sie die Hinweise zur Prüfung." }),
  website: z.string().max(0).optional(), // Honeypot – muss leer bleiben
});

/**
 * Öffentlicher Kurzcheck: legt nur einen Job für den isolierten Worker an.
 * Kein Netzwerkzugriff auf das Ziel aus der Web-/Serverless-Umgebung.
 */
export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Ungültige Anfrage" }, { status: 400 });
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Ungültige Eingabe" }, { status: 400 });
  const norm = normalizeHostname(parsed.data.domain);
  if (!norm.ok) return NextResponse.json({ error: norm.error }, { status: 400 });
  const ipHash = await clientIpHash();
  if (!(await rateLimit(`pc-ip-h:${ipHash}`, 3600, 5)) || !(await rateLimit(`pc-ip-d:${ipHash}`, 86400, 15))) {
    return NextResponse.json({ error: "Sie haben das Limit für kostenlose Checks erreicht. Bitte versuchen Sie es später erneut." }, { status: 429 });
  }
  const admin = createAdminClient();
  // Gleiche Domain innerhalb von 10 Minuten: vorhandenes Ergebnis wiederverwenden (schont Zielsysteme)
  const since = new Date(Date.now() - 10 * 60_000).toISOString();
  const { data: recent } = await admin.from("public_checks").select("id").eq("hostname", norm.hostname).gte("created_at", since).neq("status", "failed").order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (recent) return NextResponse.json({ id: recent.id });
  if (!(await rateLimit(`pc-domain:${norm.hostname}`, 3600, 6))) return NextResponse.json({ error: "Diese Domain wurde gerade mehrfach geprüft. Bitte später erneut versuchen." }, { status: 429 });

  const { data: check, error } = await admin.from("public_checks").insert({ hostname: norm.hostname, ip_hash: ipHash }).select("id").single();
  if (error) return NextResponse.json({ error: "Prüfung konnte nicht gestartet werden" }, { status: 500 });
  const { data: job } = await admin
    .from("scan_jobs")
    .insert({ kind: "public_check", trigger: "public", priority: 5, max_attempts: 2, payload: { public_check_id: check.id }, idempotency_key: `public:${check.id}` })
    .select("id")
    .single();
  await admin.from("public_checks").update({ job_id: job?.id ?? null }).eq("id", check.id);
  await audit(admin, { orgId: null, actorType: "public", action: "public_check.requested", targetType: "public_check", targetId: check.id, data: { hostname: norm.hostname }, ipHash });
  return NextResponse.json({ id: check.id }, { status: 201 });
}
