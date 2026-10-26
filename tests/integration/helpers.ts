import { config } from "dotenv";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { randomUUID } from "node:crypto";
import type { Database } from "@/lib/database.types";

config({ path: ".env.local", quiet: true });
// Feste Testschlüssel (überschreiben lokale Werte, damit Tests deterministisch sind)
process.env.DATA_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

export const URL_ = process.env.NEXT_PUBLIC_SUPABASE_URL!;
export const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
export const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const service: SupabaseClient<Database> = createClient<Database>(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } });

export async function createUser(prefix: string) {
  const email = `${prefix}-${randomUUID().slice(0, 8)}@test.example.org`;
  const password = "Testpasswort123";
  const { data, error } = await service.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name: prefix } });
  if (error) throw error;
  const client = createClient<Database>(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } });
  const { error: e2 } = await client.auth.signInWithPassword({ email, password });
  if (e2) throw e2;
  return { id: data.user.id, email, client };
}

export async function createOrgWithDomain(userId: string, name: string, hostname: string) {
  const { data: orgId, error } = await service.rpc("create_organization", { p_user: userId, p_name: name, p_industry: "", p_employee_range: "", p_contact_email: "" });
  if (error || !orgId) throw error ?? new Error("org");
  const { data: domain, error: dErr } = await service
    .from("domains")
    .insert({ org_id: orgId, hostname, verification_status: "verified", verified_at: new Date().toISOString() })
    .select("id")
    .single();
  if (dErr) throw dErr;
  await service.from("scan_authorizations").insert({ org_id: orgId, domain_id: domain.id, scopes: ["passive", "config"], statement_version: "test", statement_sha256: "x", signer_name: "Test Person", signer_role: "GF" });
  return { orgId: orgId as string, domainId: domain.id };
}

export const log = { info() {}, warn() {}, error() {} };
