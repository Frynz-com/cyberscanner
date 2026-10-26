import "server-only";
import { sha256 } from "@/lib/core/crypto";
import { createAdminClient } from "@/lib/supabase/admin";

export interface PartnerSession {
  inviteId: string;
  orgId: string;
  orgName: string;
  email: string;
  companyName: string | null;
  contactName: string | null;
  expiresAt: string;
  findingIds: string[];
}

/**
 * Validiert einen Partner-Link. Das Token selbst wird nie gespeichert, nur sein SHA-256-Hash.
 * Zugriff ausschließlich auf ausdrücklich freigegebene Befunde – niemals auf das Kundenkonto.
 */
export async function resolvePartnerToken(token: string, touch = true): Promise<PartnerSession | null> {
  if (!/^[A-Za-z0-9_-]{40,64}$/.test(token)) return null;
  const admin = createAdminClient();
  const { data: invite } = await admin
    .from("service_provider_invites")
    .select("id, org_id, email, company_name, contact_name, expires_at, revoked_at, access_count, organizations(name, deleted_at)")
    .eq("token_hash", sha256(token))
    .maybeSingle();
  if (!invite || invite.revoked_at || new Date(invite.expires_at) < new Date()) return null;
  const org = invite.organizations as unknown as { name: string; deleted_at: string | null } | null;
  if (!org || org.deleted_at) return null;
  const { data: shares } = await admin.from("service_provider_shares").select("finding_id").eq("invite_id", invite.id);
  if (touch) {
    await admin.from("service_provider_invites").update({ last_access_at: new Date().toISOString(), access_count: invite.access_count + 1 }).eq("id", invite.id);
  }
  return {
    inviteId: invite.id,
    orgId: invite.org_id,
    orgName: org.name,
    email: invite.email,
    companyName: invite.company_name,
    contactName: invite.contact_name,
    expiresAt: invite.expires_at,
    findingIds: (shares ?? []).map((s) => s.finding_id),
  };
}
