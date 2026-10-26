import "server-only";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";
import { hashIp } from "@/lib/core/crypto";
import { audit } from "@/lib/core/events";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

export const ROLE_RANK = { owner: 100, admin: 80, member: 50, viewer: 10 } as const;
export type Role = keyof typeof ROLE_RANK;
export const ORG_COOKIE = "cs24_org";

export class AuthzError extends Error {
  constructor(message = "Keine Berechtigung für diese Aktion") {
    super(message);
    this.name = "AuthzError";
  }
}

export const getUser = cache(async () => {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user ?? null;
});

export async function requireUser() {
  const user = await getUser();
  if (!user) redirect("/login");
  return user;
}

export interface OrgContext {
  org: {
    id: string;
    name: string;
    is_demo: boolean;
    monitoring_paused: boolean;
    onboarding_step: number;
    contact_email: string | null;
    contact_phone: string | null;
    industry: string | null;
    employee_range: string | null;
    data_retention_days: number;
  };
  role: Role;
  rank: number;
  memberships: Array<{ org_id: string; name: string; role: Role; is_demo: boolean }>;
}

/** Aktuelle Organisation des Nutzers (über RLS geladen – nur eigene Mitgliedschaften sichtbar). */
export const getOrgContext = cache(async (): Promise<OrgContext | null> => {
  const user = await getUser();
  if (!user) return null;
  const supabase = await createClient();
  const { data } = await supabase
    .from("memberships")
    .select("org_id, role, organizations(id, name, is_demo, monitoring_paused, onboarding_step, contact_email, contact_phone, industry, employee_range, data_retention_days, deleted_at)")
    .eq("user_id", user.id);
  const rows = (data ?? []).filter((m) => m.organizations && !(m.organizations as unknown as { deleted_at: string | null }).deleted_at);
  if (rows.length === 0) return null;
  const preferred = (await cookies()).get(ORG_COOKIE)?.value;
  const current = rows.find((r) => r.org_id === preferred) ?? rows[0];
  const role = current.role as Role;
  return {
    org: current.organizations as unknown as OrgContext["org"],
    role,
    rank: ROLE_RANK[role] ?? 0,
    memberships: rows.map((r) => ({
      org_id: r.org_id,
      name: (r.organizations as unknown as { name: string }).name,
      role: r.role as Role,
      is_demo: (r.organizations as unknown as { is_demo: boolean }).is_demo,
    })),
  };
});

export async function requireOrg(): Promise<OrgContext & { userId: string }> {
  const user = await requireUser();
  const ctx = await getOrgContext();
  if (!ctx) redirect("/onboarding");
  return { ...ctx, userId: user.id };
}

/**
 * Verbindliche Rechteprüfung für Server Actions / Route Handler.
 * Prüft die Mitgliedschaft direkt in der Datenbank (nicht nur über Cookies/Client-Angaben).
 */
export async function authorizeOrg(orgId: string, minRole: Role) {
  const user = await getUser();
  if (!user) throw new AuthzError("Bitte melden Sie sich an");
  const admin = createAdminClient();
  const { data: membership } = await admin
    .from("memberships")
    .select("role, organizations(is_demo, deleted_at)")
    .eq("org_id", orgId)
    .eq("user_id", user.id)
    .maybeSingle();
  const org = membership?.organizations as unknown as { is_demo: boolean; deleted_at: string | null } | undefined;
  if (!membership || !org || org.deleted_at) throw new AuthzError();
  const rank = ROLE_RANK[membership.role as Role] ?? 0;
  if (rank < ROLE_RANK[minRole]) throw new AuthzError();
  return { user, role: membership.role as Role, isDemo: org.is_demo, admin };
}

export async function requirePlatformAdmin() {
  const user = await requireUser();
  const admin = createAdminClient();
  const { data } = await admin.from("platform_admins").select("user_id").eq("user_id", user.id).maybeSingle();
  if (!data) redirect("/app");
  return { user, admin };
}

export async function clientIpHash(): Promise<string> {
  const h = await headers();
  const ip = h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? h.get("x-real-ip") ?? "unknown";
  return hashIp(ip);
}

/** Ratenbegrenzung über Postgres (funktioniert auch auf Serverless). true = erlaubt. */
export async function rateLimit(key: string, windowSeconds: number, max: number): Promise<boolean> {
  const admin = createAdminClient();
  const { data, error } = await admin.rpc("rate_limit_hit", { p_key: key, p_window_seconds: windowSeconds, p_max: max });
  if (error) return false; // im Zweifel ablehnen
  return Boolean(data);
}

export async function auditUser(orgId: string | null, userId: string, action: string, target?: { type: string; id: string }, data?: Record<string, unknown>) {
  const admin = createAdminClient();
  await audit(admin, {
    orgId,
    actorType: "user",
    actorId: userId,
    action,
    targetType: target?.type,
    targetId: target?.id,
    data: (data ?? {}) as never,
    ipHash: await clientIpHash(),
  });
}
