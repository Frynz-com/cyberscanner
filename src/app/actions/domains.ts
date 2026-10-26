"use server";

import { headers } from "next/headers";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { authorizationStatement, AUTHORIZATION_STATEMENT_VERSION, statementHash } from "@/lib/core/authorization-statement";
import { randomToken } from "@/lib/core/crypto";
import { normalizeHostname, VERIFICATION_PREFIX } from "@/lib/core/domain";
import { getEntitlements } from "@/lib/core/entitlements";
import { addTimeline } from "@/lib/core/events";
import { DohResolver, resolveTxt } from "@/lib/core/net/dns";
import { createAdminClient } from "@/lib/supabase/admin";
import { auditUser, authorizeOrg, clientIpHash, getUser, rateLimit } from "@/lib/server/auth";
import { formToObject, runAction, UserError, type ActionResult } from "@/lib/server/action";


export async function addDomainAction(_: unknown, formData: FormData): Promise<ActionResult<{ domainId: string }>> {
  return runAction(async () => {
    const orgId = z.uuid().parse(formData.get("orgId"));
    const { user, admin, isDemo } = await authorizeOrg(orgId, "admin");
    if (isDemo) throw new UserError("Im Demo-Modus können keine echten Domains hinzugefügt werden.");
    const norm = normalizeHostname(String(formData.get("domain") ?? ""));
    if (!norm.ok) return { ok: false as const, error: norm.error, fieldErrors: { domain: norm.error } };
    const ent = await getEntitlements(admin, orgId);
    const { count } = await admin.from("domains").select("id", { count: "exact", head: true }).eq("org_id", orgId);
    const limit = Math.max(ent.limits.max_domains, ent.active ? 0 : 1);
    if ((count ?? 0) >= limit) throw new UserError(`Ihr Tarif erlaubt ${limit} Domain(s). Bitte wechseln Sie den Tarif, um weitere hinzuzufügen.`);
    const { data: domain, error } = await admin
      .from("domains")
      .insert({ org_id: orgId, hostname: norm.hostname, created_by: user.id, scan_interval_hours: Math.max(24, ent.limits.min_scan_interval_hours) })
      .select("id")
      .single();
    if (error) {
      if (error.code === "23505") throw new UserError("Diese Domain ist bereits hinterlegt.");
      throw new Error(error.message);
    }
    await admin.from("verification_challenges").insert({
      org_id: orgId,
      domain_id: domain.id,
      record_name: `${VERIFICATION_PREFIX}.${norm.hostname}`,
      token: `cs24-verify=${randomToken(24)}`,
    });
    await admin.from("organizations").update({ onboarding_step: 4 }).eq("id", orgId).lt("onboarding_step", 4);
    await addTimeline(admin, { orgId, type: "domain_added", title: `Domain ${norm.hostname} hinzugefügt`, domainId: domain.id });
    await auditUser(orgId, user.id, "domain.added", { type: "domain", id: domain.id }, { hostname: norm.hostname });
    revalidatePath("/app", "layout");
    revalidatePath("/onboarding");
    return { ok: true as const, data: { domainId: domain.id } };
  });
}

export async function checkVerificationAction(domainId: string): Promise<ActionResult<{ verified: boolean; found: string[] }>> {
  return runAction<{ verified: boolean; found: string[] }>(async () => {
    const id = z.uuid().parse(domainId);
    const user = await getUser();
    if (!user) throw new UserError("Bitte melden Sie sich an");
    const { data: domain } = await createAdminClient().from("domains").select("id, org_id, hostname, verification_status").eq("id", id).maybeSingle();
    if (!domain) throw new UserError("Domain nicht gefunden");
    const { admin } = await authorizeOrg(domain.org_id, "admin");
    if (!(await rateLimit(`verify:${domain.id}`, 60, 6))) throw new UserError("Bitte warten Sie einen Moment, bevor Sie erneut prüfen.");

    const { data: challenge } = await admin
      .from("verification_challenges")
      .select("*")
      .eq("domain_id", domain.id)
      .is("consumed_at", null)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (!challenge) throw new UserError("Keine offene Verifizierung gefunden.");
    if (new Date(challenge.expires_at) < new Date()) throw new UserError("Der Verifizierungscode ist abgelaufen. Bitte fordern Sie einen neuen an.");

    // DNS-Abfrage über festen DoH-Resolver (kein Kontakt zu Kundensystemen)
    let found: string[] = [];
    try {
      const res = await resolveTxt(new DohResolver(), challenge.record_name);
      found = res.records.map((r) => r.trim());
    } catch {
      throw new UserError("Die DNS-Abfrage ist fehlgeschlagen. Bitte versuchen Sie es in einer Minute erneut.");
    }
    const ok = found.includes(challenge.token);
    const now = new Date().toISOString();
    await admin
      .from("verification_challenges")
      .update({ attempts: challenge.attempts + 1, last_checked_at: now, last_result: ok ? "present" : "not_found", ...(ok ? { consumed_at: now } : {}) })
      .eq("id", challenge.id);
    if (!ok) return { ok: true as const, data: { verified: false, found: found.slice(0, 5) } };

    await admin
      .from("domains")
      .update({ verification_status: "verified", verified_at: now, verification_last_checked_at: now })
      .eq("id", domain.id);
    await admin.from("organizations").update({ onboarding_step: 5 }).eq("id", domain.org_id).lt("onboarding_step", 5);
    await addTimeline(admin, { orgId: domain.org_id, type: "domain_verified", severity: "success", title: `Domain ${domain.hostname} verifiziert`, domainId: domain.id });
    await auditUser(domain.org_id, user.id, "domain.verified", { type: "domain", id: domain.id });
    revalidatePath("/app", "layout");
    revalidatePath("/onboarding");
    return { ok: true as const, data: { verified: true, found: [] } };
  });
}

export async function renewChallengeAction(domainId: string): Promise<ActionResult> {
  return runAction(async () => {
    const { data: domain } = await createAdminClient().from("domains").select("id, org_id, hostname").eq("id", z.uuid().parse(domainId)).maybeSingle();
    if (!domain) throw new UserError("Domain nicht gefunden");
    const { admin, user } = await authorizeOrg(domain.org_id, "admin");
    await admin.from("verification_challenges").update({ consumed_at: new Date().toISOString(), last_result: "replaced" }).eq("domain_id", domain.id).is("consumed_at", null);
    await admin.from("verification_challenges").insert({
      org_id: domain.org_id,
      domain_id: domain.id,
      record_name: `${VERIFICATION_PREFIX}.${domain.hostname}`,
      token: `cs24-verify=${randomToken(24)}`,
    });
    await admin.from("domains").update({ verification_status: "pending" }).eq("id", domain.id).neq("verification_status", "verified");
    await auditUser(domain.org_id, user.id, "domain.challenge_renewed", { type: "domain", id: domain.id });
    revalidatePath("/app/domains");
    revalidatePath("/onboarding");
    return { ok: true as const };
  });
}

const authSchema = z.object({
  domainId: z.uuid(),
  signerName: z.string().trim().min(2, "Bitte geben Sie Ihren Namen ein.").max(120),
  signerRole: z.string().trim().min(2, "Bitte geben Sie Ihre Funktion an.").max(120),
  scopePassive: z.literal("on").optional(),
  scopeConfig: z.literal("on").optional(),
  includeSubdomains: z.literal("on").optional(),
  confirm: z.literal("on", { error: "Bitte bestätigen Sie die Berechtigung." }),
});

export async function grantAuthorizationAction(_: unknown, formData: FormData): Promise<ActionResult> {
  return runAction(async () => {
    const input = authSchema.parse(formToObject(formData));
    const { data: domain } = await createAdminClient().from("domains").select("id, org_id, hostname, verification_status").eq("id", input.domainId).maybeSingle();
    if (!domain) throw new UserError("Domain nicht gefunden");
    const { admin, user, isDemo } = await authorizeOrg(domain.org_id, "admin");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    if (domain.verification_status !== "verified") throw new UserError("Bitte verifizieren Sie zuerst die Domain.");
    const scopes = [input.scopePassive && "passive", input.scopeConfig && "config"].filter(Boolean) as string[];
    if (scopes.length === 0) throw new UserError("Bitte wählen Sie mindestens eine Prüfart aus.");
    const { data: org } = await admin.from("organizations").select("name").eq("id", domain.org_id).single();
    const statement = authorizationStatement({
      orgName: org!.name,
      domain: domain.hostname,
      scopes,
      includeSubdomains: Boolean(input.includeSubdomains),
      signerName: input.signerName,
      signerRole: input.signerRole,
    });
    // vorherige Autorisierungen ersetzen (Historie bleibt erhalten)
    await admin.from("scan_authorizations").update({ revoked_at: new Date().toISOString(), revoked_by: user.id }).eq("domain_id", domain.id).is("revoked_at", null);
    const h = await headers();
    const { data: auth, error } = await admin
      .from("scan_authorizations")
      .insert({
        org_id: domain.org_id,
        domain_id: domain.id,
        scopes,
        include_subdomains: Boolean(input.includeSubdomains),
        statement_version: AUTHORIZATION_STATEMENT_VERSION,
        statement_sha256: statementHash(statement),
        signer_name: input.signerName,
        signer_role: input.signerRole,
        granted_by: user.id,
        ip_hash: await clientIpHash(),
        user_agent: (h.get("user-agent") ?? "").slice(0, 300),
      })
      .select("id")
      .single();
    if (error) throw new Error(error.message);
    // Erste Prüfung startet der Nutzer im Onboarding; der Zeitplan beginnt danach
    const { data: dom } = await admin.from("domains").select("scan_interval_hours").eq("id", domain.id).single();
    await admin.from("domains").update({ next_scan_at: new Date(Date.now() + (dom?.scan_interval_hours ?? 24) * 3600_000).toISOString() }).eq("id", domain.id).is("next_scan_at", null);
    await admin.from("organizations").update({ onboarding_step: 6 }).eq("id", domain.org_id).lt("onboarding_step", 6);
    await addTimeline(admin, { orgId: domain.org_id, type: "authorization_granted", title: `Prüfberechtigung für ${domain.hostname} erteilt`, body: `Durch ${input.signerName} (${input.signerRole})`, domainId: domain.id });
    await auditUser(domain.org_id, user.id, "authorization.granted", { type: "scan_authorization", id: auth.id }, { scopes, statementSha256: statementHash(statement) });
    revalidatePath("/app", "layout");
    revalidatePath("/onboarding");
    return { ok: true as const };
  });
}

export async function revokeAuthorizationAction(domainId: string): Promise<ActionResult> {
  return runAction(async () => {
    const { data: domain } = await createAdminClient().from("domains").select("id, org_id").eq("id", z.uuid().parse(domainId)).maybeSingle();
    if (!domain) throw new UserError("Domain nicht gefunden");
    const { admin, user } = await authorizeOrg(domain.org_id, "admin");
    await admin.from("scan_authorizations").update({ revoked_at: new Date().toISOString(), revoked_by: user.id }).eq("domain_id", domain.id).is("revoked_at", null);
    await admin.from("scan_jobs").update({ cancel_requested: true }).eq("domain_id", domain.id).in("status", ["queued", "running"]);
    await auditUser(domain.org_id, user.id, "authorization.revoked", { type: "domain", id: domain.id });
    revalidatePath("/app", "layout");
    return { ok: true as const, message: "Autorisierung widerrufen. Es finden keine weiteren Prüfungen statt." };
  });
}

/** Startet eine zulässige, manuelle Prüfung (mit Tageslimit und Idempotenz). */
export async function requestScanAction(domainId: string, trigger: "manual" | "onboarding" = "manual"): Promise<ActionResult<{ jobId: string }>> {
  return runAction(async () => {
    const { data: domain } = await createAdminClient().from("domains").select("id, org_id, hostname, verification_status").eq("id", z.uuid().parse(domainId)).maybeSingle();
    if (!domain) throw new UserError("Domain nicht gefunden");
    const { admin, user, isDemo } = await authorizeOrg(domain.org_id, "member");
    if (isDemo) throw new UserError("Im Demo-Modus werden keine echten Prüfungen ausgeführt.");
    if (domain.verification_status !== "verified") throw new UserError("Die Domain ist nicht verifiziert.");
    const { data: auth } = await admin.from("scan_authorizations").select("id").eq("domain_id", domain.id).is("revoked_at", null).gt("valid_until", new Date().toISOString()).limit(1).maybeSingle();
    if (!auth) throw new UserError("Bitte erteilen Sie zuerst die Prüfberechtigung.");
    const ent = await getEntitlements(admin, domain.org_id);
    if (!ent.active) throw new UserError("Ihr Abonnement ist nicht aktiv. Bitte prüfen Sie die Abrechnung.");
    const { data: active } = await admin.from("scan_jobs").select("id").eq("domain_id", domain.id).in("status", ["queued", "running"]).in("kind", ["domain_scan"]).limit(1).maybeSingle();
    if (active) return { ok: true as const, data: { jobId: active.id }, message: "Für diese Domain läuft bereits eine Prüfung." };
    const since = new Date(Date.now() - 86_400_000).toISOString();
    const { count } = await admin.from("scan_jobs").select("id", { count: "exact", head: true }).eq("org_id", domain.org_id).in("trigger", ["manual", "onboarding"]).gte("created_at", since);
    if ((count ?? 0) >= ent.limits.manual_scans_per_day) throw new UserError(`Tageslimit von ${ent.limits.manual_scans_per_day} manuellen Prüfungen erreicht.`);
    const { data: job, error } = await admin
      .from("scan_jobs")
      .insert({
        org_id: domain.org_id,
        domain_id: domain.id,
        kind: "domain_scan",
        trigger,
        priority: 10,
        requested_by: user.id,
        idempotency_key: `manual:${domain.id}:${Math.floor(Date.now() / 60_000)}`,
      })
      .select("id")
      .single();
    if (error) {
      if (error.code === "23505") return { ok: true as const, message: "Prüfung wurde bereits angefordert." };
      throw new Error(error.message);
    }
    await auditUser(domain.org_id, user.id, "scan.requested", { type: "scan_job", id: job.id });
    revalidatePath("/app", "layout");
    return { ok: true as const, data: { jobId: job.id }, message: "Prüfung gestartet" };
  });
}

export async function cancelScanAction(jobId: string): Promise<ActionResult> {
  return runAction(async () => {
    const { data: job } = await createAdminClient().from("scan_jobs").select("id, org_id, status").eq("id", z.uuid().parse(jobId)).maybeSingle();
    if (!job?.org_id) throw new UserError("Prüfung nicht gefunden");
    const { admin, user } = await authorizeOrg(job.org_id, "member");
    if (job.status === "queued") await admin.from("scan_jobs").update({ status: "cancelled", cancel_requested: true, finished_at: new Date().toISOString() }).eq("id", job.id).eq("status", "queued");
    else if (job.status === "running") await admin.from("scan_jobs").update({ cancel_requested: true }).eq("id", job.id);
    await auditUser(job.org_id, user.id, "scan.cancelled", { type: "scan_job", id: job.id });
    revalidatePath("/app", "layout");
    return { ok: true as const, message: "Abbruch angefordert" };
  });
}

const settingsSchema = z.object({
  domainId: z.uuid(),
  intervalHours: z.coerce.number().int().min(6).max(744),
  monitoringEnabled: z.enum(["on", "off"]).optional(),
});

export async function updateDomainSettingsAction(_: unknown, formData: FormData): Promise<ActionResult> {
  return runAction(async () => {
    const input = settingsSchema.parse(formToObject(formData));
    const { data: domain } = await createAdminClient().from("domains").select("id, org_id").eq("id", input.domainId).maybeSingle();
    if (!domain) throw new UserError("Domain nicht gefunden");
    const { admin, user, isDemo } = await authorizeOrg(domain.org_id, "admin");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    const ent = await getEntitlements(admin, domain.org_id);
    if (input.intervalHours < ent.limits.min_scan_interval_hours)
      throw new UserError(`Ihr Tarif erlaubt Prüfungen höchstens alle ${ent.limits.min_scan_interval_hours} Stunden.`);
    await admin
      .from("domains")
      .update({ scan_interval_hours: input.intervalHours, monitoring_enabled: input.monitoringEnabled !== "off" })
      .eq("id", domain.id);
    await auditUser(domain.org_id, user.id, "domain.settings_updated", { type: "domain", id: domain.id }, { interval: input.intervalHours });
    revalidatePath("/app/domains");
    return { ok: true as const, message: "Einstellungen gespeichert" };
  });
}

export async function setAssetVulnScanAction(assetId: string, approved: boolean): Promise<ActionResult> {
  return runAction(async () => {
    const { data: asset } = await createAdminClient().from("assets").select("id, org_id, kind, value").eq("id", z.uuid().parse(assetId)).maybeSingle();
    if (!asset) throw new UserError("Asset nicht gefunden");
    const { admin, user, isDemo } = await authorizeOrg(asset.org_id, "owner");
    if (isDemo) throw new UserError("Im Demo-Modus nicht verfügbar.");
    if (asset.kind === "ip") throw new UserError("IP-Adressen können nicht direkt freigegeben werden.");
    const ent = await getEntitlements(admin, asset.org_id);
    if (approved && !ent.limits.vuln_scan) throw new UserError("Die Schwachstellenprüfung ist nur im Tarif Shield Care enthalten.");
    await admin.from("assets").update({ vuln_scan_approved: approved }).eq("id", asset.id);
    await auditUser(asset.org_id, user.id, approved ? "asset.vuln_scan_approved" : "asset.vuln_scan_revoked", { type: "asset", id: asset.id }, { value: asset.value });
    revalidatePath("/app/assets");
    return { ok: true as const };
  });
}

export async function getScanJobStatusAction(jobId: string): Promise<ActionResult<{ status: string; error: string | null; summary: unknown; startedAt: string | null; finishedAt: string | null }>> {
  return runAction<{ status: string; error: string | null; summary: unknown; startedAt: string | null; finishedAt: string | null }>(async () => {
    const { data: job } = await createAdminClient().from("scan_jobs").select("id, org_id, status, error, summary, started_at, finished_at").eq("id", z.uuid().parse(jobId)).maybeSingle();
    if (!job?.org_id) throw new UserError("Prüfung nicht gefunden");
    await authorizeOrg(job.org_id, "viewer");
    return { ok: true as const, data: { status: job.status, error: job.error, summary: job.summary, startedAt: job.started_at, finishedAt: job.finished_at } };
  });
}
