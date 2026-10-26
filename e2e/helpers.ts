import { config } from "dotenv";
import { createClient } from "@supabase/supabase-js";
import type { Page } from "@playwright/test";
import type { Database } from "../src/lib/database.types";
import { processJob } from "../worker/index";
import type { ScanJob } from "../worker/jobs/domain-scan";

config({ path: ".env.local", quiet: true });

export const service = createClient<Database>(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } });
const log = { info() {}, warn() {}, error() {} };

/** Arbeitet wartende Jobs ab – wie der produktive Worker (gleicher Code). */
export async function drainJobs(max = 10) {
  for (let i = 0; i < max; i++) {
    const { data } = await service.rpc("claim_scan_job", { p_worker: "e2e", p_kinds: ["domain_scan", "reverify", "public_check"] });
    const job = (data as ScanJob[] | null)?.[0];
    if (!job) return i;
    await processJob(job, { db: service, env: process.env as Record<string, string | undefined>, log, workerId: "e2e" });
  }
  return max;
}

/**
 * Die DNS-TXT-Verifikation selbst ist in Unit-Tests mit Fixture-Resolver abgedeckt.
 * Im E2E-Test kann für eine fremde Testdomain kein DNS-Eintrag gesetzt werden – daher wird nur
 * dieser eine Schritt über die Datenbank simuliert (genau wie es der erfolgreiche Check täte).
 */
export async function simulateDnsVerification(hostname: string, orgName: string) {
  const { data: org } = await service.from("organizations").select("id").eq("name", orgName).single();
  await service.from("domains").update({ verification_status: "verified", verified_at: new Date().toISOString() }).eq("org_id", org!.id).eq("hostname", hostname);
  await service.from("verification_challenges").update({ consumed_at: new Date().toISOString(), last_result: "present" }).eq("org_id", org!.id);
  await service.from("organizations").update({ onboarding_step: 5 }).eq("id", org!.id);
  return org!.id;
}

export async function register(page: Page, email: string, password = "Sicher12345abc") {
  await page.goto("/register");
  await page.fill("#fullName", "Erika Mustermann");
  await page.fill("#email", email);
  await page.fill("#password", password);
  await page.getByRole("checkbox").click();
  await page.getByRole("button", { name: "Konto erstellen" }).click();
  await page.waitForURL("**/onboarding**");
}

export async function login(page: Page, email: string, password = "Sicher12345abc") {
  await page.goto("/login");
  await page.fill("#email", email);
  await page.fill("#password", password);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
}
