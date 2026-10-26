"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";
import { clientIpHash, ORG_COOKIE, rateLimit } from "@/lib/server/auth";

/** Meldet Besucher im separaten Demo-Mandanten an (synthetische Daten, keine echten Prüfungen). */
export async function startDemoAction(): Promise<{ error: string } | void> {
  const email = process.env.DEMO_USER_EMAIL;
  const password = process.env.DEMO_USER_PASSWORD;
  if (!email || !password) return { error: "Der Demo-Modus ist in dieser Umgebung nicht eingerichtet." };
  if (!(await rateLimit(`demo:${await clientIpHash()}`, 3600, 20))) return { error: "Bitte versuchen Sie es später erneut." };
  const admin = createAdminClient();
  const { data: org } = await admin.from("organizations").select("id").eq("is_demo", true).limit(1).maybeSingle();
  if (!org) return { error: "Der Demo-Mandant wurde noch nicht angelegt (pnpm demo:seed)." };
  const supabase = await createClient();
  await supabase.auth.signOut();
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return { error: "Demo-Anmeldung fehlgeschlagen." };
  (await cookies()).set(ORG_COOKIE, org.id, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
  redirect("/app");
}
