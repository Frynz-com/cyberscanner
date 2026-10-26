"use server";

import { redirect } from "next/navigation";
import { z } from "zod";
import { createClient } from "@/lib/supabase/server";
import { clientIpHash, rateLimit } from "@/lib/server/auth";
import { formToObject, runAction, type ActionResult } from "@/lib/server/action";

const passwordSchema = z
  .string()
  .min(10, "Das Passwort muss mindestens 10 Zeichen lang sein.")
  .max(128)
  .regex(/[a-zA-Z]/, "Das Passwort muss Buchstaben enthalten.")
  .regex(/\d/, "Das Passwort muss mindestens eine Ziffer enthalten.");

const registerSchema = z.object({
  fullName: z.string().trim().min(2, "Bitte geben Sie Ihren Namen ein.").max(120),
  email: z.email("Bitte geben Sie eine gültige E-Mail-Adresse ein.").max(254),
  password: passwordSchema,
  terms: z.literal("on", { error: "Bitte stimmen Sie den Nutzungsbedingungen und der Datenschutzerklärung zu." }),
});

function safeNext(next: string | undefined): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/app";
}

export async function registerAction(_: unknown, formData: FormData): Promise<ActionResult<{ confirm: boolean }>> {
  const result = await runAction(async () => {
    if (!(await rateLimit(`register:${await clientIpHash()}`, 3600, 10))) {
      return { ok: false as const, error: "Zu viele Versuche. Bitte versuchen Sie es später erneut." };
    }
    const input = registerSchema.parse(formToObject(formData));
    const supabase = await createClient();
    const { data, error } = await supabase.auth.signUp({
      email: input.email.toLowerCase(),
      password: input.password,
      options: {
        data: { full_name: input.fullName },
        emailRedirectTo: `${process.env.APP_URL}/auth/confirm?next=/onboarding`,
      },
    });
    if (error) {
      if (/registered|exists/i.test(error.message)) return { ok: false as const, error: "Für diese E-Mail-Adresse besteht bereits ein Konto." };
      if (/weak|password/i.test(error.message)) return { ok: false as const, error: "Das Passwort ist zu schwach." };
      return { ok: false as const, error: "Die Registrierung ist fehlgeschlagen. Bitte versuchen Sie es erneut." };
    }
    return { ok: true as const, data: { confirm: !data.session } };
  });
  if (result.ok && !result.data?.confirm) redirect("/onboarding");
  return result;
}

const loginSchema = z.object({
  email: z.email("Bitte geben Sie eine gültige E-Mail-Adresse ein."),
  password: z.string().min(1, "Bitte geben Sie Ihr Passwort ein."),
  next: z.string().optional(),
});

export async function loginAction(_: unknown, formData: FormData): Promise<ActionResult> {
  let next = "/app";
  const result = await runAction(async () => {
    const input = loginSchema.parse(formToObject(formData));
    next = safeNext(input.next);
    if (!(await rateLimit(`login:${await clientIpHash()}`, 900, 20))) {
      return { ok: false as const, error: "Zu viele Anmeldeversuche. Bitte warten Sie einige Minuten." };
    }
    const supabase = await createClient();
    const { error } = await supabase.auth.signInWithPassword({ email: input.email.toLowerCase(), password: input.password });
    if (error) return { ok: false as const, error: "E-Mail-Adresse oder Passwort ist nicht korrekt." };
    return { ok: true as const };
  });
  if (result.ok) redirect(next);
  return result;
}

export async function logoutAction() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  redirect("/login");
}
