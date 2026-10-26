import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getUser } from "@/lib/server/auth";
import { RegisterForm } from "./register-form";

export const metadata: Metadata = { title: "Registrieren" };

export default async function RegisterPage({ searchParams }: { searchParams: Promise<{ domain?: string }> }) {
  const { domain } = await searchParams;
  if (await getUser()) redirect("/onboarding");
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <p className="text-xs font-medium tracking-wide text-brand uppercase">Schritt 1 von 7</p>
        <h1 className="text-2xl font-semibold tracking-tight">Konto erstellen</h1>
        <p className="text-sm text-muted-foreground">In wenigen Minuten zur ersten Sicherheitsübersicht – ohne Installation.</p>
      </div>
      <RegisterForm domain={domain} />
    </div>
  );
}
