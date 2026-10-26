import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getUser } from "@/lib/server/auth";
import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Anmelden" };

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  if (await getUser()) redirect("/app");
  const { next } = await searchParams;
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Willkommen zurück</h1>
        <p className="text-sm text-muted-foreground">Melden Sie sich an, um den Sicherheitsstatus Ihres Unternehmens zu sehen.</p>
      </div>
      <LoginForm next={next} />
    </div>
  );
}
