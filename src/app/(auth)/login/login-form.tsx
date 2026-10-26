"use client";

import Link from "next/link";
import { useActionState } from "react";
import { loginAction } from "@/app/actions/auth";
import { FormError, SubmitButton } from "@/components/forms/submit-button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function LoginForm({ next }: { next?: string }) {
  const [state, action] = useActionState(loginAction, null);
  return (
    <form action={action} className="space-y-4">
      <input type="hidden" name="next" value={next ?? ""} />
      <div className="space-y-2">
        <Label htmlFor="email">Geschäftliche E-Mail</Label>
        <Input id="email" name="email" type="email" autoComplete="email" required autoFocus />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Passwort</Label>
        <Input id="password" name="password" type="password" autoComplete="current-password" required />
      </div>
      <FormError message={state && !state.ok ? state.error : undefined} />
      <SubmitButton className="w-full" pendingText="Anmeldung läuft …">Anmelden</SubmitButton>
      <p className="text-center text-sm text-muted-foreground">
        Noch kein Konto? <Link href="/register" className="font-medium text-foreground hover:underline">Jetzt registrieren</Link>
      </p>
    </form>
  );
}
