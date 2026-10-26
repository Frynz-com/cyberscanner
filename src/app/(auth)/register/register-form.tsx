"use client";

import Link from "next/link";
import { useActionState } from "react";
import { MailCheck } from "lucide-react";
import { registerAction } from "@/app/actions/auth";
import { FieldError, FormError, SubmitButton } from "@/components/forms/submit-button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function RegisterForm() {
  const [state, action] = useActionState(registerAction, null);
  if (state?.ok && state.data?.confirm) {
    return (
      <div className="space-y-3 rounded-xl border bg-card p-6 text-center">
        <MailCheck className="mx-auto size-8 text-brand" />
        <h2 className="font-semibold">Bitte bestätigen Sie Ihre E-Mail-Adresse</h2>
        <p className="text-sm text-muted-foreground">Wir haben Ihnen einen Bestätigungslink gesendet. Danach geht es direkt mit der Einrichtung weiter.</p>
      </div>
    );
  }
  const fe = state && !state.ok ? state.fieldErrors : undefined;
  return (
    <form action={action} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="fullName">Ihr Name</Label>
        <Input id="fullName" name="fullName" autoComplete="name" required autoFocus />
        <FieldError message={fe?.fullName} />
      </div>
      <div className="space-y-2">
        <Label htmlFor="email">Geschäftliche E-Mail</Label>
        <Input id="email" name="email" type="email" autoComplete="email" required />
        <FieldError message={fe?.email} />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Passwort</Label>
        <Input id="password" name="password" type="password" autoComplete="new-password" minLength={10} required />
        <p className="text-xs text-muted-foreground">Mindestens 10 Zeichen mit Buchstaben und Ziffern.</p>
        <FieldError message={fe?.password} />
      </div>
      <label className="flex items-start gap-2.5 text-sm text-muted-foreground">
        <Checkbox name="terms" className="mt-0.5" required />
        <span>
          Ich akzeptiere die <Link href="/agb" className="underline">Nutzungsbedingungen</Link> und habe die <Link href="/datenschutz" className="underline">Datenschutzerklärung</Link> gelesen.
        </span>
      </label>
      <FormError message={state && !state.ok && !fe?.password && !fe?.email && !fe?.fullName ? state.error : undefined} />
      <SubmitButton className="w-full" pendingText="Konto wird erstellt …">Konto erstellen</SubmitButton>
      <p className="text-center text-sm text-muted-foreground">
        Bereits registriert? <Link href="/login" className="font-medium text-foreground hover:underline">Anmelden</Link>
      </p>
    </form>
  );
}
