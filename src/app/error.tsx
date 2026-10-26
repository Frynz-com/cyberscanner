"use client";

import { Button } from "@/components/ui/button";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="flex min-h-[60dvh] flex-col items-center justify-center gap-4 px-4 text-center">
      <h1 className="text-2xl font-semibold">Etwas ist schiefgelaufen</h1>
      <p className="max-w-md text-sm text-muted-foreground">Bitte versuchen Sie es erneut. Bleibt der Fehler bestehen, kontaktieren Sie uns.</p>
      <Button onClick={reset}>Erneut versuchen</Button>
    </main>
  );
}
