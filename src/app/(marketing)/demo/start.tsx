"use client";

import { useState, useTransition } from "react";
import { ArrowRight, Loader2 } from "lucide-react";
import { startDemoAction } from "@/app/actions/demo";
import { Button } from "@/components/ui/button";

export function DemoStart() {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="mt-8 space-y-3">
      <Button size="lg" disabled={pending} onClick={() => start(async () => { const r = await startDemoAction(); if (r?.error) setError(r.error); })} data-testid="start-demo">
        {pending ? <Loader2 className="animate-spin" /> : null} Demo starten <ArrowRight />
      </Button>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <p className="text-xs text-muted-foreground">Hinweis: Eine bestehende Anmeldung in diesem Browser wird dabei beendet.</p>
    </div>
  );
}
