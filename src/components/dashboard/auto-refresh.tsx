"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** Aktualisiert die Seite, solange Prüfungen laufen (sanftes Polling, kein Scan-Trigger). */
export function AutoRefresh({ active, intervalMs = 8000 }: { active: boolean; intervalMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => router.refresh(), intervalMs);
    return () => clearInterval(t);
  }, [active, intervalMs, router]);
  return null;
}
