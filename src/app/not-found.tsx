import Link from "next/link";
import { Logo } from "@/components/brand/logo";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-6 px-4 text-center">
      <Logo />
      <div className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">Fehler 404</p>
        <h1 className="text-2xl font-semibold">Seite nicht gefunden</h1>
        <p className="max-w-md text-sm text-muted-foreground">Die Seite existiert nicht oder Sie haben keinen Zugriff darauf.</p>
      </div>
      <Button asChild><Link href="/app">Zur Übersicht</Link></Button>
    </main>
  );
}
