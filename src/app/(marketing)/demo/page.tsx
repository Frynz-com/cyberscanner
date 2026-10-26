import type { Metadata } from "next";
import { FlaskConical } from "lucide-react";
import { DemoStart } from "./start";

export const metadata: Metadata = { title: "Demo" };

export default function DemoPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-20 text-center sm:px-6">
      <span className="inline-flex items-center gap-2 rounded-full bg-violet-500/10 px-3 py-1 text-xs font-semibold text-violet-700"><FlaskConical className="size-3.5" /> DEMO-MODUS</span>
      <h1 className="mt-5 text-4xl font-semibold tracking-tight">CyberSafe24 Shield live erleben</h1>
      <p className="mt-4 text-muted-foreground">
        Die Demo zeigt einen fiktiven Maschinenbauer mit realistischen, aber vollständig <strong>synthetischen</strong> Daten: Befunde, Security-Timeline, IT-Dienstleister-Workflow, Notfallbereich und einen Musterbericht. Es werden keine echten Systeme geprüft und keine E-Mails versendet.
      </p>
      <DemoStart />
    </div>
  );
}
