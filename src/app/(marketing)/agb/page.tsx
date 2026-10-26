import type { Metadata } from "next";
export const metadata: Metadata = { title: "AGB" };

export default function Page() {
  return (
    <article className="mx-auto max-w-3xl space-y-4 px-4 py-16 text-sm sm:px-6">
      <h1 className="text-3xl font-semibold">Allgemeine Geschäftsbedingungen</h1>
      <p className="rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-3">Vorlage – die AGB sind vor dem Vertrieb durch die CyberSafe24 GmbH juristisch zu erstellen.</p>
      <p>Wesentliche Leistungsgrenzen, die in den AGB abzubilden sind: CyberSafe24 Shield ist eine externe Überwachung öffentlich sichtbarer Konfigurationen und bekannter Datenleck-Hinweise. Es handelt sich nicht um einen Penetrationstest, keine Zertifizierung und keine Zusicherung vollständiger Sicherheit. Persönliche Notfallunterstützung und Reaktionszeiten gelten nur bei gesonderter vertraglicher Vereinbarung.</p>
    </article>
  );
}
