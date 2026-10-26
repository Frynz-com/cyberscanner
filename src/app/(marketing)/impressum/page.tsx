import type { Metadata } from "next";
export const metadata: Metadata = { title: "Impressum" };

export default function Page() {
  return (
    <article className="prose mx-auto max-w-3xl space-y-4 px-4 py-16 text-sm sm:px-6">
      <h1 className="text-3xl font-semibold">Impressum</h1>
      <p className="rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-3">Vorlage – vor Veröffentlichung durch die CyberSafe24 GmbH mit den gesetzlich erforderlichen Angaben (§ 5 DDG) zu vervollständigen.</p>
      <p>CyberSafe24 GmbH<br />[Straße, Hausnummer]<br />[PLZ, Ort]</p>
      <p>Vertreten durch die Geschäftsführung: [Name]<br />Registergericht: [Amtsgericht], [HRB-Nummer]<br />USt-IdNr.: [Nummer]</p>
      <p>Kontakt: [Telefon] · [E-Mail]</p>
    </article>
  );
}
