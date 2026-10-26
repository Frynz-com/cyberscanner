import type { Metadata } from "next";
export const metadata: Metadata = { title: "Datenschutz" };

export default function Page() {
  return (
    <article className="mx-auto max-w-3xl space-y-4 px-4 py-16 text-sm sm:px-6">
      <h1 className="text-3xl font-semibold">Datenschutzerklärung</h1>
      <p className="rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-3">Entwurf – vor Veröffentlichung juristisch prüfen und um Verantwortlichen, Datenschutzbeauftragten, Auftragsverarbeiter und Speicherorte ergänzen.</p>
      <h2 className="text-lg font-semibold">Welche Daten wir verarbeiten</h2>
      <ul className="list-disc space-y-1 pl-5">
        <li>Kontodaten (Name, E-Mail-Adresse) zur Bereitstellung des Dienstes.</li>
        <li>Technische Prüfergebnisse zu den von Ihnen verifizierten Domains.</li>
        <li>Hinweise auf Datenlecks: betroffene Firmen-E-Mail-Adressen werden verschlüsselt gespeichert; Passwörter werden weder abgerufen noch gespeichert.</li>
        <li>IP-Adressen werden für Ratenbegrenzung und Protokollierung nur als nicht umkehrbarer Hash gespeichert.</li>
        <li>Kostenloser Kurzcheck: geprüfte Domain und Ergebnis werden nach 7 Tagen gelöscht.</li>
      </ul>
      <h2 className="text-lg font-semibold">Ihre Rechte</h2>
      <p>Sie können Ihre Daten jederzeit in den Einstellungen exportieren (Art. 20 DSGVO) und Ihre Organisation löschen. Die endgültige Löschung erfolgt 30 Tage nach Anforderung.</p>
      <h2 className="text-lg font-semibold">Datenquellen</h2>
      <p>Datenleck-Informationen stammen u. a. von Have I Been Pwned (haveibeenpwned.com, CC BY 4.0).</p>
    </article>
  );
}
