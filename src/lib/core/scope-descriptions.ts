/** Beschreibung der Prüfarten (auch im Client verwendbar). */
export const SCOPE_DESCRIPTIONS = {
  passive: {
    title: "Öffentliche Datenquellen auswerten",
    text: "Auswertung öffentlich verfügbarer Informationen ohne direkten Kontakt zu Ihren Systemen: DNS-Einträge, Certificate-Transparency-Logs, passive Subdomain-Quellen, Shodan-Daten (sofern lizenziert) und Datenleck-Datenbanken (sofern aktiviert).",
  },
  config: {
    title: "Schonende Konfigurationsprüfung",
    text: "Aufruf Ihrer Webseiten und Abruf der TLS-Zertifikate – vergleichbar mit einem normalen Browserbesuch (wenige Anfragen, keine Formulareingaben, keine Anmeldeversuche).",
  },
  vuln_scan: {
    title: "Autorisierte Schwachstellenprüfung (optional)",
    text: "Ausführung ausschließlich vorab freigegebener, nicht-destruktiver Prüfmuster (Nuclei) gegen von Ihnen einzeln freigegebene Systeme. Kein Brute Force, keine Exploits, keine Überlastung.",
  },
} as const;
