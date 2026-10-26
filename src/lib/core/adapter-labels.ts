/** Anzeigenamen der Prüfmodule (Client und Worker). */
export const ADAPTER: Record<string, { label: string; description: string }> = {
  dns: { label: "DNS & E-Mail", description: "SPF, DMARC, DKIM, DNSSEC, CAA, Nameserver, verwaiste Einträge" },
  tls: { label: "TLS-Zertifikate", description: "Gültigkeit, Ablauf, Hostname, Vertrauenskette, veraltete Protokolle" },
  http_headers: { label: "Website-Konfiguration", description: "HTTPS, Weiterleitung, Sicherheitsheader, Cookies, security.txt" },
  subfinder: { label: "Subdomain-Erkennung", description: "Passive Quellen über ProjectDiscovery Subfinder" },
  ct_logs: { label: "Zertifikats-Logs", description: "Certificate Transparency (crt.sh / Cert Spotter)" },
  internetdb: { label: "Offene Dienste (Shodan)", description: "Bekannte offene Ports und CVE-Hinweise" },
  hibp: { label: "Datenlecks (HIBP)", description: "Bekannte Datenlecks mit Firmen-E-Mail-Adressen" },
  hudsonrock: { label: "Infostealer (Hudson Rock)", description: "Infizierte Geräte mit Firmen-Zugangsdaten" },
  ransomware_live: { label: "Ransomware-Leakseiten", description: "Nennung auf Erpresser-Leakseiten" },
  lookalike: { label: "Nachgemachte Domains", description: "Phishing-Frühwarnung durch ähnliche Domains" },
  nuclei: { label: "Schwachstellenprüfung", description: "Freigegebene, nicht-destruktive Prüfmuster" },
};

export const adapterName = (key: string) => ADAPTER[key]?.label ?? key;
