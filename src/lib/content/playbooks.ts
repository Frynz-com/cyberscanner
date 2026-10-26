/**
 * Notfall-Playbooks (digitale Erstunterstützung). Inhalte orientieren sich an allgemein
 * anerkannten Empfehlungen (u. a. BSI, Polizei). Sie ersetzen keine professionelle Incident Response.
 */
export type IncidentType = "account_compromise" | "ransomware" | "phishing" | "data_exfiltration" | "suspicious_activity" | "other";

export interface Playbook {
  type: IncidentType;
  title: string;
  short: string;
  defaultPriority: "p1" | "p2" | "p3";
  immediate: string[];
  avoid: string[];
  document: string[];
  dataProtectionHint: boolean;
}

export const PLAYBOOKS: Record<IncidentType, Playbook> = {
  account_compromise: {
    type: "account_compromise",
    title: "E-Mail-Konto möglicherweise kompromittiert",
    short: "Ungewöhnliche Anmeldungen, versendete E-Mails, die niemand geschrieben hat, oder neue Weiterleitungsregeln.",
    defaultPriority: "p2",
    immediate: [
      "Passwort des betroffenen Kontos sofort von einem sauberen Gerät aus ändern.",
      "Alle aktiven Sitzungen des Kontos abmelden (z. B. in Microsoft 365 / Google Workspace „Von allen Geräten abmelden“).",
      "Mehr-Faktor-Anmeldung (MFA) aktivieren bzw. hinterlegte Faktoren auf Fremdeinträge prüfen.",
      "Postfachregeln und Weiterleitungen auf unbekannte Einträge prüfen und entfernen.",
      "Kontakte warnen, falls Phishing- oder Zahlungsaufforderungen aus dem Konto versendet wurden.",
      "IT-Dienstleister informieren und Anmeldeprotokolle (Sign-in-Logs) sichern lassen.",
    ],
    avoid: ["Das Konto nicht einfach löschen – Protokolle werden für die Aufklärung benötigt.", "Keine Zahlungsänderungen ausführen, die per E-Mail angefordert wurden, ohne telefonische Rückbestätigung."],
    document: ["Zeitpunkt der ersten Auffälligkeit", "Betroffenes Konto", "Verdächtige E-Mails (als Datei/Anhang sichern)", "Bereits ergriffene Maßnahmen"],
    dataProtectionHint: true,
  },
  ransomware: {
    type: "ransomware",
    title: "Verdacht auf Ransomware",
    short: "Dateien sind verschlüsselt oder umbenannt, Erpressernachricht auf dem Bildschirm.",
    defaultPriority: "p1",
    immediate: [
      "Betroffene Geräte vom Netzwerk trennen (Netzwerkkabel ziehen, WLAN deaktivieren) – Geräte aber NICHT ausschalten.",
      "Weitere Ausbreitung verhindern: verbundene Netzlaufwerke trennen, Fernzugänge (VPN/RDP) sperren lassen.",
      "Sofort IT-Dienstleister bzw. Incident-Response-Experten hinzuziehen.",
      "Backups schützen: Backup-Systeme vom Netz trennen und Integrität prüfen lassen.",
      "Anzeige bei der Zentralen Ansprechstelle Cybercrime (ZAC) Ihrer Landespolizei erstatten.",
      "Geschäftsleitung informieren und Notfallkommunikation (Telefon statt E-Mail) organisieren.",
    ],
    avoid: ["Kein Lösegeld zahlen, ohne Beratung durch Experten und Behörden.", "Geräte nicht neu installieren oder ausschalten – Spuren gehen verloren.", "Keine Kommunikation mit den Tätern ohne fachliche Begleitung."],
    document: ["Foto der Erpressernachricht", "Betroffene Systeme und Laufwerke", "Zeitpunkt der Entdeckung", "Dateiendungen verschlüsselter Dateien"],
    dataProtectionHint: true,
  },
  phishing: {
    type: "phishing",
    title: "Phishing-Vorfall",
    short: "Jemand hat auf einen Link geklickt, Zugangsdaten eingegeben oder einen Anhang geöffnet.",
    defaultPriority: "p2",
    immediate: [
      "Wurden Zugangsdaten eingegeben: Passwort sofort ändern und Sitzungen abmelden.",
      "Wurde ein Anhang geöffnet: Gerät vom Netzwerk trennen und IT-Dienstleister informieren.",
      "Die Phishing-E-Mail nicht löschen, sondern als Datei sichern (für die Analyse).",
      "Kolleginnen und Kollegen warnen, falls ähnliche E-Mails eingegangen sind.",
      "Absender/Domain im E-Mail-System sperren lassen.",
    ],
    avoid: ["Die verdächtige E-Mail nicht an viele Personen weiterleiten.", "Keine weiteren Links in der E-Mail anklicken."],
    document: ["Phishing-E-Mail (.eml) als Upload", "Wer hat was angeklickt/eingegeben?", "Uhrzeit"],
    dataProtectionHint: false,
  },
  data_exfiltration: {
    type: "data_exfiltration",
    title: "Möglicher Datenabfluss",
    short: "Hinweise, dass vertrauliche oder personenbezogene Daten in fremde Hände gelangt sind.",
    defaultPriority: "p1",
    immediate: [
      "Quelle des Abflusses eingrenzen (welches System, welches Konto, welche Daten?).",
      "Betroffene Zugänge sperren bzw. Passwörter ändern.",
      "Beweise sichern (Protokolle, Hinweise, Erpressungsschreiben).",
      "Datenschutzbeauftragte(n) einbeziehen: Bei personenbezogenen Daten besteht ggf. eine Meldepflicht binnen 72 Stunden (Art. 33 DSGVO).",
      "IT-Dienstleister bzw. Forensik-Experten hinzuziehen.",
    ],
    avoid: ["Keine öffentlichen Stellungnahmen ohne Abstimmung.", "Protokolle nicht löschen oder überschreiben."],
    document: ["Welche Daten sind betroffen?", "Wie wurde der Abfluss bemerkt?", "Zeitraum"],
    dataProtectionHint: true,
  },
  suspicious_activity: {
    type: "suspicious_activity",
    title: "Verdächtige Systemaktivität",
    short: "Ungewöhnliches Verhalten von Rechnern, unbekannte Programme, Warnungen des Virenschutzes.",
    defaultPriority: "p3",
    immediate: [
      "Betroffenes Gerät beobachten, Warnmeldungen fotografieren.",
      "Bei Verdacht auf Schadsoftware: Gerät vom Netzwerk trennen (nicht ausschalten).",
      "IT-Dienstleister informieren.",
    ],
    avoid: ["Keine eigenen „Reparaturversuche“ mit aus dem Internet geladenen Tools."],
    document: ["Gerät und Nutzer", "Beobachtetes Verhalten", "Zeitpunkt"],
    dataProtectionHint: false,
  },
  other: {
    type: "other",
    title: "Sonstiger Sicherheitsvorfall",
    short: "Alles andere, das sich nach einem Sicherheitsproblem anfühlt.",
    defaultPriority: "p3",
    immediate: ["Ruhe bewahren und Beobachtungen dokumentieren.", "IT-Dienstleister informieren.", "Bei akuter Gefahr oder Erpressung: Polizei verständigen."],
    avoid: ["Keine Spuren beseitigen."],
    document: ["Was ist passiert?", "Wer ist betroffen?", "Seit wann?"],
    dataProtectionHint: false,
  },
};

export const PUBLIC_CONTACTS = [
  { name: "Polizei – Zentrale Ansprechstelle Cybercrime (ZAC)", detail: "Jedes Landeskriminalamt betreibt eine ZAC für Unternehmen; Übersicht über polizei.de", url: "https://www.polizei.de/" },
  { name: "Notruf bei akuter Gefahr", detail: "110", url: "tel:110" },
  { name: "BSI – Bundesamt für Sicherheit in der Informationstechnik", detail: "Informationen und Hilfe bei IT-Sicherheitsvorfällen", url: "https://www.bsi.bund.de/" },
  { name: "Datenschutz-Aufsichtsbehörde Ihres Bundeslandes", detail: "Meldung von Datenschutzverletzungen (Art. 33 DSGVO) – Anschriften der Landesbehörden", url: "https://www.bfdi.bund.de/DE/Service/Anschriften/Laender/Laender-node.html" },
];

export function contractedExpert(env: Record<string, string | undefined> = process.env) {
  if (!env.EMERGENCY_PARTNER_NAME || !(env.EMERGENCY_PARTNER_PHONE || env.EMERGENCY_PARTNER_EMAIL)) return null;
  return { name: env.EMERGENCY_PARTNER_NAME, phone: env.EMERGENCY_PARTNER_PHONE ?? null, email: env.EMERGENCY_PARTNER_EMAIL ?? null, hours: env.EMERGENCY_PARTNER_HOURS ?? null };
}
