import type { Certainty, FindingStatus, Severity } from "@/lib/core/risk/types";

export const SEVERITY: Record<Severity, { label: string; dot: string; text: string; soft: string; order: number }> = {
  critical: { label: "Kritisch", dot: "bg-sev-critical", text: "text-sev-critical", soft: "bg-sev-critical/10 text-sev-critical ring-sev-critical/20", order: 0 },
  high: { label: "Hoch", dot: "bg-sev-high", text: "text-sev-high", soft: "bg-sev-high/10 text-sev-high ring-sev-high/25", order: 1 },
  medium: { label: "Mittel", dot: "bg-sev-medium", text: "text-[oklch(0.55_0.13_70)]", soft: "bg-sev-medium/15 text-[oklch(0.5_0.12_70)] ring-sev-medium/30", order: 2 },
  low: { label: "Niedrig", dot: "bg-sev-low", text: "text-sev-low", soft: "bg-sev-low/10 text-sev-low ring-sev-low/20", order: 3 },
  info: { label: "Info", dot: "bg-sev-info", text: "text-muted-foreground", soft: "bg-muted text-muted-foreground ring-border", order: 4 },
};

export const CERTAINTY: Record<Certainty, { label: string; hint: string }> = {
  confirmed: { label: "Bestätigter Befund", hint: "Direkt technisch festgestellt." },
  potential: { label: "Mögliches Risiko", hint: "Hinweis aus Datenquellen oder Versionsangaben – nicht selbst bestätigt." },
  informational: { label: "Informationshinweis", hint: "Kein unmittelbares Risiko, aber eine Verbesserungsmöglichkeit." },
  not_checkable: { label: "Nicht prüfbar", hint: "Konnte von außen nicht abschließend geprüft werden." },
};

export const STATUS: Record<FindingStatus, { label: string; tone: string }> = {
  new: { label: "Neu", tone: "bg-brand-soft text-brand ring-brand/20" },
  investigating: { label: "In Prüfung", tone: "bg-sev-low/10 text-sev-low ring-sev-low/20" },
  action_required: { label: "Handlungsbedarf", tone: "bg-sev-high/10 text-sev-high ring-sev-high/20" },
  resolved: { label: "Behoben", tone: "bg-ok/10 text-ok ring-ok/20" },
  accepted_risk: { label: "Risiko akzeptiert", tone: "bg-muted text-muted-foreground ring-border" },
  false_positive: { label: "Fehlalarm", tone: "bg-muted text-muted-foreground ring-border" },
};

export const CATEGORY: Record<string, string> = {
  email: "E-Mail-Sicherheit",
  dns: "DNS",
  tls: "Verschlüsselung (TLS)",
  web: "Website-Konfiguration",
  exposure: "Offene Dienste",
  vulnerability: "Schwachstellen",
  breach: "Datenlecks",
  asset: "Assets",
};

export { ADAPTER } from "@/lib/core/adapter-labels";

export const PROVIDER_STATUS: Record<string, { label: string; tone: string }> = {
  available: { label: "Aktiv", tone: "text-ok" },
  degraded: { label: "Eingeschränkt", tone: "text-sev-high" },
  unavailable: { label: "Nicht verfügbar", tone: "text-sev-critical" },
  not_configured: { label: "Nicht eingerichtet", tone: "text-muted-foreground" },
  license_required: { label: "Lizenz erforderlich", tone: "text-muted-foreground" },
  disabled: { label: "Deaktiviert", tone: "text-muted-foreground" },
  unknown: { label: "Unbekannt", tone: "text-muted-foreground" },
};

export function formatDate(iso: string | null | undefined, withTime = false): string {
  if (!iso) return "–";
  const d = new Date(iso);
  return d.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
    timeZone: "Europe/Berlin",
  });
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "nie";
  const diff = Date.now() - new Date(iso).getTime();
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat("de", { numeric: "auto" });
  const sign = diff > 0 ? -1 : 1;
  if (abs < 60_000) return "gerade eben";
  if (abs < 3600_000) return rtf.format(sign * Math.round(abs / 60_000), "minute");
  if (abs < 86_400_000) return rtf.format(sign * Math.round(abs / 3600_000), "hour");
  if (abs < 30 * 86_400_000) return rtf.format(sign * Math.round(abs / 86_400_000), "day");
  return formatDate(iso);
}

/** Zeitpunkt vor n Tagen (außerhalb von Render-Funktionen berechnet). */
export function daysAgoIso(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}
