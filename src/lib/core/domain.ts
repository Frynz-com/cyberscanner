import { domainToASCII } from "node:url";
import { isIP } from "node:net";

const HOSTNAME_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

// Nicht öffentlich auflösbare bzw. reservierte TLDs – niemals als Kundendomain akzeptieren.
const RESERVED_TLDS = new Set([
  "local", "localhost", "internal", "test", "invalid", "example", "lan", "home", "corp", "intranet", "private", "arpa", "onion",
]);

export type HostnameResult = { ok: true; hostname: string } | { ok: false; error: string };

/**
 * Normalisiert eine Benutzereingabe ("https://www.Firma.de/pfad") zu einem ASCII-Hostname ("www.firma.de").
 * Lehnt IP-Adressen, einteilige Namen und reservierte TLDs ab.
 */
export function normalizeHostname(input: string, opts: { allowDemo?: boolean; stripWww?: boolean } = {}): HostnameResult {
  let value = (input ?? "").trim().toLowerCase();
  if (!value) return { ok: false, error: "Bitte geben Sie eine Domain ein." };
  if (value.length > 300) return { ok: false, error: "Die Eingabe ist zu lang." };
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  value = value.split(/[/?#]/, 1)[0];
  if (value.includes("@")) return { ok: false, error: "Bitte geben Sie nur die Domain ein, keine E-Mail-Adresse." };
  value = value.replace(/:\d+$/, "").replace(/\.$/, "");
  if (opts.stripWww !== false) value = value.replace(/^www\./, "");
  if (isIP(value) || /^\[.*\]$/.test(value)) {
    return { ok: false, error: "Bitte geben Sie einen Domainnamen ein, keine IP-Adresse." };
  }
  const ascii = domainToASCII(value);
  if (!ascii || ascii.length > 253 || !HOSTNAME_RE.test(ascii)) {
    return { ok: false, error: "Das sieht nicht nach einer gültigen Domain aus (Beispiel: firma.de)." };
  }
  const tld = ascii.slice(ascii.lastIndexOf(".") + 1);
  if (RESERVED_TLDS.has(tld) && !(opts.allowDemo && tld === "example")) {
    return { ok: false, error: "Diese Domain-Endung ist nicht öffentlich erreichbar." };
  }
  return { ok: true, hostname: ascii };
}

/** Häufige Mehrteil-Suffixe; genügt für die Ableitung der Hauptdomain im MVP (kein PSL-Download nötig). */
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.at", "or.at", "gv.at", "co.nz", "com.br",
  "com.tr", "co.jp", "com.cn", "com.pl", "co.za", "com.mx", "com.es",
]);

/** Liefert die registrierbare Domain ("shop.firma.de" -> "firma.de"). */
export function registrableDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

/** Ist host die Domain selbst oder eine Subdomain davon? Strikt label-basiert. */
export function isWithinScope(host: string, apex: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const a = apex.toLowerCase().replace(/\.$/, "");
  return h === a || h.endsWith("." + a);
}

export function isValidHostname(host: string): boolean {
  return host.length <= 253 && HOSTNAME_RE.test(host);
}

/** DNS-Name des TXT-Eintrags für den Eigentumsnachweis: _cybersafe24-verification.<domain> */
export const VERIFICATION_PREFIX = "_cybersafe24-verification";
