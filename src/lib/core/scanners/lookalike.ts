import { isValidHostname, registrableDomain } from "../domain";
import { RR } from "../net/dns";
import type { Observation } from "../risk/types";
import { mapLimit } from "./runner";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

/**
 * Erkennung nachgemachter Domains (Typosquatting / Phishing), angelehnt an die dnstwist-Methodik.
 * Rein passiv: es werden nur öffentliche DNS-Einträge FREMDER Domains abgefragt –
 * kein Kontakt zu Kundensystemen, daher auch im öffentlichen Kurzcheck zulässig.
 */
const KEYBOARD: Record<string, string> = {
  q: "wa", w: "qes", e: "wrd", r: "etf", t: "rzg", z: "tuh", u: "zij", i: "uok", o: "ipl", p: "o",
  a: "qsy", s: "awdx", d: "sefc", f: "drgv", g: "fthb", h: "gzjn", j: "hukm", k: "jil", l: "ko",
  y: "asx", x: "ysdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
};
const HOMOGLYPHS: Array<[string, string]> = [["o", "0"], ["l", "1"], ["i", "1"], ["i", "l"], ["l", "i"], ["m", "rn"], ["rn", "m"], ["w", "vv"], ["vv", "w"], ["d", "cl"], ["a", "4"], ["e", "3"], ["s", "5"], ["g", "q"]];
const TLDS = ["de", "com", "net", "eu", "org", "info", "online", "shop", "co", "at", "ch", "biz", "io", "email"];
const KEYWORDS = ["login", "rechnung", "invoice", "portal", "service", "support", "secure", "mail", "gmbh", "online", "konto", "pay"];

export interface Permutation {
  domain: string;
  technique: string;
}

export function splitDomain(apex: string): { label: string; tld: string } {
  const idx = apex.indexOf(".");
  return { label: apex.slice(0, idx), tld: apex.slice(idx + 1) };
}

/** Erzeugt Domain-Varianten, priorisiert nach Missbrauchswahrscheinlichkeit. */
export function generatePermutations(apex: string, max = 400): Permutation[] {
  const { label, tld } = splitDomain(apex);
  const out = new Map<string, string>();
  const add = (l: string, t: string, technique: string) => {
    const d = `${l}.${t}`.toLowerCase();
    if (d === apex || out.has(d) || l.length < 2 || l.startsWith("-") || l.endsWith("-") || l.includes("--")) return;
    if (!isValidHostname(d)) return;
    out.set(d, technique);
  };
  for (const t of TLDS) if (t !== tld) add(label, t, "andere Endung");
  for (const [from, to] of HOMOGLYPHS) {
    let i = label.indexOf(from);
    while (i !== -1) {
      add(label.slice(0, i) + to + label.slice(i + from.length), tld, "Verwechslungszeichen");
      i = label.indexOf(from, i + 1);
    }
  }
  for (let i = 0; i < label.length; i++) add(label.slice(0, i) + label.slice(i + 1), tld, "fehlender Buchstabe");
  for (let i = 0; i < label.length - 1; i++) add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), tld, "vertauschte Buchstaben");
  for (let i = 0; i < label.length; i++) add(label.slice(0, i + 1) + label[i] + label.slice(i + 1), tld, "doppelter Buchstabe");
  for (const k of KEYWORDS) {
    add(`${label}-${k}`, tld, "Zusatzwort");
    add(`${k}-${label}`, tld, "Zusatzwort");
  }
  for (let i = 1; i < label.length; i++) if (label[i] !== "-" && label[i - 1] !== "-") add(`${label.slice(0, i)}-${label.slice(i)}`, tld, "Bindestrich");
  if (label.includes("-")) add(label.replace(/-/g, ""), tld, "ohne Bindestrich");
  for (let i = 0; i < label.length; i++) {
    for (const c of KEYBOARD[label[i]] ?? "") add(label.slice(0, i) + c + label.slice(i + 1), tld, "Tippfehler");
  }
  return [...out.entries()].slice(0, max).map(([domain, technique]) => ({ domain, technique }));
}

export interface LookalikeHit {
  domain: string;
  technique: string;
  a: string[];
  mx: string[];
  ns: string[];
  /** Gleiche Mail-/Nameserver-Infrastruktur oder IP wie die Kundendomain → vermutlich eigene Domain */
  likelyOwned: boolean;
}

/** Maximal so viele Einzelbefunde; der Rest wird zusammengefasst, damit Kunden nicht überflutet werden. */
export const MAX_LOOKALIKE_FINDINGS = 15;

export interface LookalikeRaw {
  apex: string;
  checked: number;
  hits: LookalikeHit[];
  errors: number;
}

export class LookalikeAdapter implements ScannerAdapter<LookalikeRaw> {
  key = "lookalike";
  label = "Nachgemachte Domains (Phishing-Frühwarnung)";
  requiredScope = "passive" as const;
  requiresVerification = false;
  timeoutMs = 150_000;

  initialize(): void {}

  async checkAvailability() {
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    return standardAuthorization(this, ctx);
  }

  async execute(ctx: ScanContext): Promise<LookalikeRaw> {
    const perms = generatePermutations(ctx.apex, ctx.mode === "public_check" ? 160 : 400);
    const infra = async (d: string) => {
      const [a, mx, ns] = await Promise.all([ctx.resolver.query(d, "A"), ctx.resolver.query(d, "MX"), ctx.resolver.query(d, "NS")]);
      return {
        a: a.answers.filter((x) => x.type === RR.A).map((x) => x.data),
        mx: mx.answers.filter((x) => x.type === RR.MX).map((x) => x.data.split(" ").pop()!.replace(/\.$/, "")).filter((m) => m && m !== "."),
        ns: ns.answers.filter((x) => x.type === RR.NS).map((x) => x.data.replace(/\.$/, "")),
      };
    };
    const own = await infra(ctx.apex).catch(() => ({ a: [], mx: [], ns: [] }));
    const ownMx = new Set(own.mx.map(registrableDomain));
    const ownNs = new Set(own.ns.map(registrableDomain));
    const ownA = new Set(own.a);
    let errors = 0;
    const hits: LookalikeHit[] = [];
    await mapLimit(perms, 10, async (p) => {
      if (ctx.signal.aborted) return;
      try {
        const probe = await ctx.resolver.query(p.domain, "A");
        if (probe.status === "NXDOMAIN") return; // nicht registriert
        const { a, mx, ns } = await infra(p.domain);
        if (a.length === 0 && mx.length === 0) return; // registriert, aber inaktiv
        // Eigene Domain: gleiche Mail-Infrastruktur (nicht nur Großanbieter-Hosting), gleiche Nameserver der Firma oder gleiche IP
        const ownDomainMail = mx.some((m) => ownMx.has(registrableDomain(m)) && registrableDomain(m) === ctx.apex);
        const sharedNs = ns.length > 0 && ns.every((n) => ownNs.has(registrableDomain(n))) && [...ownNs].some((n) => n === ctx.apex);
        const sharedIp = a.some((ip) => ownA.has(ip));
        hits.push({ domain: p.domain, technique: p.technique, a: a.slice(0, 4), mx: mx.slice(0, 4), ns: ns.slice(0, 4), likelyOwned: ownDomainMail || sharedNs || sharedIp });
      } catch {
        errors++;
      }
    });
    return { apex: ctx.apex, checked: perms.length, hits, errors };
  }

  normalizeResults(raw: LookalikeRaw): AdapterOutput {
    const foreign = raw.hits.filter((h) => !h.likelyOwned);
    // Priorität: Mail-fähig > Verwechslungszeichen/Zusatzwort > Rest
    const weight = (h: LookalikeHit) => (h.mx.length ? 2 : 0) + (["Verwechslungszeichen", "Zusatzwort"].includes(h.technique) ? 1 : 0);
    const ranked = [...foreign].sort((x, y) => weight(y) - weight(x) || x.domain.localeCompare(y.domain));
    const individual = ranked.slice(0, MAX_LOOKALIKE_FINDINGS);
    const rest = ranked.slice(MAX_LOOKALIKE_FINDINGS);
    const observations: Observation[] = individual.map((h) => ({
      ruleId: "brand.lookalike_domain",
      asset: raw.apex,
      discriminator: h.domain,
      facts: { lookalike: h.domain, technique: h.technique, hasMx: h.mx.length > 0, a: h.a, mx: h.mx },
      evidence: { lookalike: h.domain, technique: h.technique, a: h.a, mx: h.mx },
    }));
    if (rest.length > 0) {
      observations.push({
        ruleId: "brand.lookalike_more",
        asset: raw.apex,
        discriminator: "summary",
        facts: { count: rest.length, domains: rest.slice(0, 50).map((h) => h.domain) },
        evidence: { domains: rest.slice(0, 50).map((h) => h.domain) },
      });
    }
    // Abdeckung nur, wenn (fast) alle Abfragen beantwortet wurden – sonst keine "Behebung" behaupten
    const reliable = raw.errors <= raw.checked * 0.05;
    return {
      status: reliable ? "ok" : "partial",
      message: reliable ? undefined : `${raw.errors} von ${raw.checked} DNS-Abfragen fehlgeschlagen`,
      observations,
      coverage: reliable ? [{ asset: raw.apex, check: "brand.lookalike" }] : [],
      discoveredAssets: [],
      targets: [raw.apex],
      data: { checked: raw.checked, registered: foreign.length, likelyOwned: raw.hits.length - foreign.length, withMail: foreign.filter((h) => h.mx.length > 0).length, top: ranked.slice(0, 10).map((h) => h.domain) },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `Domain-Ähnlichkeitsprüfung fehlgeschlagen: ${errorMessage(error)}`);
  }
}
