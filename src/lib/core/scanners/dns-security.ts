import { RR, resolveTxt, type DnsResolver, type DnsStatus } from "../net/dns";
import type { Coverage, Observation } from "../risk/types";
import { mapLimit } from "./runner";
import {
  emptyOutput,
  errorMessage,
  standardAuthorization,
  type AdapterOutput,
  type ScanContext,
  type ScannerAdapter,
} from "./types";

export const DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "zoho", "mxvault"];

export interface SpfAnalysis {
  records: string[];
  record: string | null;
  allQualifier: "+" | "-" | "~" | "?" | null;
  lookups: number;
}

export interface DnsRaw {
  apex: string;
  mx: string[];
  ns: string[];
  spf: SpfAnalysis;
  dmarc: { records: string[]; tags: Record<string, string> | null; status: DnsStatus };
  dkim: { found: string[]; tried: string[] };
  dnssec: { hasDs: boolean; validated: boolean; broken: boolean };
  caa: string[];
  dangling: Array<{ host: string; target: string }>;
  checkedSubdomains: string[];
  /** Abfragen, die keine verwertbare Antwort lieferten (z. B. SERVFAIL) */
  failedChecks: string[];
}

/** Zählt DNS-Lookup-Mechanismen gemäß RFC 7208 §4.6.4 (rekursiv über include/redirect). */
export async function countSpfLookups(resolver: DnsResolver, record: string, depth = 0, budget = { queries: 0 }): Promise<number> {
  if (depth > 10 || budget.queries > 30) return 0;
  let count = 0;
  const terms = record.split(/\s+/).slice(1);
  for (const raw of terms) {
    const term = raw.replace(/^[+\-~?]/, "").toLowerCase();
    const include = term.match(/^include:(.+)$/);
    const redirect = term.match(/^redirect=(.+)$/);
    if (include || redirect) {
      count += 1;
      const target = (include ?? redirect)![1];
      if (target.includes("%")) continue; // Makros nicht auflösen
      budget.queries++;
      try {
        const { records } = await resolveTxt(resolver, target);
        const nested = records.find((r) => /^v=spf1(\s|$)/i.test(r));
        if (nested) count += await countSpfLookups(resolver, nested, depth + 1, budget);
      } catch {
        // Fehler einzelner Includes zählen nicht zusätzlich
      }
    } else if (/^(a|mx|ptr|exists)([:/]|$)/.test(term)) {
      count += 1;
    }
  }
  return count;
}

export function parseDmarc(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(";")) {
    const [k, ...v] = part.split("=");
    if (k && v.length) tags[k.trim().toLowerCase()] = v.join("=").trim();
  }
  return tags;
}

export class DnsSecurityAdapter implements ScannerAdapter<DnsRaw> {
  key = "dns";
  label = "DNS- und E-Mail-Sicherheit";
  requiredScope = "passive" as const;
  requiresVerification = false;
  timeoutMs = 60_000;

  initialize(): void {}

  async checkAvailability() {
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    return standardAuthorization(this, ctx);
  }

  async execute(ctx: ScanContext): Promise<DnsRaw> {
    const r = ctx.resolver;
    const apex = ctx.apex;
    const [mxRes, nsRes, txt, dmarcTxt, dsRes, caaRes, soaRes] = await Promise.all([
      r.query(apex, "MX"),
      r.query(apex, "NS"),
      resolveTxt(r, apex),
      resolveTxt(r, `_dmarc.${apex}`),
      r.query(apex, "DS"),
      r.query(apex, "CAA"),
      r.query(apex, "SOA"),
    ]);

    const spfRecords = txt.records.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    const spfRecord = spfRecords.length === 1 ? spfRecords[0].trim() : null;
    let allQualifier: SpfAnalysis["allQualifier"] = null;
    if (spfRecord) {
      const m = spfRecord.match(/(?:^|\s)([+\-~?]?)all(?:\s|$)/i);
      if (m) allQualifier = ((m[1] || "+") as SpfAnalysis["allQualifier"]);
    }
    const lookups = spfRecord ? await countSpfLookups(r, spfRecord) : 0;

    const dmarcRecords = dmarcTxt.records.filter((t) => /^v=DMARC1/i.test(t.trim()));
    const mx = mxRes.answers.filter((a) => a.type === RR.MX).map((a) => a.data);

    // DKIM nur sinnvoll, wenn die Domain E-Mail nutzt
    const found: string[] = [];
    if (mx.length > 0 || spfRecord) {
      await mapLimit(DKIM_SELECTORS, 4, async (sel) => {
        const res = await r.query(`${sel}._domainkey.${apex}`, "TXT").catch(() => null);
        if (res && res.status === "NOERROR" && res.answers.some((a) => a.type === RR.TXT || a.type === RR.CNAME)) found.push(sel);
      });
    }

    // DNSSEC: SERVFAIL mit Validierung, aber Erfolg ohne Validierung (CD) => kaputte Signatur
    let broken = false;
    if (soaRes.status === "SERVFAIL") {
      const cd = await r.query(apex, "SOA", { checkingDisabled: true }).catch(() => null);
      broken = cd?.status === "NOERROR";
    }
    const hasDs = dsRes.answers.some((a) => a.type === RR.DS);

    const subdomains = ctx.hosts.filter((h) => h !== apex);
    const dangling: DnsRaw["dangling"] = [];
    const checkedSubdomains: string[] = [];
    await mapLimit(subdomains.slice(0, ctx.limits.maxHosts), 5, async (host) => {
      const res = await r.query(host, "A").catch(() => null);
      if (!res) return;
      checkedSubdomains.push(host);
      const cnames = res.answers.filter((a) => a.type === RR.CNAME);
      if (res.status === "NXDOMAIN" && cnames.length > 0) {
        dangling.push({ host, target: cnames[cnames.length - 1].data.replace(/\.$/, "") });
      }
    });

    const bad = (s: DnsStatus) => s !== "NOERROR" && s !== "NXDOMAIN";
    const failedChecks: string[] = [];
    if (bad(txt.status)) failedChecks.push("email.spf");
    if (bad(dmarcTxt.status)) failedChecks.push("email.dmarc");
    if (bad(caaRes.status)) failedChecks.push("dns.caa");
    if (bad(nsRes.status)) failedChecks.push("dns.ns");
    if (bad(mxRes.status)) failedChecks.push("email.dkim");
    if (bad(dsRes.status) && !broken) failedChecks.push("dns.dnssec");

    return {
      apex,
      failedChecks,
      mx,
      ns: nsRes.answers.filter((a) => a.type === RR.NS).map((a) => a.data.replace(/\.$/, "")),
      spf: { records: spfRecords, record: spfRecord, allQualifier, lookups },
      dmarc: { records: dmarcRecords, tags: dmarcRecords.length === 1 ? parseDmarc(dmarcRecords[0]) : null, status: dmarcTxt.status },
      dkim: { found, tried: DKIM_SELECTORS },
      dnssec: { hasDs, validated: soaRes.authenticated, broken },
      caa: caaRes.answers.filter((a) => a.type === RR.CAA).map((a) => a.data),
      dangling,
      checkedSubdomains,
    };
  }

  normalizeResults(raw: DnsRaw): AdapterOutput {
    const a = raw.apex;
    const obs: Observation[] = [];
    const hasMx = raw.mx.length > 0;
    const failed = new Set(raw.failedChecks);
    const coverage: Coverage[] = ["email.spf", "email.dmarc", "dns.dnssec", "dns.caa", "dns.ns"]
      .filter((check) => !failed.has(check))
      .map((check) => ({ asset: a, check }));
    if (raw.dnssec.broken) {
      // Bei kaputtem DNSSEC sind alle weiteren Antworten unzuverlässig
      return {
        status: "partial",
        observations: [{ ruleId: "dns.dnssec.broken", asset: a, facts: {}, evidence: {} }],
        coverage: [{ asset: a, check: "dns.dnssec" }],
        discoveredAssets: [],
        targets: [a],
        message: "DNSSEC-Validierung schlägt fehl – weitere DNS-Prüfungen nicht aussagekräftig",
        data: { dnssec: "broken" },
      };
    }

    // SPF
    if (failed.has("email.spf")) {
      // nicht auswertbar
    } else if (raw.spf.records.length === 0) obs.push({ ruleId: "email.spf.missing", asset: a, facts: { hasMx }, evidence: {} });
    else if (raw.spf.records.length > 1)
      obs.push({ ruleId: "email.spf.multiple", asset: a, facts: { count: raw.spf.records.length }, evidence: { records: raw.spf.records } });
    else {
      const record = raw.spf.record!;
      if (raw.spf.allQualifier === "+" || raw.spf.allQualifier === "?")
        obs.push({ ruleId: "email.spf.permissive_all", asset: a, facts: { qualifier: raw.spf.allQualifier, record }, evidence: { record } });
      else if (raw.spf.allQualifier === null && !/redirect=/i.test(record))
        obs.push({ ruleId: "email.spf.no_all", asset: a, facts: { record }, evidence: { record } });
      if (raw.spf.lookups > 10)
        obs.push({ ruleId: "email.spf.too_many_lookups", asset: a, facts: { lookups: raw.spf.lookups, record }, evidence: { record } });
    }

    // DMARC
    if (failed.has("email.dmarc")) {
      // nicht auswertbar
    } else if (raw.dmarc.records.length === 0) obs.push({ ruleId: "email.dmarc.missing", asset: a, facts: { hasMx }, evidence: {} });
    else if (raw.dmarc.records.length > 1) obs.push({ ruleId: "email.dmarc.multiple", asset: a, facts: {}, evidence: { records: raw.dmarc.records } });
    else if (raw.dmarc.tags) {
      const record = raw.dmarc.records[0];
      const p = (raw.dmarc.tags.p ?? "").toLowerCase();
      if (p === "none" || p === "") obs.push({ ruleId: "email.dmarc.policy_none", asset: a, facts: { record }, evidence: { record } });
      const pct = raw.dmarc.tags.pct ? Number(raw.dmarc.tags.pct) : 100;
      if (pct < 100 && p !== "none") obs.push({ ruleId: "email.dmarc.partial", asset: a, facts: { pct, record }, evidence: { record } });
      if (!raw.dmarc.tags.rua) obs.push({ ruleId: "email.dmarc.no_reporting", asset: a, facts: { record }, evidence: { record } });
    }

    // DKIM (nur prüfbar mit Selektor)
    if ((hasMx || raw.spf.record) && !failed.has("email.dkim")) {
      coverage.push({ asset: a, check: "email.dkim" });
      if (raw.dkim.found.length === 0)
        obs.push({ ruleId: "email.dkim.not_checkable", asset: a, facts: {}, evidence: { selectorsTried: raw.dkim.tried } });
    }

    // DNSSEC
    if (!failed.has("dns.dnssec") && !raw.dnssec.hasDs) obs.push({ ruleId: "dns.dnssec.unsigned", asset: a, facts: {}, evidence: {} });

    if (!failed.has("dns.caa") && raw.caa.length === 0) obs.push({ ruleId: "dns.caa.missing", asset: a, facts: {}, evidence: {} });
    if (!failed.has("dns.ns") && raw.ns.length === 1) obs.push({ ruleId: "dns.ns.single", asset: a, facts: {}, evidence: { ns: raw.ns } });

    for (const host of raw.checkedSubdomains) coverage.push({ asset: host, check: "dns.dangling" });
    for (const d of raw.dangling)
      obs.push({ ruleId: "dns.dangling_cname", asset: d.host, discriminator: d.target, facts: { target: d.target }, evidence: { target: d.target } });

    return {
      status: failed.size > 0 ? "partial" : "ok",
      message: failed.size > 0 ? `Nicht auswertbar: ${[...failed].join(", ")}` : undefined,
      observations: obs,
      coverage,
      discoveredAssets: [],
      targets: [a, ...raw.checkedSubdomains],
      data: {
        mx: raw.mx,
        ns: raw.ns,
        spf: raw.spf.record,
        spfLookups: raw.spf.lookups,
        dmarc: raw.dmarc.records[0] ?? null,
        dmarcPolicy: raw.dmarc.tags?.p ?? null,
        dkimSelectorsFound: raw.dkim.found,
        dnssec: raw.dnssec.broken ? "broken" : raw.dnssec.hasDs ? (raw.dnssec.validated ? "signed_validated" : "signed") : "unsigned",
        caa: raw.caa,
      },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `DNS-Prüfung fehlgeschlagen: ${errorMessage(error)}`);
  }
}
