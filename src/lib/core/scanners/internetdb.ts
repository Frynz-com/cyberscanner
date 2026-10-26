import { isPublicIp } from "../net/ip";
import { RISKY_PORTS } from "../risk/rules";
import type { Coverage, Observation } from "../risk/types";
import { mapLimit } from "./runner";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

/**
 * Shodan InternetDB – passive Abfrage bekannter offener Ports und CVE-Hinweise pro IP.
 * Lizenz: laut https://internetdb.shodan.io/ kostenlos nur für nicht-kommerzielle Nutzung;
 * kommerzielle Nutzung erfordert eine Enterprise-Lizenz. Deshalb ist der Adapter ohne
 * ausdrückliche Lizenzbestätigung (SHODAN_INTERNETDB_LICENSE) deaktiviert.
 */
export interface InternetDbEntry {
  ip: string;
  ports: number[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
}

export interface InternetDbRaw {
  results: Array<{ ip: string; entry: InternetDbEntry | null; error?: string }>;
}

const CDN_PATTERNS = [/cloudflare/i, /akamai/i, /fastly/i, /cloudfront/i, /incapsula|imperva/i, /edgecast|edgio/i, /azureedge|azurefd/i, /sucuri/i];

export function isCdnEntry(e: InternetDbEntry): boolean {
  if (e.tags.includes("cdn")) return true;
  return [...e.cpes, ...e.hostnames].some((s) => CDN_PATTERNS.some((p) => p.test(s)));
}

export class InternetDbAdapter implements ScannerAdapter<InternetDbRaw> {
  key = "internetdb";
  label = "Shodan InternetDB (bekannte offene Dienste)";
  requiredScope = "passive" as const;
  requiresVerification = true;
  timeoutMs = 90_000;
  private license: string | undefined;
  private production = false;

  constructor(private fetchImpl: typeof fetch = fetch) {}

  initialize(env: Record<string, string | undefined>): void {
    this.license = env.SHODAN_INTERNETDB_LICENSE;
    this.production = env.NODE_ENV === "production";
  }

  async checkAvailability() {
    if (this.license === "enterprise") return { status: "available" as const };
    if (this.license === "evaluation" && !this.production)
      return { status: "available" as const, message: "Evaluationsmodus (nicht-kommerziell, nur Entwicklung)" };
    return {
      status: "license_required" as const,
      message: "Für die kommerzielle Nutzung von Shodan InternetDB ist eine Enterprise-Lizenz erforderlich (SHODAN_INTERNETDB_LICENSE=enterprise).",
    };
  }

  validateAuthorization(ctx: ScanContext) {
    return standardAuthorization(this, ctx);
  }

  async execute(ctx: ScanContext): Promise<InternetDbRaw> {
    const ips = [...new Set(ctx.ips.filter(isPublicIp))].slice(0, ctx.limits.maxHosts);
    const results = await mapLimit(ips, 2, async (ip) => {
      if (ctx.signal.aborted) return { ip, entry: null, error: "abgebrochen" };
      try {
        const res = await this.fetchImpl(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
          signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(15_000)]),
          headers: { "user-agent": "CyberSafe24-Shield/1.0" },
        });
        if (res.status === 404) return { ip, entry: { ip, ports: [], cpes: [], hostnames: [], tags: [], vulns: [] } };
        if (res.status === 429) throw new Error("Ratenlimit erreicht (HTTP 429)");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const j = (await res.json()) as Partial<InternetDbEntry>;
        return {
          ip,
          entry: { ip, ports: j.ports ?? [], cpes: j.cpes ?? [], hostnames: j.hostnames ?? [], tags: j.tags ?? [], vulns: j.vulns ?? [] },
        };
      } catch (err) {
        return { ip, entry: null, error: errorMessage(err) };
      }
    });
    return { results };
  }

  normalizeResults(raw: InternetDbRaw, ctx: ScanContext): AdapterOutput {
    const obs: Observation[] = [];
    const coverage: Coverage[] = [];
    const cdnIps: string[] = [];
    for (const r of raw.results) {
      if (!r.entry) continue;
      const e = r.entry;
      coverage.push({ asset: r.ip, check: "exposure.ports" }, { asset: r.ip, check: "exposure.cves" });
      if (isCdnEntry(e)) {
        // Ports/CVEs gehören zur CDN-Infrastruktur, nicht zum Kunden -> nicht zuordnen
        cdnIps.push(r.ip);
        continue;
      }
      const evidence = { ports: e.ports, hostnames: e.hostnames.slice(0, 10), cpes: e.cpes.slice(0, 10), source: "Shodan InternetDB" };
      for (const port of e.ports) {
        if (RISKY_PORTS[port]) obs.push({ ruleId: "exposure.risky_service", asset: r.ip, discriminator: String(port), facts: { port }, evidence });
      }
      const vulns = [...e.vulns]
        .map((cve) => ({ cve, kev: ctx.isKnownExploited?.(cve) ?? false }))
        .sort((a, b) => Number(b.kev) - Number(a.kev))
        .slice(0, 25);
      for (const v of vulns) {
        obs.push({
          ruleId: "exposure.cve_hint",
          asset: r.ip,
          discriminator: v.cve,
          facts: { cve: v.cve, kev: v.kev },
          evidence: { cpes: e.cpes.slice(0, 10), source: "Shodan InternetDB" },
          sourceRef: `https://nvd.nist.gov/vuln/detail/${v.cve}`,
        });
      }
    }
    const failed = raw.results.filter((r) => !r.entry);
    return {
      status: failed.length === 0 ? "ok" : failed.length === raw.results.length && raw.results.length > 0 ? "error" : "partial",
      message: failed.length ? `${failed.length} IP(s) nicht abfragbar: ${failed[0].error}` : undefined,
      observations: obs,
      coverage,
      discoveredAssets: [],
      targets: raw.results.map((r) => r.ip),
      data: { ipsChecked: raw.results.length, cdnIps },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `InternetDB-Abfrage fehlgeschlagen: ${errorMessage(error)}`);
  }
}
