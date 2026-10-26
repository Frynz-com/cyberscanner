import { isWithinScope } from "../domain";
import type { Observation } from "../risk/types";
import { safeExec, type ExecFn } from "./subfinder";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

/**
 * ProjectDiscovery Nuclei – NUR für ausdrücklich freigegebene Assets und Prüfmuster.
 * Sicherheitsleitplanken:
 *  - standardmäßig deaktiviert (NUCLEI_ENABLED=true erforderlich)
 *  - nur Hosts mit Asset-Freigabe "vuln_scan_approved" + Scope "vuln_scan" in der Autorisierung
 *  - nur Templates aus einer expliziten Allowlist (NUCLEI_TEMPLATE_IDS), destruktive Tags ausgeschlossen
 *  - kein Interactsh (keine Out-of-Band-Kommunikation), niedrige Rate- und Parallelitätslimits
 */
export const EXCLUDED_TAGS = ["dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force", "default-login", "rce", "sqli", "xss", "lfi", "ssrf", "injection", "oast", "headless", "code"];

export interface NucleiRaw {
  lines: string[];
  hosts: string[];
}

export function parseNucleiOutput(lines: string[], allowedHosts: string[], apex: string): Observation[] {
  const out: Observation[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    let j: { "template-id"?: string; info?: { name?: string; severity?: string; description?: string; remediation?: string }; "matched-at"?: string; host?: string };
    try {
      j = JSON.parse(line);
    } catch {
      continue;
    }
    const templateId = j["template-id"];
    if (!templateId) continue;
    let host = "";
    try {
      host = new URL(j["matched-at"] ?? j.host ?? "").hostname;
    } catch {
      host = (j.host ?? "").replace(/:\d+$/, "");
    }
    if (!allowedHosts.includes(host) || !isWithinScope(host, apex)) continue;
    out.push({
      ruleId: "vuln.nuclei",
      asset: host,
      discriminator: templateId,
      facts: {
        templateId,
        name: j.info?.name ?? templateId,
        severity: (j.info?.severity ?? "info").toLowerCase(),
        description: (j.info?.description ?? "").slice(0, 1000),
        remediation: (j.info?.remediation ?? "").slice(0, 1000),
        matchedAt: (j["matched-at"] ?? "").slice(0, 300),
      },
      evidence: { templateId, matchedAt: (j["matched-at"] ?? "").slice(0, 300) },
    });
  }
  return out;
}

export class NucleiAdapter implements ScannerAdapter<NucleiRaw> {
  key = "nuclei";
  label = "Autorisierte Schwachstellenprüfung (Nuclei)";
  requiredScope = "vuln_scan" as const;
  requiresVerification = true;
  timeoutMs = 15 * 60_000;
  private enabled = false;
  private bin = "nuclei";
  private templateIds: string[] = [];

  constructor(private exec: ExecFn = safeExec) {}

  initialize(env: Record<string, string | undefined>): void {
    this.enabled = env.NUCLEI_ENABLED === "true";
    this.bin = env.NUCLEI_BIN || "nuclei";
    this.templateIds = (env.NUCLEI_TEMPLATE_IDS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => /^[a-z0-9][a-z0-9_-]{1,100}$/i.test(s));
  }

  async checkAvailability() {
    if (!this.enabled) return { status: "disabled" as const, message: "Nuclei ist deaktiviert (NUCLEI_ENABLED)." };
    if (this.templateIds.length === 0) return { status: "not_configured" as const, message: "Keine freigegebenen Templates (NUCLEI_TEMPLATE_IDS)." };
    try {
      await this.exec(this.bin, ["-version"], { timeoutMs: 15_000, signal: AbortSignal.timeout(15_000) });
      return { status: "available" as const };
    } catch (err) {
      return { status: "unavailable" as const, message: `Nuclei nicht ausführbar: ${errorMessage(err)}` };
    }
  }

  validateAuthorization(ctx: ScanContext) {
    const base = standardAuthorization(this, ctx);
    if (!base.ok) return base;
    if (ctx.mode !== "customer") return { ok: false as const, reason: "Nur für Kundendomains" };
    if (!ctx.limits.vulnScan) return { ok: false as const, reason: "Im aktuellen Tarif nicht enthalten" };
    if (ctx.vulnScanHosts.length === 0) return { ok: false as const, reason: "Keine Assets für aktive Prüfung freigegeben" };
    if (ctx.vulnScanHosts.some((h) => !isWithinScope(h, ctx.apex))) return { ok: false as const, reason: "Freigegebene Assets außerhalb der Domain" };
    return base;
  }

  async execute(ctx: ScanContext): Promise<NucleiRaw> {
    const hosts = ctx.vulnScanHosts.slice(0, 20);
    const args = ["-jsonl", "-silent", "-nc", "-duc", "-ni", "-rl", "10", "-c", "5", "-timeout", "10", "-retries", "1", "-etags", EXCLUDED_TAGS.join(","), "-id", this.templateIds.join(",")];
    for (const h of hosts) args.push("-u", `https://${h}`);
    const { stdout } = await this.exec(this.bin, args, { timeoutMs: this.timeoutMs - 10_000, signal: ctx.signal });
    return { lines: stdout.split("\n"), hosts };
  }

  normalizeResults(raw: NucleiRaw, ctx: ScanContext): AdapterOutput {
    const observations = parseNucleiOutput(raw.lines, raw.hosts, ctx.apex);
    return {
      status: "ok",
      observations,
      coverage: raw.hosts.map((h) => ({ asset: h, check: "vuln.nuclei" })),
      discoveredAssets: [],
      targets: raw.hosts,
      data: { templates: this.templateIds.length, matches: observations.length },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `Nuclei fehlgeschlagen: ${errorMessage(error)}`);
  }
}
