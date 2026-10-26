import { isValidHostname, isWithinScope } from "../domain";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

/**
 * Passive Asset Discovery über Certificate-Transparency-Logs.
 * Primär: crt.sh (kostenlos, ohne Schlüssel). Fallback: SSLMate Cert Spotter API
 * (kostenloses Kontingent ohne Schlüssel, optional CERTSPOTTER_API_KEY).
 */
export interface CtRaw {
  apex: string;
  names: Array<{ name: string; source: string }>;
  sourceUsed: string;
  errors: string[];
}

export function extractCtNames(names: string[], apex: string): string[] {
  const out = new Set<string>();
  for (const raw of names) {
    for (const part of raw.split(/\s+/)) {
      const host = part.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (host && host !== apex && isValidHostname(host) && isWithinScope(host, apex)) out.add(host);
    }
  }
  return [...out];
}

export class CtLogsAdapter implements ScannerAdapter<CtRaw> {
  key = "ct_logs";
  label = "Certificate Transparency (crt.sh / Cert Spotter)";
  requiredScope = "passive" as const;
  requiresVerification = true;
  timeoutMs = 90_000;
  private certspotterKey: string | undefined;

  constructor(private fetchImpl: typeof fetch = fetch) {}

  initialize(env: Record<string, string | undefined>): void {
    this.certspotterKey = env.CERTSPOTTER_API_KEY || undefined;
  }

  async checkAvailability() {
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    return standardAuthorization(this, ctx);
  }

  async execute(ctx: ScanContext): Promise<CtRaw> {
    const errors: string[] = [];
    try {
      const url = `https://crt.sh/?q=${encodeURIComponent(`%.${ctx.apex}`)}&output=json&exclude=expired`;
      const res = await this.fetchImpl(url, { signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(40_000)]), headers: { "user-agent": "CyberSafe24-Shield/1.0" } });
      if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
      const json = (await res.json()) as Array<{ name_value?: string; common_name?: string }>;
      const names = json.flatMap((e) => [e.name_value ?? "", e.common_name ?? ""]);
      return { apex: ctx.apex, names: names.map((n) => ({ name: n, source: "crt.sh" })), sourceUsed: "crt.sh", errors };
    } catch (err) {
      errors.push(errorMessage(err));
    }
    const url = new URL("https://api.certspotter.com/v1/issuances");
    url.searchParams.set("domain", ctx.apex);
    url.searchParams.set("include_subdomains", "true");
    url.searchParams.append("expand", "dns_names");
    const headers: Record<string, string> = { "user-agent": "CyberSafe24-Shield/1.0" };
    if (this.certspotterKey) headers.authorization = `Bearer ${this.certspotterKey}`;
    const res = await this.fetchImpl(url, { signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(30_000)]), headers });
    if (!res.ok) throw new Error(`crt.sh: ${errors.join("; ")}; Cert Spotter HTTP ${res.status}`);
    const json = (await res.json()) as Array<{ dns_names?: string[] }>;
    return { apex: ctx.apex, names: json.flatMap((e) => (e.dns_names ?? []).map((n) => ({ name: n, source: "certspotter" }))), sourceUsed: "certspotter", errors };
  }

  normalizeResults(raw: CtRaw): AdapterOutput {
    const hosts = extractCtNames(raw.names.map((n) => n.name), raw.apex);
    return {
      status: raw.errors.length > 0 ? "partial" : "ok",
      message: raw.errors.length > 0 ? `Fallback auf ${raw.sourceUsed}: ${raw.errors.join("; ")}` : undefined,
      observations: [],
      coverage: [],
      discoveredAssets: hosts.map((h) => ({ kind: "subdomain" as const, value: h, source: `ct:${raw.sourceUsed}` })),
      targets: [raw.apex],
      data: { subdomainCount: hosts.length, source: raw.sourceUsed },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `CT-Log-Abfrage fehlgeschlagen: ${errorMessage(error)}`);
  }
}
