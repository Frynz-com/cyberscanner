/**
 * DNS-Auflösung über DNS-over-HTTPS (DoH, JSON-API).
 * Gründe: funktioniert hinter restriktiven Egress-Proxies, liefert das AD-Flag für die
 * DNSSEC-Validierung und ist unabhängig vom lokalen (ggf. manipulierbaren) Resolver.
 */

export const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, DNSKEY: 48, CAA: 257 } as const;
export type RRType = keyof typeof RR;

export type DnsStatus = "NOERROR" | "SERVFAIL" | "NXDOMAIN" | "REFUSED" | "OTHER";

export interface DnsAnswer {
  name: string;
  type: number;
  ttl: number;
  data: string;
}

export interface DnsResponse {
  status: DnsStatus;
  /** Antwort wurde vom validierenden Resolver per DNSSEC authentifiziert (AD-Flag). */
  authenticated: boolean;
  answers: DnsAnswer[];
}

export interface DnsResolver {
  query(name: string, type: RRType, opts?: { checkingDisabled?: boolean }): Promise<DnsResponse>;
}

export class DnsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsError";
  }
}

const STATUS: Record<number, DnsStatus> = { 0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED" };

export const DEFAULT_DOH_ENDPOINTS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];

export class DohResolver implements DnsResolver {
  private cache = new Map<string, { at: number; value: DnsResponse }>();

  constructor(
    private endpoints: string[] = DEFAULT_DOH_ENDPOINTS,
    private timeoutMs = 5000,
    private fetchImpl: typeof fetch = fetch,
  ) {}

  async query(name: string, type: RRType, opts: { checkingDisabled?: boolean } = {}): Promise<DnsResponse> {
    const key = `${name}|${type}|${opts.checkingDisabled ? 1 : 0}`;
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.at < 30_000) return cached.value;

    let lastError: unknown;
    for (const endpoint of this.endpoints) {
      const url = new URL(endpoint);
      url.searchParams.set("name", name);
      url.searchParams.set("type", type);
      url.searchParams.set("do", "1");
      if (opts.checkingDisabled) url.searchParams.set("cd", "1");
      try {
        const res = await this.fetchImpl(url, {
          headers: { accept: "application/dns-json" },
          signal: AbortSignal.timeout(this.timeoutMs),
          redirect: "error",
        });
        if (!res.ok) throw new DnsError(`DoH ${url.host} HTTP ${res.status}`);
        const json = (await res.json()) as {
          Status: number;
          AD?: boolean;
          Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
        };
        const value: DnsResponse = {
          status: STATUS[json.Status] ?? "OTHER",
          authenticated: Boolean(json.AD),
          answers: (json.Answer ?? []).map((a) => ({
            name: a.name.replace(/\.$/, "").toLowerCase(),
            type: a.type,
            ttl: a.TTL,
            data: a.data,
          })),
        };
        this.cache.set(key, { at: Date.now(), value });
        return value;
      } catch (err) {
        lastError = err;
      }
    }
    throw new DnsError(`DNS-Abfrage fehlgeschlagen (${name} ${type}): ${String((lastError as Error)?.message ?? lastError)}`);
  }
}

/** TXT-Daten: "\"teil1\" \"teil2\"" -> "teil1teil2" */
export function unquoteTxt(data: string): string {
  const parts = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!parts) return data;
  return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}

export async function resolveTxt(r: DnsResolver, name: string): Promise<{ status: DnsStatus; records: string[] }> {
  const res = await r.query(name, "TXT");
  return { status: res.status, records: res.answers.filter((a) => a.type === RR.TXT).map((a) => unquoteTxt(a.data)) };
}

export async function resolveAddresses(r: DnsResolver, name: string): Promise<{ v4: string[]; v6: string[]; cnames: string[]; status: DnsStatus }> {
  const [a, aaaa] = await Promise.all([r.query(name, "A"), r.query(name, "AAAA")]);
  const cnames = [...a.answers, ...aaaa.answers].filter((x) => x.type === RR.CNAME).map((x) => x.data.replace(/\.$/, "").toLowerCase());
  return {
    v4: a.answers.filter((x) => x.type === RR.A).map((x) => x.data),
    v6: aaaa.answers.filter((x) => x.type === RR.AAAA).map((x) => x.data),
    cnames: [...new Set(cnames)],
    status: a.status === "NOERROR" || aaaa.status === "NOERROR" ? "NOERROR" : a.status,
  };
}

/** Fixture-Resolver für Tests: Schlüssel "name|TYPE". */
export class StaticResolver implements DnsResolver {
  constructor(private records: Record<string, Partial<DnsResponse> & { answers?: Array<Omit<DnsAnswer, "ttl" | "name"> & { name?: string; ttl?: number }> }>) {}
  async query(name: string, type: RRType): Promise<DnsResponse> {
    const hit = this.records[`${name}|${type}`];
    if (!hit) return { status: "NXDOMAIN", authenticated: false, answers: [] };
    return {
      status: hit.status ?? "NOERROR",
      authenticated: hit.authenticated ?? false,
      answers: (hit.answers ?? []).map((a) => ({ name: a.name ?? name, ttl: a.ttl ?? 300, type: a.type, data: a.data })),
    };
  }
}
