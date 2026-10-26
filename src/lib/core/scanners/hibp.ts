import type { Observation } from "../risk/types";
import {
  emptyOutput,
  errorMessage,
  standardAuthorization,
  type AdapterOutput,
  type BreachRecordInput,
  type ScanContext,
  type ScannerAdapter,
} from "./types";

/**
 * Have I Been Pwned API v3 – Domain Search und (optional) Stealer Logs.
 * Voraussetzungen laut offizieller Dokumentation (https://haveibeenpwned.com/API/v3):
 *  - kostenpflichtiger API-Schlüssel (Header "hibp-api-key") und aussagekräftiger User-Agent
 *  - jede Domain muss im HIBP-Dashboard des Schlüsselinhabers verifiziert sein, sonst HTTP 403
 *  - Stealer-Log-Endpunkte erst ab Pro-Tarif
 *  - Lizenz der Breach-Daten: CC BY 4.0 → Quelle sichtbar mit Link nennen
 * Es werden niemals Passwörter oder Zugangsdaten abgerufen – die API liefert nur Breach-Namen.
 */
export interface HibpBreach {
  Name: string;
  Title: string;
  BreachDate: string | null;
  AddedDate: string | null;
  DataClasses: string[];
  IsSpamList?: boolean;
  IsVerified?: boolean;
  IsSensitive?: boolean;
  IsMalware?: boolean;
}

export interface HibpRaw {
  apex: string;
  subscribed: boolean;
  domainResults: Record<string, string[]> | null;
  stealer: Record<string, string[]> | null;
  stealerError?: string;
  breaches: Record<string, HibpBreach>;
  now: string;
}

const BASE = "https://haveibeenpwned.com/api/v3";
const USER_AGENT = "CyberSafe24-Shield/1.0 (Domain Breach Monitoring; +https://cybersafe24.de)";

export class HibpHttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export class HibpAdapter implements ScannerAdapter<HibpRaw> {
  key = "hibp";
  label = "Have I Been Pwned (Datenleck-Überwachung)";
  requiredScope = "passive" as const;
  requiresVerification = true;
  timeoutMs = 90_000;
  private apiKey: string | undefined;
  private stealerLogs = false;
  private breachCache: { at: number; data: Record<string, HibpBreach> } | null = null;

  constructor(private fetchImpl: typeof fetch = fetch, private sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))) {}

  initialize(env: Record<string, string | undefined>): void {
    this.apiKey = env.HIBP_API_KEY || undefined;
    this.stealerLogs = env.HIBP_STEALER_LOGS === "true";
  }

  async checkAvailability() {
    if (!this.apiKey) {
      return { status: "not_configured" as const, message: "Kein HIBP-API-Schlüssel hinterlegt (HIBP_API_KEY). Datenleck-Überwachung ist inaktiv." };
    }
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    const base = standardAuthorization(this, ctx);
    if (!base.ok) return base;
    if (ctx.mode !== "customer") return { ok: false as const, reason: "Datenleck-Abfragen nur für verifizierte Kundendomains" };
    if (!ctx.limits.breachMonitoring) return { ok: false as const, reason: "Datenleck-Überwachung ist im aktuellen Tarif nicht enthalten" };
    return base;
  }

  private async get<T>(path: string, signal: AbortSignal, auth = true): Promise<T | null> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const headers: Record<string, string> = { "user-agent": USER_AGENT };
      if (auth) headers["hibp-api-key"] = this.apiKey!;
      const res = await this.fetchImpl(`${BASE}${path}`, { headers, signal: AbortSignal.any([signal, AbortSignal.timeout(20_000)]) });
      if (res.status === 404) return null;
      if (res.status === 429) {
        const retry = Math.min(Number(res.headers.get("retry-after") ?? "2"), 10);
        await this.sleep(retry * 1000);
        continue;
      }
      if (!res.ok) throw new HibpHttpError(res.status, `HIBP ${path.split("/")[1]} HTTP ${res.status}`);
      return (await res.json()) as T;
    }
    throw new HibpHttpError(429, "HIBP-Ratenlimit wiederholt überschritten");
  }

  private async breachMetadata(signal: AbortSignal): Promise<Record<string, HibpBreach>> {
    if (this.breachCache && Date.now() - this.breachCache.at < 12 * 3600_000) return this.breachCache.data;
    const list = (await this.get<HibpBreach[]>("/breaches", signal, false)) ?? [];
    const data = Object.fromEntries(list.map((b) => [b.Name, b]));
    this.breachCache = { at: Date.now(), data };
    return data;
  }

  async execute(ctx: ScanContext): Promise<HibpRaw> {
    const apex = ctx.apex;
    const subscribed = (await this.get<Array<{ DomainName: string }>>("/subscribeddomains", ctx.signal)) ?? [];
    const isSubscribed = subscribed.some((d) => d.DomainName.toLowerCase() === apex);
    if (!isSubscribed) return { apex, subscribed: false, domainResults: null, stealer: null, breaches: {}, now: new Date().toISOString() };

    const domainResults = (await this.get<Record<string, string[]>>(`/breacheddomain/${encodeURIComponent(apex)}`, ctx.signal)) ?? {};
    const breaches = await this.breachMetadata(ctx.signal);
    let stealer: Record<string, string[]> | null = null;
    let stealerError: string | undefined;
    if (this.stealerLogs) {
      try {
        stealer = (await this.get<Record<string, string[]>>(`/stealerlogsbyemaildomain/${encodeURIComponent(apex)}`, ctx.signal)) ?? {};
      } catch (err) {
        stealerError = errorMessage(err);
      }
    }
    return { apex, subscribed: true, domainResults, stealer, stealerError, breaches, now: new Date().toISOString() };
  }

  normalizeResults(raw: HibpRaw): AdapterOutput {
    const a = raw.apex;
    if (!raw.subscribed) {
      return {
        status: "partial",
        message: "Domain ist im HIBP-Konto noch nicht verifiziert",
        observations: [{ ruleId: "breach.provider_domain_unverified", asset: a, facts: {}, evidence: {} }],
        coverage: [],
        discoveredAssets: [],
        targets: [a],
        data: { subscribed: false },
      };
    }
    const now = new Date(raw.now).getTime();
    const byBreach = new Map<string, string[]>();
    for (const [alias, names] of Object.entries(raw.domainResults ?? {})) {
      for (const name of names) {
        if (!byBreach.has(name)) byBreach.set(name, []);
        byBreach.get(name)!.push(alias);
      }
    }
    const observations: Observation[] = [];
    const breachRecords: BreachRecordInput[] = [];
    for (const [name, aliases] of byBreach) {
      const meta = raw.breaches[name];
      const breachDate = meta?.BreachDate ?? null;
      const added = meta?.AddedDate ?? null;
      const ageDays = breachDate ? Math.floor((now - new Date(breachDate).getTime()) / 86_400_000) : 9999;
      const addedDays = added ? Math.floor((now - new Date(added).getTime()) / 86_400_000) : 9999;
      observations.push({
        ruleId: "breach.accounts_exposed",
        asset: a,
        discriminator: name,
        facts: {
          accountCount: aliases.length,
          breachKey: name,
          breachTitle: meta?.Title ?? name,
          breachDate: breachDate ?? "",
          addedDate: added ? added.slice(0, 10) : "",
          dataClasses: meta?.DataClasses ?? [],
          breachAgeDays: ageDays,
          isSpamList: Boolean(meta?.IsSpamList),
          recentBreach: addedDays <= 90,
        },
        evidence: { breach: name, accountCount: aliases.length, dataClasses: meta?.DataClasses ?? [], source: "Have I Been Pwned (CC BY 4.0)" },
        sourceRef: `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(name)}`,
      });
      for (const alias of aliases) {
        breachRecords.push({
          provider: "hibp",
          account: `${alias}@${a}`,
          breachKey: name,
          breachTitle: meta?.Title ?? name,
          breachDate,
          breachAddedAt: added,
          dataClasses: meta?.DataClasses ?? [],
          isStealerLog: false,
          isSynthetic: false,
          findingRuleId: "breach.accounts_exposed",
          findingDiscriminator: name,
        });
      }
    }
    const coverage = [{ asset: a, check: "breach.domain" }];
    if (raw.stealer) {
      coverage.push({ asset: a, check: "breach.stealer" });
      const aliases = Object.keys(raw.stealer);
      if (aliases.length > 0) {
        const websites = [...new Set(Object.values(raw.stealer).flat())].slice(0, 50);
        observations.push({ ruleId: "breach.stealer_log", asset: a, discriminator: "stealer", facts: { accountCount: aliases.length }, evidence: { websites, source: "Have I Been Pwned Stealer Logs" } });
        for (const alias of aliases) {
          breachRecords.push({
            provider: "hibp",
            account: `${alias}@${a}`,
            breachKey: "stealer-logs",
            breachTitle: "Infostealer-Logs",
            breachDate: null,
            breachAddedAt: null,
            dataClasses: ["Infostealer"],
            isStealerLog: true,
            isSynthetic: false,
            findingRuleId: "breach.stealer_log",
            findingDiscriminator: "stealer",
          });
        }
      }
    }
    return {
      status: raw.stealerError ? "partial" : "ok",
      message: raw.stealerError ? `Stealer-Logs nicht abrufbar: ${raw.stealerError}` : undefined,
      observations,
      coverage,
      discoveredAssets: [],
      targets: [a],
      data: { subscribed: true, breachCount: byBreach.size, accountCount: Object.keys(raw.domainResults ?? {}).length },
      breachRecords,
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    if (error instanceof HibpHttpError && (error.status === 401 || error.status === 403)) {
      return emptyOutput("unavailable", `HIBP verweigert den Zugriff (HTTP ${error.status}) – API-Schlüssel oder Tarif prüfen`);
    }
    return emptyOutput("error", `HIBP-Abfrage fehlgeschlagen: ${errorMessage(error)}`);
  }
}
