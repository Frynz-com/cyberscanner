import { isWithinScope } from "../domain";
import type { Observation } from "../risk/types";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

/**
 * ransomware.live – öffentliche Beobachtung von Ransomware-Leakseiten.
 * Abgleich ausschließlich über die Domain (keine unscharfe Namenssuche → keine Fehlalarme).
 */
export interface RansomwareVictim {
  victim: string;
  domain?: string | null;
  group: string;
  discovered?: string;
  attackdate?: string;
  country?: string;
  url?: string;
  description?: string;
}

export interface RansomwareRaw {
  apex: string;
  victims: RansomwareVictim[];
  now: string;
}

export function matchVictims(victims: RansomwareVictim[], apex: string): RansomwareVictim[] {
  return victims.filter((v) => {
    const d = (v.domain ?? "").toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    return d !== "" && isWithinScope(d, apex);
  });
}

export class RansomwareLiveAdapter implements ScannerAdapter<RansomwareRaw> {
  key = "ransomware_live";
  label = "Ransomware-Leakseiten (ransomware.live)";
  requiredScope = "passive" as const;
  requiresVerification = true;
  timeoutMs = 45_000;
  private enabled = true;

  constructor(private fetchImpl: typeof fetch = fetch) {}

  initialize(env: Record<string, string | undefined>): void {
    this.enabled = env.RANSOMWARE_LIVE_MODE !== "off";
  }

  async checkAvailability() {
    return this.enabled ? { status: "available" as const } : { status: "disabled" as const, message: "ransomware.live ist deaktiviert." };
  }

  validateAuthorization(ctx: ScanContext) {
    const base = standardAuthorization(this, ctx);
    if (!base.ok) return base;
    if (ctx.mode !== "customer") return { ok: false as const, reason: "Nur für verifizierte Kundendomains" };
    return base;
  }

  async execute(ctx: ScanContext): Promise<RansomwareRaw> {
    const res = await this.fetchImpl(`https://api.ransomware.live/v2/searchvictims/${encodeURIComponent(ctx.apex)}`, {
      signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(20_000)]),
      headers: { "user-agent": "CyberSafe24-Shield/1.0", accept: "application/json" },
    });
    if (res.status === 404) return { apex: ctx.apex, victims: [], now: new Date().toISOString() };
    if (!res.ok) throw new Error(`ransomware.live HTTP ${res.status}`);
    const json = (await res.json()) as unknown;
    return { apex: ctx.apex, victims: Array.isArray(json) ? (json as RansomwareVictim[]) : [], now: new Date().toISOString() };
  }

  normalizeResults(raw: RansomwareRaw): AdapterOutput {
    const now = new Date(raw.now).getTime();
    const observations: Observation[] = matchVictims(raw.victims, raw.apex).map((v) => {
      const discovered = v.discovered ?? v.attackdate ?? "";
      return {
        ruleId: "intel.ransomware_listing",
        asset: raw.apex,
        discriminator: `${v.group}:${v.victim}`.toLowerCase(),
        facts: { group: v.group, victim: v.victim, discovered, attackDate: v.attackdate ?? "", country: v.country ?? "", ageDays: discovered ? Math.floor((now - new Date(discovered).getTime()) / 86_400_000) : 9999, recentBreach: true },
        evidence: { group: v.group, victim: v.victim, discovered, source: "ransomware.live" },
        sourceRef: v.url ?? "https://www.ransomware.live/",
      };
    });
    return { status: "ok", observations, coverage: [{ asset: raw.apex, check: "intel.ransomware" }], discoveredAssets: [], targets: [raw.apex], data: { listings: observations.length } };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `ransomware.live nicht erreichbar: ${errorMessage(error)}`);
  }
}
