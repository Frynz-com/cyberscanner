import type { Observation } from "../risk/types";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

/**
 * Hudson Rock – Infostealer-Intelligence je Domain.
 * Genutzt wird der kostenlose OSINT-Endpunkt, der nur Zählwerte, Zeitpunkte, Login-URLs und
 * Passwortstärke-Statistiken liefert – keine Zugangsdaten, keine personenbezogenen Daten.
 * Kommerzielle Nutzung ist mit Hudson Rock schriftlich zu klären (HUDSONROCK_TERMS_CONFIRMED=true),
 * bis dahin ist der Adapter in Produktion deaktiviert.
 */
export interface HudsonRockResponse {
  total?: number;
  employees?: number;
  users?: number;
  third_parties?: number;
  last_employee_compromised?: string | null;
  last_user_compromised?: string | null;
  data?: { employees_urls?: Array<{ url: string; occurrence: number }>; clients_urls?: Array<{ url: string; occurrence: number }> };
  employeePasswords?: Record<string, { qty: number; perc: number } | number>;
  stealerFamilies?: Record<string, number>;
  message?: string;
}

export interface HudsonRockRaw {
  apex: string;
  response: HudsonRockResponse | null;
  now: string;
}

const ENDPOINT = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain";

export class HudsonRockAdapter implements ScannerAdapter<HudsonRockRaw> {
  key = "hudsonrock";
  label = "Infostealer-Hinweise (Hudson Rock)";
  requiredScope = "passive" as const;
  requiresVerification = true;
  timeoutMs = 45_000;
  private enabled = true;
  private production = false;
  private termsConfirmed = false;

  constructor(private fetchImpl: typeof fetch = fetch) {}

  initialize(env: Record<string, string | undefined>): void {
    this.enabled = env.HUDSONROCK_MODE !== "off";
    this.production = env.NODE_ENV === "production";
    this.termsConfirmed = env.HUDSONROCK_TERMS_CONFIRMED === "true";
  }

  async checkAvailability() {
    if (!this.enabled) return { status: "disabled" as const, message: "Hudson Rock ist deaktiviert (HUDSONROCK_MODE=off)." };
    if (this.production && !this.termsConfirmed)
      return { status: "license_required" as const, message: "Kommerzielle Nutzung mit Hudson Rock klären und HUDSONROCK_TERMS_CONFIRMED=true setzen." };
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    const base = standardAuthorization(this, ctx);
    if (!base.ok) return base;
    if (ctx.mode !== "customer") return { ok: false as const, reason: "Nur für verifizierte Kundendomains" };
    if (!ctx.limits.breachMonitoring) return { ok: false as const, reason: "Datenleck-Überwachung ist im aktuellen Tarif nicht enthalten" };
    return base;
  }

  async execute(ctx: ScanContext): Promise<HudsonRockRaw> {
    const url = `${ENDPOINT}?domain=${encodeURIComponent(ctx.apex)}`;
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await this.fetchImpl(url, { signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(20_000)]), headers: { "user-agent": "CyberSafe24-Shield/1.0", accept: "application/json" } });
      if (res.status === 404) return { apex: ctx.apex, response: null, now: new Date().toISOString() };
      if (res.status === 429 && attempt === 0) {
        await new Promise((r) => setTimeout(r, 3000));
        continue;
      }
      if (!res.ok) throw new Error(`Hudson Rock HTTP ${res.status}`);
      return { apex: ctx.apex, response: (await res.json()) as HudsonRockResponse, now: new Date().toISOString() };
    }
    throw new Error("Hudson Rock: Ratenlimit");
  }

  normalizeResults(raw: HudsonRockRaw): AdapterOutput {
    const r = raw.response;
    const now = new Date(raw.now).getTime();
    const age = (iso: string | null | undefined) => (iso ? Math.max(0, Math.floor((now - new Date(iso).getTime()) / 86_400_000)) : 9999);
    const observations: Observation[] = [];
    if (r && (r.employees ?? 0) > 0) {
      const pw = r.employeePasswords ?? {};
      const weak = ["too_weak", "weak"].reduce((s, k) => s + (typeof pw[k] === "object" ? (pw[k] as { qty: number }).qty : 0), 0);
      const totalPass = typeof pw.totalPass === "number" ? pw.totalPass : 0;
      const families = Object.entries(r.stealerFamilies ?? {}).filter(([k]) => k !== "total").sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k]) => k);
      const urls = (r.data?.employees_urls ?? []).slice(0, 10).map((u) => u.url);
      observations.push({
        ruleId: "intel.infostealer_employees",
        asset: raw.apex,
        discriminator: "employees",
        facts: {
          employees: r.employees,
          lastCompromised: r.last_employee_compromised ?? "",
          ageDays: age(r.last_employee_compromised),
          urls,
          passwordStrength: totalPass ? `${weak} von ${totalPass} schwach` : "",
          families: families.join(", "),
          recentBreach: age(r.last_employee_compromised) <= 90,
        },
        evidence: { employees: r.employees, lastCompromised: r.last_employee_compromised, urls, source: "Hudson Rock (nur Zählwerte/URLs)" },
        sourceRef: "https://www.hudsonrock.com/",
      });
    }
    if (r && (r.users ?? 0) > 0) {
      const urls = (r.data?.clients_urls ?? []).slice(0, 10).map((u) => u.url);
      observations.push({
        ruleId: "intel.infostealer_users",
        asset: raw.apex,
        discriminator: "users",
        facts: { users: r.users, lastCompromised: r.last_user_compromised ?? "", ageDays: age(r.last_user_compromised), urls },
        evidence: { users: r.users, lastCompromised: r.last_user_compromised, urls, source: "Hudson Rock (nur Zählwerte/URLs)" },
        sourceRef: "https://www.hudsonrock.com/",
      });
    }
    return {
      status: "ok",
      observations,
      coverage: [{ asset: raw.apex, check: "intel.infostealer" }],
      discoveredAssets: [],
      targets: [raw.apex],
      data: { employees: r?.employees ?? 0, users: r?.users ?? 0, thirdParties: r?.third_parties ?? 0, lastEmployee: r?.last_employee_compromised ?? null },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `Hudson Rock nicht erreichbar: ${errorMessage(error)}`);
  }
}
