import type { DnsResolver } from "../net/dns";
import type { Coverage, Observation } from "../risk/types";

export type ScanScope = "passive" | "config" | "vuln_scan";
export type ProviderStatus = "available" | "degraded" | "unavailable" | "not_configured" | "license_required" | "disabled";
export type AdapterRunStatus = "ok" | "partial" | "error" | "unavailable" | "skipped" | "not_authorized";

export interface Logger {
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
}

export interface ScanAuthorizationInfo {
  /** Domain-Eigentum per DNS-TXT nachgewiesen */
  domainVerified: boolean;
  /** Freigegebene Prüfarten aus der schriftlichen Scan-Autorisierung */
  scopes: ScanScope[];
  includeSubdomains: boolean;
}

export interface ScanContext {
  mode: "customer" | "public_check";
  orgId: string | null;
  domainId: string | null;
  /** Verifizierte Hauptdomain – definiert die Ziel-Allowlist */
  apex: string;
  /** Hosts, die in diesem Lauf geprüft werden dürfen (alle innerhalb von apex) */
  hosts: string[];
  /** Öffentliche IPs der Hosts (für passive Intel-Abfragen) */
  ips: string[];
  /** Für aktive Prüfungen ausdrücklich freigegebene Hosts */
  vulnScanHosts: string[];
  authorization: ScanAuthorizationInfo;
  resolver: DnsResolver;
  signal: AbortSignal;
  log: Logger;
  limits: { maxHosts: number; breachMonitoring: boolean; vulnScan: boolean };
  /** KEV-Lookup für deterministische Priorisierung */
  isKnownExploited?: (cve: string) => boolean;
}

export interface DiscoveredAsset {
  kind: "subdomain" | "ip";
  value: string;
  source: string;
}

export interface AdapterOutput {
  status: AdapterRunStatus;
  observations: Observation[];
  coverage: Coverage[];
  discoveredAssets: DiscoveredAsset[];
  targets: string[];
  message?: string;
  /** Minimierte, nicht personenbezogene Zusatzdaten (z. B. für Kurzbericht) */
  data: Record<string, unknown>;
  /** Personenbezogene Breach-Daten werden separat und verschlüsselt behandelt */
  breachRecords?: BreachRecordInput[];
}

export interface BreachRecordInput {
  provider: string;
  account: string; // nur im Speicher; wird vor dem Speichern verschlüsselt + gehasht
  breachKey: string;
  breachTitle: string;
  breachDate: string | null;
  breachAddedAt: string | null;
  dataClasses: string[];
  isStealerLog: boolean;
  isSynthetic: boolean;
  /** Fingerprint-Discriminator des zugehörigen Findings */
  findingDiscriminator: string;
  findingRuleId: string;
}

/**
 * Gemeinsame Schnittstelle aller Scanner- und Datenquellen-Adapter.
 */
export interface ScannerAdapter<Raw = unknown> {
  key: string;
  label: string;
  /** Benötigte Prüfart */
  requiredScope: ScanScope;
  /** Nur nach Domain-Verifikation zulässig */
  requiresVerification: boolean;
  /** Maximale Laufzeit */
  timeoutMs: number;
  initialize(env: Record<string, string | undefined>): void;
  checkAvailability(): Promise<{ status: ProviderStatus; message?: string }>;
  validateAuthorization(ctx: ScanContext): { ok: true } | { ok: false; reason: string };
  execute(ctx: ScanContext): Promise<Raw>;
  normalizeResults(raw: Raw, ctx: ScanContext): AdapterOutput;
  reportErrors(error: unknown, ctx: ScanContext): AdapterOutput;
}

export function emptyOutput(status: AdapterRunStatus, message?: string): AdapterOutput {
  return { status, observations: [], coverage: [], discoveredAssets: [], targets: [], message, data: {} };
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message.slice(0, 500);
  return String(err).slice(0, 500);
}

/** Standard-Autorisierungsprüfung, die alle Adapter verwenden. */
export function standardAuthorization(
  adapter: Pick<ScannerAdapter, "requiredScope" | "requiresVerification">,
  ctx: ScanContext,
): { ok: true } | { ok: false; reason: string } {
  if (adapter.requiresVerification && !ctx.authorization.domainVerified) {
    return { ok: false, reason: "Domain ist nicht verifiziert" };
  }
  if (ctx.mode === "customer" && !ctx.authorization.scopes.includes(adapter.requiredScope)) {
    return { ok: false, reason: `Prüfart „${adapter.requiredScope}“ ist nicht freigegeben` };
  }
  if (ctx.mode === "public_check" && adapter.requiredScope === "vuln_scan") {
    return { ok: false, reason: "Aktive Prüfungen sind im öffentlichen Kurzcheck nicht zulässig" };
  }
  return { ok: true };
}
