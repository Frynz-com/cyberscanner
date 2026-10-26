import { CtLogsAdapter } from "./ct-logs";
import { DnsSecurityAdapter } from "./dns-security";
import { HibpAdapter } from "./hibp";
import { HttpHeadersAdapter } from "./http-headers";
import { InternetDbAdapter } from "./internetdb";
import { NucleiAdapter } from "./nuclei";
import { SubfinderAdapter } from "./subfinder";
import { TlsAdapter } from "./tls";
import type { ScannerAdapter } from "./types";

/** Phase 1: Asset-Erkennung (liefert Hosts für Phase 2) */
export function discoveryAdapters(env: Record<string, string | undefined>): ScannerAdapter[] {
  return init([new SubfinderAdapter(), new CtLogsAdapter()], env);
}

/** Phase 2: Konfigurations- und Intel-Prüfungen auf dem Asset-Bestand */
export function assessmentAdapters(env: Record<string, string | undefined>): ScannerAdapter[] {
  return init([new DnsSecurityAdapter(), new TlsAdapter(), new HttpHeadersAdapter(), new InternetDbAdapter(), new HibpAdapter(), new NucleiAdapter()], env);
}

/** Öffentlicher Kurzcheck: nur schonende Konfigurationsprüfungen der Hauptdomain */
export function publicCheckAdapters(env: Record<string, string | undefined>): ScannerAdapter[] {
  return init([new DnsSecurityAdapter(), new TlsAdapter(), new HttpHeadersAdapter()], env);
}

export function allAdapters(env: Record<string, string | undefined>): ScannerAdapter[] {
  return [...discoveryAdapters(env), ...assessmentAdapters(env)];
}

function init(adapters: ScannerAdapter[], env: Record<string, string | undefined>) {
  for (const a of adapters) a.initialize(env);
  return adapters;
}

/**
 * Weitere lizenzierte Breach-/Threat-Intel-Anbieter (z. B. SpyCloud, Hudson Rock) werden als
 * ScannerAdapter mit requiredScope "passive" und eigener Lizenzprüfung in checkAvailability()
 * implementiert und hier registriert. Ohne Vertrag bleiben sie bewusst unimplementiert.
 */
export const PLANNED_PROVIDERS = [
  { key: "spycloud", label: "SpyCloud", status: "not_contracted" },
  { key: "hudson_rock", label: "Hudson Rock", status: "not_contracted" },
] as const;
