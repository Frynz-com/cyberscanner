import { randomBytes } from "node:crypto";
import { RR, type DnsResolver } from "./net/dns";
import { mapLimit } from "./scanners/runner";
import type { DiscoveredAsset } from "./scanners/types";

export const MAX_DISCOVERY_CANDIDATES = 2000;

export interface ValidatedSubdomain {
  host: string;
  sources: string[];
  /** CNAME zeigt auf nicht existierenden Namen (für Takeover-Prüfung relevant) */
  dangling: boolean;
}

/** Prüft, ob die Zone Wildcard-Einträge hat (zufälliger Name löst auf). */
export async function detectWildcard(resolver: DnsResolver, apex: string): Promise<Set<string> | null> {
  const probe = `cs24-wc-${randomBytes(6).toString("hex")}.${apex}`;
  const res = await resolver.query(probe, "A").catch(() => null);
  if (!res || res.status !== "NOERROR") return null;
  const ips = res.answers.filter((a) => a.type === RR.A).map((a) => a.data);
  return ips.length ? new Set(ips) : null;
}

/**
 * Passive Quellen enthalten viele historische oder fehlerhafte Namen. In den Asset-Bestand
 * gelangen nur Subdomains, die aktuell im DNS existieren (oder als verwaister CNAME relevant sind).
 * Bei Wildcard-Zonen werden nur Namen übernommen, deren Adresse vom Wildcard-Ziel abweicht.
 */
export async function validateSubdomains(resolver: DnsResolver, apex: string, discovered: DiscoveredAsset[], signal?: AbortSignal): Promise<{ hosts: ValidatedSubdomain[]; candidates: number; truncated: boolean; wildcard: boolean }> {
  const bySource = new Map<string, Set<string>>();
  for (const d of discovered) {
    if (d.kind !== "subdomain") continue;
    if (!bySource.has(d.value)) bySource.set(d.value, new Set());
    bySource.get(d.value)!.add(d.source);
  }
  // Mehrfach bestätigte und kurze Namen zuerst
  const ranked = [...bySource.entries()].sort((a, b) => b[1].size - a[1].size || a[0].split(".").length - b[0].split(".").length || a[0].length - b[0].length);
  const truncated = ranked.length > MAX_DISCOVERY_CANDIDATES;
  const candidates = ranked.slice(0, MAX_DISCOVERY_CANDIDATES);
  const wildcardIps = await detectWildcard(resolver, apex);

  const results = await mapLimit(candidates, 16, async ([host, sources]): Promise<ValidatedSubdomain | null> => {
    if (signal?.aborted) return null;
    const res = await resolver.query(host, "A").catch(() => null);
    if (!res) return null;
    const cnames = res.answers.filter((a) => a.type === RR.CNAME);
    if (res.status === "NXDOMAIN") return cnames.length > 0 ? { host, sources: [...sources], dangling: true } : null;
    if (res.status !== "NOERROR") return null;
    const ips = res.answers.filter((a) => a.type === RR.A).map((a) => a.data);
    if (ips.length === 0 && cnames.length === 0) {
      const v6 = await resolver.query(host, "AAAA").catch(() => null);
      if (!v6 || !v6.answers.some((a) => a.type === RR.AAAA)) return null;
    }
    if (wildcardIps && ips.length > 0 && ips.every((ip) => wildcardIps.has(ip))) return null;
    return { host, sources: [...sources], dangling: false };
  });
  return { hosts: results.filter((r): r is ValidatedSubdomain => r !== null), candidates: candidates.length, truncated, wildcard: Boolean(wildcardIps) };
}
