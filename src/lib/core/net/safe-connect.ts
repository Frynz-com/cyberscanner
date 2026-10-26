import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import type { LookupFunction } from "node:net";
import { isValidHostname, isWithinScope } from "../domain";
import { isPublicIp } from "./ip";
import { resolveAddresses, type DnsResolver } from "./dns";

export const SCANNER_USER_AGENT =
  "CyberSafe24-Shield-Scanner/1.0 (+https://cybersafe24.de/scanner; autorisierte Konfigurationspruefung)";

export class ScopeError extends Error {
  constructor(
    message: string,
    public code: "invalid_host" | "out_of_scope" | "no_address" | "non_public_address" | "invalid_url" | "port_not_allowed",
  ) {
    super(message);
    this.name = "ScopeError";
  }
}

export interface SafeTarget {
  host: string;
  ip: string;
  family: 4 | 6;
  allAddresses: string[];
}

/**
 * Löst einen Host auf und prüft:
 *  - Host liegt in der freigegebenen Zieldomain (Allowlist)
 *  - ALLE aufgelösten Adressen sind öffentlich (Schutz vor SSRF/DNS-Rebinding auf interne Ziele)
 * Die Verbindung erfolgt anschließend fest auf die geprüfte IP (Pinning), damit eine zweite,
 * abweichende DNS-Antwort (Rebinding) keine Wirkung hat.
 */
export async function resolveSafeTarget(host: string, resolver: DnsResolver, allowedApexes: string[]): Promise<SafeTarget> {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!isValidHostname(h)) throw new ScopeError(`Ungültiger Hostname: ${h}`, "invalid_host");
  if (!allowedApexes.some((apex) => isWithinScope(h, apex))) {
    throw new ScopeError(`${h} liegt außerhalb des freigegebenen Bereichs`, "out_of_scope");
  }
  const { v4, v6 } = await resolveAddresses(resolver, h);
  const all = [...v4, ...v6];
  if (all.length === 0) throw new ScopeError(`${h} hat keine IP-Adresse`, "no_address");
  const nonPublic = all.filter((ip) => !isPublicIp(ip));
  if (nonPublic.length > 0) {
    throw new ScopeError(`${h} zeigt auf nicht-öffentliche Adressen – Prüfung aus Sicherheitsgründen übersprungen`, "non_public_address");
  }
  const ip = v4[0] ?? v6[0];
  return { host: h, ip, family: v4[0] ? 4 : 6, allAddresses: all };
}

function pinnedLookup(target: SafeTarget): LookupFunction {
  return ((_hostname: string, options: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    if (options?.all) callback(null, [{ address: target.ip, family: target.family }]);
    else callback(null, target.ip, target.family);
  }) as unknown as LookupFunction;
}

export interface TlsProbeResult {
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  peerCertificate: tls.DetailedPeerCertificate | null;
}

export function tlsProbe(
  target: SafeTarget,
  opts: { port?: number; timeoutMs?: number; minVersion?: tls.SecureVersion; maxVersion?: tls.SecureVersion; ciphers?: string } = {},
): Promise<TlsProbeResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: target.ip,
      port: opts.port ?? 443,
      servername: target.host,
      rejectUnauthorized: false, // Bewertung erfolgt selbst (authorized/authorizationError)
      minVersion: opts.minVersion,
      maxVersion: opts.maxVersion,
      ciphers: opts.ciphers,
      ALPNProtocols: ["http/1.1"],
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`TLS-Timeout nach ${opts.timeoutMs ?? 8000} ms`));
    }, opts.timeoutMs ?? 8000);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      const cert = socket.getPeerCertificate(true);
      const result: TlsProbeResult = {
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        peerCertificate: cert && Object.keys(cert).length > 0 ? cert : null,
      };
      socket.end();
      resolve(result);
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    });
  });
}

export interface HttpHop {
  url: string;
  status: number;
  headers: Record<string, string | string[]>;
  ip: string;
}

export interface SafeHttpResult {
  hops: HttpHop[];
  final: HttpHop;
  /** Weiterleitung auf ein Ziel außerhalb der Freigabe – wird nicht verfolgt. */
  stoppedAtOutOfScopeRedirect?: string;
  bodySample: string;
}

const ALLOWED_PORTS: Record<string, number> = { "http:": 80, "https:": 443 };

export async function safeHttpRequest(
  rawUrl: string,
  resolver: DnsResolver,
  allowedApexes: string[],
  opts: { maxRedirects?: number; timeoutMs?: number; maxBodyBytes?: number; method?: "GET" | "HEAD" } = {},
): Promise<SafeHttpResult> {
  const maxRedirects = opts.maxRedirects ?? 5;
  const hops: HttpHop[] = [];
  let current = rawUrl;
  for (let i = 0; i <= maxRedirects; i++) {
    let url: URL;
    try {
      url = new URL(current);
    } catch {
      throw new ScopeError(`Ungültige URL: ${current}`, "invalid_url");
    }
    if (!(url.protocol in ALLOWED_PORTS)) throw new ScopeError(`Protokoll nicht erlaubt: ${url.protocol}`, "invalid_url");
    if (url.username || url.password) throw new ScopeError("URLs mit Zugangsdaten sind nicht erlaubt", "invalid_url");
    const port = url.port ? Number(url.port) : ALLOWED_PORTS[url.protocol];
    if (port !== ALLOWED_PORTS[url.protocol]) throw new ScopeError(`Port ${port} nicht erlaubt`, "port_not_allowed");

    let target: SafeTarget;
    try {
      target = await resolveSafeTarget(url.hostname, resolver, allowedApexes);
    } catch (err) {
      if (err instanceof ScopeError && err.code === "out_of_scope" && hops.length > 0) {
        return { hops, final: hops[hops.length - 1], stoppedAtOutOfScopeRedirect: url.hostname, bodySample: "" };
      }
      throw err;
    }
    const { status, headers, body } = await singleRequest(url, target, opts);
    const hop: HttpHop = { url: url.toString(), status, headers, ip: target.ip };
    hops.push(hop);
    const location = headers["location"];
    if (status >= 300 && status < 400 && typeof location === "string" && i < maxRedirects) {
      current = new URL(location, url).toString();
      continue;
    }
    return { hops, final: hop, bodySample: body };
  }
  return { hops, final: hops[hops.length - 1], bodySample: "" };
}

function singleRequest(
  url: URL,
  target: SafeTarget,
  opts: { timeoutMs?: number; maxBodyBytes?: number; method?: "GET" | "HEAD" },
): Promise<{ status: number; headers: Record<string, string | string[]>; body: string }> {
  const mod = url.protocol === "https:" ? https : http;
  const maxBody = opts.maxBodyBytes ?? 64 * 1024;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      url,
      {
        method: opts.method ?? "GET",
        lookup: pinnedLookup(target),
        servername: url.protocol === "https:" ? target.host : undefined,
        rejectUnauthorized: false, // Zertifikatsfehler bewertet der TLS-Adapter; hier nur Header
        agent: false,
        headers: { "user-agent": SCANNER_USER_AGENT, accept: "text/html,*/*;q=0.8", "accept-encoding": "identity" },
        timeout: opts.timeoutMs ?? 10_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          if (size < maxBody) chunks.push(chunk.subarray(0, maxBody - size));
          size += chunk.length;
          if (size >= maxBody) res.destroy();
        });
        const done = () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string | string[]>,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        res.on("end", done);
        res.on("close", done);
        res.on("error", () => done());
      },
    );
    req.on("timeout", () => req.destroy(new Error(`HTTP-Timeout nach ${opts.timeoutMs ?? 10_000} ms`)));
    req.on("error", reject);
    req.end();
  });
}
