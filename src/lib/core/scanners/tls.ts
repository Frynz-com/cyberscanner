import tls from "node:tls";
import { resolveSafeTarget, ScopeError, tlsProbe, type SafeTarget, type TlsProbeResult } from "../net/safe-connect";
import type { Coverage, Observation } from "../risk/types";
import { mapLimit } from "./runner";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

export interface TlsHostResult {
  host: string;
  ip?: string;
  skipped?: string;
  error?: string;
  intercepted?: boolean;
  cert?: {
    subject: string;
    issuer: string;
    issuerOrg: string;
    validFrom: string;
    validTo: string;
    altNames: string[];
    bits: number | null;
    isEc: boolean;
    selfSigned: boolean;
  };
  protocol?: string | null;
  authorized?: boolean;
  authorizationError?: string | null;
  hostnameMatches?: boolean;
  legacy?: { checked: boolean; supported: string | null };
}

export interface TlsRaw {
  hosts: TlsHostResult[];
  now: string;
}

const SELF_SIGNED_ERRORS = new Set(["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"]);

export function summarizeCert(host: string, probe: TlsProbeResult): Pick<TlsHostResult, "cert" | "hostnameMatches"> {
  const c = probe.peerCertificate!;
  const altNames = (c.subjectaltname ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:"))
    .map((s) => s.slice(4).toLowerCase());
  const identityError = tls.checkServerIdentity(host, c);
  return {
    cert: {
      subject: c.subject?.CN ? String(c.subject.CN) : "",
      issuer: c.issuer?.CN ? String(c.issuer.CN) : "",
      issuerOrg: c.issuer?.O ? String(c.issuer.O) : "",
      validFrom: new Date(c.valid_from).toISOString(),
      validTo: new Date(c.valid_to).toISOString(),
      altNames,
      bits: typeof c.bits === "number" ? c.bits : null,
      isEc: Boolean((c as { asn1Curve?: string }).asn1Curve),
      selfSigned: SELF_SIGNED_ERRORS.has(probe.authorizationError ?? ""),
    },
    hostnameMatches: identityError === undefined,
  };
}

export class TlsAdapter implements ScannerAdapter<TlsRaw> {
  key = "tls";
  label = "TLS-Zertifikate und Protokolle";
  requiredScope = "config" as const;
  requiresVerification = false;
  timeoutMs = 120_000;
  private interceptPattern: RegExp | null = null;

  initialize(env: Record<string, string | undefined>): void {
    // Schutz vor Fehlinterpretation: Wird TLS von einem Egress-Proxy terminiert (z. B. in
    // Entwicklungsumgebungen), sind die Zertifikatsdaten NICHT die des Kunden.
    this.interceptPattern = env.TLS_INTERCEPT_ISSUER_PATTERN ? new RegExp(env.TLS_INTERCEPT_ISSUER_PATTERN, "i") : null;
  }

  async checkAvailability() {
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    return standardAuthorization(this, ctx);
  }

  async execute(ctx: ScanContext): Promise<TlsRaw> {
    const hosts = ctx.hosts.slice(0, ctx.limits.maxHosts);
    const results = await mapLimit(hosts, 4, async (host): Promise<TlsHostResult> => {
      if (ctx.signal.aborted) return { host, skipped: "abgebrochen" };
      let target: SafeTarget;
      try {
        target = await resolveSafeTarget(host, ctx.resolver, [ctx.apex]);
      } catch (err) {
        if (err instanceof ScopeError) return { host, skipped: err.message };
        return { host, error: errorMessage(err) };
      }
      let probe: TlsProbeResult;
      try {
        probe = await tlsProbe(target, { timeoutMs: 8000 });
      } catch (err) {
        return { host, ip: target.ip, error: errorMessage(err) };
      }
      if (!probe.peerCertificate) return { host, ip: target.ip, error: "Kein Zertifikat erhalten" };
      const summary = summarizeCert(host, probe);
      const issuerText = `${summary.cert!.issuer} ${summary.cert!.issuerOrg}`;
      if (this.interceptPattern?.test(issuerText)) {
        return { host, ip: target.ip, intercepted: true, error: "TLS wird von einem Egress-Proxy terminiert – Zertifikatsdaten nicht verwertbar" };
      }
      // Veraltete Protokolle (TLS 1.0/1.1) gezielt anfragen
      let legacy: TlsHostResult["legacy"] = { checked: false, supported: null };
      try {
        const old = await tlsProbe(target, { timeoutMs: 6000, minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT@SECLEVEL=0" });
        legacy = { checked: true, supported: old.protocol };
      } catch (err) {
        // Handshake-Ablehnung = nicht unterstützt; Timeout = nicht aussagekräftig
        legacy = { checked: !/Timeout/i.test(errorMessage(err)), supported: null };
      }
      return {
        host,
        ip: target.ip,
        protocol: probe.protocol,
        authorized: probe.authorized,
        authorizationError: probe.authorizationError,
        legacy,
        ...summary,
      };
    });
    return { hosts: results, now: new Date().toISOString() };
  }

  normalizeResults(raw: TlsRaw): AdapterOutput {
    const obs: Observation[] = [];
    const coverage: Coverage[] = [];
    const now = new Date(raw.now).getTime();
    let intercepted = 0;
    for (const h of raw.hosts) {
      if (h.intercepted) intercepted++;
      if (!h.cert) continue;
      coverage.push({ asset: h.host, check: "tls.cert" });
      const c = h.cert;
      const facts = { subject: c.subject, issuer: c.issuer || c.issuerOrg, validTo: c.validTo.slice(0, 10) };
      const daysLeft = Math.floor((new Date(c.validTo).getTime() - now) / 86_400_000);
      if (daysLeft < 0) obs.push({ ruleId: "tls.cert.expired", asset: h.host, facts, evidence: facts });
      else if (daysLeft <= 30) obs.push({ ruleId: "tls.cert.expiring", asset: h.host, facts: { ...facts, daysLeft }, evidence: { ...facts, daysLeft } });
      if (!h.hostnameMatches) obs.push({ ruleId: "tls.cert.hostname_mismatch", asset: h.host, facts, evidence: { altNames: c.altNames.slice(0, 20) } });
      if (!h.authorized && h.authorizationError && h.authorizationError !== "CERT_HAS_EXPIRED") {
        obs.push({
          ruleId: "tls.cert.untrusted",
          asset: h.host,
          facts: { ...facts, error: h.authorizationError, selfSigned: c.selfSigned },
          evidence: { error: h.authorizationError, issuer: c.issuer },
        });
      }
      if (!c.isEc && c.bits !== null && c.bits < 2048) obs.push({ ruleId: "tls.cert.weak_key", asset: h.host, facts: { bits: c.bits }, evidence: { bits: c.bits } });
      if (h.legacy?.checked) {
        coverage.push({ asset: h.host, check: "tls.protocol" });
        if (h.legacy.supported) obs.push({ ruleId: "tls.protocol.legacy", asset: h.host, facts: { protocol: h.legacy.supported }, evidence: { protocol: h.legacy.supported } });
      }
    }
    const withCert = raw.hosts.filter((h) => h.cert).length;
    const status = intercepted > 0 && withCert === 0 ? "unavailable" : raw.hosts.some((h) => h.error && !h.cert) ? "partial" : "ok";
    return {
      status,
      message: intercepted > 0 ? "TLS-Verbindungen werden in dieser Umgebung von einem Proxy terminiert; Ergebnisse verworfen." : undefined,
      observations: obs,
      coverage,
      discoveredAssets: [],
      targets: raw.hosts.map((h) => h.host),
      data: {
        hosts: raw.hosts.map((h) => ({
          host: h.host,
          issuer: h.cert?.issuerOrg || h.cert?.issuer || null,
          validTo: h.cert?.validTo ?? null,
          protocol: h.protocol ?? null,
          error: h.error ?? h.skipped ?? null,
        })),
      },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `TLS-Prüfung fehlgeschlagen: ${errorMessage(error)}`);
  }
}
