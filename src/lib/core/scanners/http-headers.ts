import { resolveSafeTarget, safeHttpRequest, ScopeError, type HttpHop } from "../net/safe-connect";
import type { Coverage, Observation } from "../risk/types";
import { mapLimit } from "./runner";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

export interface HttpHostResult {
  host: string;
  skipped?: string;
  httpsError?: string;
  hstsHop?: HttpHop;
  contentHop?: HttpHop;
  redirectedOutOfScope?: string;
  httpCheck?: { status: number; location: string | null } | { error: string };
  securityTxt?: { status: number; hasContact: boolean } | { error: string };
}

export interface HttpRaw {
  apex: string;
  hosts: HttpHostResult[];
}

const header = (hop: HttpHop | undefined, name: string): string | undefined => {
  const v = hop?.headers[name.toLowerCase()];
  if (v === undefined) return undefined;
  return Array.isArray(v) ? v.join(", ") : v;
};

const VERSION_RE = /\d+\.\d+/;

export class HttpHeadersAdapter implements ScannerAdapter<HttpRaw> {
  key = "http_headers";
  label = "Webserver-Konfiguration und Sicherheitsheader";
  requiredScope = "config" as const;
  requiresVerification = false;
  timeoutMs = 120_000;

  initialize(): void {}

  async checkAvailability() {
    return { status: "available" as const };
  }

  validateAuthorization(ctx: ScanContext) {
    return standardAuthorization(this, ctx);
  }

  async execute(ctx: ScanContext): Promise<HttpRaw> {
    const scope = [ctx.apex];
    const hosts = ctx.hosts.slice(0, ctx.limits.maxHosts);
    const results = await mapLimit(hosts, 3, async (host): Promise<HttpHostResult> => {
      if (ctx.signal.aborted) return { host, skipped: "abgebrochen" };
      try {
        await resolveSafeTarget(host, ctx.resolver, scope);
      } catch (err) {
        return { host, skipped: err instanceof ScopeError ? err.message : errorMessage(err) };
      }
      const result: HttpHostResult = { host };
      try {
        const res = await safeHttpRequest(`https://${host}/`, ctx.resolver, scope, { maxRedirects: 5, timeoutMs: 10_000 });
        result.hstsHop = res.hops.find((h) => h.url.startsWith(`https://${host}/`)) ?? res.hops[0];
        if (res.final.status >= 200 && res.final.status < 300 && !res.stoppedAtOutOfScopeRedirect) result.contentHop = res.final;
        result.redirectedOutOfScope = res.stoppedAtOutOfScopeRedirect;
      } catch (err) {
        result.httpsError = errorMessage(err);
      }
      try {
        const res = await safeHttpRequest(`http://${host}/`, ctx.resolver, scope, { maxRedirects: 0, timeoutMs: 8000, method: "GET" });
        const loc = header(res.final, "location") ?? null;
        result.httpCheck = { status: res.final.status, location: loc };
      } catch (err) {
        result.httpCheck = { error: errorMessage(err) };
      }
      if (host === ctx.apex && !result.httpsError) {
        try {
          const res = await safeHttpRequest(`https://${host}/.well-known/security.txt`, ctx.resolver, scope, { maxRedirects: 3, timeoutMs: 8000, maxBodyBytes: 16_384 });
          result.securityTxt = { status: res.final.status, hasContact: res.final.status === 200 && /^contact:/im.test(res.bodySample) };
        } catch (err) {
          result.securityTxt = { error: errorMessage(err) };
        }
      }
      return result;
    });
    return { apex: ctx.apex, hosts: results };
  }

  normalizeResults(raw: HttpRaw): AdapterOutput {
    const obs: Observation[] = [];
    const coverage: Coverage[] = [];
    const primary = new Set([raw.apex, `www.${raw.apex}`]);

    for (const h of raw.hosts) {
      if (h.skipped) continue;
      if (h.httpsError) {
        if (primary.has(h.host)) {
          coverage.push({ asset: h.host, check: "web.https" });
          obs.push({ ruleId: "web.https.unavailable", asset: h.host, facts: { error: h.httpsError }, evidence: { error: h.httpsError } });
        }
      } else {
        coverage.push({ asset: h.host, check: "web.https" });
      }

      // HTTP -> HTTPS Weiterleitung
      if (h.httpCheck && "status" in h.httpCheck) {
        coverage.push({ asset: h.host, check: "web.redirect" });
        const { status, location } = h.httpCheck;
        const redirectsToHttps = status >= 300 && status < 400 && location !== null && /^https:\/\//i.test(new URL(location, `http://${h.host}/`).toString());
        if (status >= 200 && status < 300 && !redirectsToHttps) {
          obs.push({ ruleId: "web.redirect.no_https", asset: h.host, facts: { status }, evidence: { status } });
        }
      } else if (h.httpCheck && "error" in h.httpCheck) {
        // Port 80 nicht erreichbar = kein unverschlüsselter Zugang -> unkritisch
        coverage.push({ asset: h.host, check: "web.redirect" });
      }

      if (h.hstsHop && !h.httpsError) {
        const hsts = header(h.hstsHop, "strict-transport-security");
        if (!hsts) obs.push({ ruleId: "web.headers.hsts_missing", asset: h.host, facts: { url: h.hstsHop.url }, evidence: { url: h.hstsHop.url } });
        else {
          const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
          if (maxAge < 15_552_000) obs.push({ ruleId: "web.headers.hsts_short", asset: h.host, facts: { maxAge, header: hsts }, evidence: { header: hsts } });
        }
      }

      if (h.contentHop) {
        coverage.push({ asset: h.host, check: "web.headers" });
        const hop = h.contentHop;
        const facts = { url: hop.url };
        const csp = header(hop, "content-security-policy");
        if (!csp) obs.push({ ruleId: "web.headers.csp_missing", asset: h.host, facts, evidence: facts });
        if ((header(hop, "x-content-type-options") ?? "").toLowerCase() !== "nosniff")
          obs.push({ ruleId: "web.headers.xcto_missing", asset: h.host, facts, evidence: facts });
        if (!header(hop, "x-frame-options") && !/frame-ancestors/i.test(csp ?? ""))
          obs.push({ ruleId: "web.headers.clickjacking", asset: h.host, facts, evidence: facts });
        for (const name of ["server", "x-powered-by", "x-aspnet-version"]) {
          const value = header(hop, name);
          if (value && VERSION_RE.test(value)) {
            obs.push({ ruleId: "web.headers.version_disclosure", asset: h.host, discriminator: name, facts: { header: name, value: value.slice(0, 120) }, evidence: { header: name, value: value.slice(0, 120) } });
          }
        }
        const cookies = hop.headers["set-cookie"];
        const list = Array.isArray(cookies) ? cookies : cookies ? [cookies] : [];
        const insecure = list
          .filter((c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c))
          .map((c) => c.split("=")[0].trim())
          .filter(Boolean);
        if (insecure.length > 0) obs.push({ ruleId: "web.cookies.insecure", asset: h.host, facts: {}, evidence: { cookies: insecure.slice(0, 10) } });
      }

      if (h.securityTxt && "status" in h.securityTxt) {
        coverage.push({ asset: h.host, check: "web.security_txt" });
        if (!h.securityTxt.hasContact) obs.push({ ruleId: "web.security_txt.missing", asset: h.host, facts: { status: h.securityTxt.status }, evidence: { status: h.securityTxt.status } });
      }
    }

    const reachable = raw.hosts.filter((h) => !h.skipped);
    return {
      status: reachable.length === 0 ? "partial" : "ok",
      message: reachable.length === 0 ? "Kein Host mit öffentlicher Adresse erreichbar" : undefined,
      observations: obs,
      coverage,
      discoveredAssets: [],
      targets: raw.hosts.map((h) => h.host),
      data: {
        hosts: raw.hosts.map((h) => ({
          host: h.host,
          https: h.httpsError ? "error" : h.skipped ? "skipped" : "ok",
          hsts: h.hstsHop ? Boolean(header(h.hstsHop, "strict-transport-security")) : null,
          redirectedTo: h.redirectedOutOfScope ?? null,
          note: h.skipped ?? h.httpsError ?? null,
        })),
      },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `HTTP-Prüfung fehlgeschlagen: ${errorMessage(error)}`);
  }
}
