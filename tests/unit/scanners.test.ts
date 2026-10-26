import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { StaticResolver } from "@/lib/core/net/dns";
import { normalizeObservation, reconcile, type ExistingFinding } from "@/lib/core/risk/engine";
import { RULES } from "@/lib/core/risk/rules";
import { CtLogsAdapter, extractCtNames } from "@/lib/core/scanners/ct-logs";
import { countSpfLookups, DnsSecurityAdapter } from "@/lib/core/scanners/dns-security";
import { HibpAdapter } from "@/lib/core/scanners/hibp";
import { HttpHeadersAdapter, type HttpRaw } from "@/lib/core/scanners/http-headers";
import { InternetDbAdapter, isCdnEntry } from "@/lib/core/scanners/internetdb";
import { NucleiAdapter, parseNucleiOutput } from "@/lib/core/scanners/nuclei";
import { runAdapter } from "@/lib/core/scanners/runner";
import { parseSubfinderOutput, SubfinderAdapter } from "@/lib/core/scanners/subfinder";
import { TlsAdapter, type TlsRaw } from "@/lib/core/scanners/tls";
import type { ScanContext, ScannerAdapter } from "@/lib/core/scanners/types";

const fx = (name: string) => readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8");
const json = (name: string) => JSON.parse(fx(name));
const log = { info() {}, warn() {}, error() {} };

function ctx(over: Partial<ScanContext> = {}): ScanContext {
  return {
    mode: "customer",
    orgId: "o",
    domainId: "d",
    apex: "kunde-beispiel.de",
    hosts: ["kunde-beispiel.de", "www.kunde-beispiel.de"],
    ips: [],
    vulnScanHosts: [],
    authorization: { domainVerified: true, scopes: ["passive", "config"], includeSubdomains: true },
    resolver: new StaticResolver({}),
    signal: new AbortController().signal,
    log,
    limits: { maxHosts: 10, breachMonitoring: true, vulnScan: false },
    ...over,
  };
}

const jsonResponse = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

describe("DNS-Sicherheitsadapter (Fixture-Resolver)", () => {
  const apex = "kunde-beispiel.de";
  const resolver = new StaticResolver({
    [`${apex}|MX`]: { answers: [{ type: 15, data: "10 mx.kunde-beispiel.de." }] },
    [`${apex}|NS`]: { answers: [{ type: 2, data: "ns1.provider.example." }] },
    [`${apex}|TXT`]: { answers: [{ type: 16, data: '"v=spf1 include:_spf.a.example include:_spf.b.example ?all"' }] },
    ["_spf.a.example|TXT"]: { answers: [{ type: 16, data: '"v=spf1 include:x1.example include:x2.example include:x3.example include:x4.example include:x5.example a mx -all"' }] },
    ["_spf.b.example|TXT"]: { answers: [{ type: 16, data: '"v=spf1 a mx ptr exists:%{i}.x.example -all"' }] },
    [`_dmarc.${apex}|TXT`]: { answers: [{ type: 16, data: '"v=DMARC1; p=none"' }] },
    [`${apex}|DS`]: { status: "NOERROR", answers: [] },
    [`${apex}|CAA`]: { status: "NOERROR", answers: [] },
    [`${apex}|SOA`]: { answers: [{ type: 6, data: "ns1. hostmaster. 1 2 3 4 5" }] },
    [`old.${apex}|A`]: { status: "NXDOMAIN", answers: [{ type: 5, data: "kunde-alt.azurewebsites.net." }] },
  });

  it("erzeugt deterministische Befunde mit Begründung", async () => {
    const run = await runAdapter(new DnsSecurityAdapter(), ctx({ resolver, hosts: [apex, `old.${apex}`] }));
    expect(run.output.status).toBe("ok");
    const ids = run.output.observations.map((o) => o.ruleId).sort();
    expect(ids).toEqual([
      "dns.caa.missing",
      "dns.dangling_cname",
      "dns.dnssec.unsigned",
      "dns.ns.single",
      "email.dkim.not_checkable",
      "email.dmarc.no_reporting",
      "email.dmarc.policy_none",
      "email.spf.permissive_all",
      "email.spf.too_many_lookups",
    ]);
    const spf = run.output.observations.find((o) => o.ruleId === "email.spf.permissive_all")!;
    const n = normalizeObservation(spf, "dns", apex);
    expect(n.severity).toBe("medium");
    expect(n.priorityReasons.join(" ")).toContain("neutral");
    expect(run.output.coverage).toContainEqual({ asset: `old.${apex}`, check: "dns.dangling" });
  });

  it("zählt SPF-Lookups rekursiv nach RFC 7208", async () => {
    expect(await countSpfLookups(resolver, "v=spf1 include:_spf.a.example include:_spf.b.example ?all")).toBe(13);
  });

  it("wertet SERVFAIL nicht als fehlenden Eintrag (keine erfundenen Befunde)", async () => {
    const broken = new StaticResolver({
      [`${apex}|TXT`]: { status: "SERVFAIL" },
      [`_dmarc.${apex}|TXT`]: { status: "SERVFAIL" },
      [`${apex}|SOA`]: { answers: [{ type: 6, data: "x" }] },
      [`${apex}|MX`]: { answers: [] },
      [`${apex}|NS`]: { answers: [{ type: 2, data: "a." }, { type: 2, data: "b." }] },
      [`${apex}|CAA`]: { answers: [{ type: 257, data: '0 issue "letsencrypt.org"' }] },
      [`${apex}|DS`]: { answers: [{ type: 43, data: "1 13 2 ABC" }] },
    });
    const run = await runAdapter(new DnsSecurityAdapter(), ctx({ resolver: broken, hosts: [apex] }));
    expect(run.output.status).toBe("partial");
    expect(run.output.observations.filter((o) => o.ruleId.startsWith("email.spf") || o.ruleId.startsWith("email.dmarc"))).toHaveLength(0);
    expect(run.output.coverage.map((c) => c.check)).not.toContain("email.spf");
  });
});

describe("TLS-Adapter (Normalisierung)", () => {
  const raw = (over: Partial<TlsRaw["hosts"][number]>): TlsRaw => ({
    now: "2026-10-26T00:00:00Z",
    hosts: [{ host: "kunde-beispiel.de", ip: "198.51.100.1", protocol: "TLSv1.3", authorized: true, authorizationError: null, hostnameMatches: true, legacy: { checked: true, supported: null }, cert: { subject: "kunde-beispiel.de", issuer: "R11", issuerOrg: "Let's Encrypt", validFrom: "2026-09-01T00:00:00Z", validTo: "2027-01-01T00:00:00Z", altNames: ["kunde-beispiel.de"], bits: 2048, isEc: false, selfSigned: false }, ...over }],
  });
  const a = new TlsAdapter();
  it("Ablaufschwellen", () => {
    const at = (validTo: string) => a.normalizeResults(raw({ cert: { ...raw({}).hosts[0].cert!, validTo } }));
    expect(at("2027-01-01T00:00:00Z").observations).toHaveLength(0);
    const in5 = at("2026-10-31T00:00:00Z").observations[0];
    expect(in5.ruleId).toBe("tls.cert.expiring");
    expect(normalizeObservation(in5, "tls", "kunde-beispiel.de").severity).toBe("high");
    expect(normalizeObservation(at("2026-11-20T00:00:00Z").observations[0], "tls", "kunde-beispiel.de").severity).toBe("low");
    expect(at("2026-10-01T00:00:00Z").observations[0].ruleId).toBe("tls.cert.expired");
  });
  it("Hostname, Vertrauen, Legacy-Protokolle", () => {
    const out = a.normalizeResults(raw({ hostnameMatches: false, authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT", legacy: { checked: true, supported: "TLSv1" } }));
    expect(out.observations.map((o) => o.ruleId).sort()).toEqual(["tls.cert.hostname_mismatch", "tls.cert.untrusted", "tls.protocol.legacy"]);
  });
  it("verwirft Ergebnisse bei TLS-Interception (keine falschen Zertifikatsdaten)", () => {
    const out = a.normalizeResults({ now: "2026-10-26T00:00:00Z", hosts: [{ host: "x.de", intercepted: true, error: "proxy" }] });
    expect(out.status).toBe("unavailable");
    expect(out.coverage).toHaveLength(0);
  });
});

describe("HTTP-Header-Adapter (Normalisierung)", () => {
  const hop = (headers: Record<string, string | string[]>, url = "https://kunde-beispiel.de/") => ({ url, status: 200, headers, ip: "198.51.100.1" });
  it("erkennt fehlende Header und Versionsangaben", () => {
    const raw: HttpRaw = {
      apex: "kunde-beispiel.de",
      hosts: [{ host: "kunde-beispiel.de", hstsHop: hop({ server: "Apache/2.4.41 (Ubuntu)" }), contentHop: hop({ server: "Apache/2.4.41 (Ubuntu)", "set-cookie": ["PHPSESSID=abc; path=/"] }), httpCheck: { status: 200, location: null }, securityTxt: { status: 404, hasContact: false } }],
    };
    const ids = new HttpHeadersAdapter().normalizeResults(raw).observations.map((o) => o.ruleId).sort();
    expect(ids).toEqual(["web.cookies.insecure", "web.headers.clickjacking", "web.headers.csp_missing", "web.headers.hsts_missing", "web.headers.version_disclosure", "web.headers.xcto_missing", "web.redirect.no_https", "web.security_txt.missing"]);
  });
  it("gut konfigurierte Seite erzeugt keine Befunde", () => {
    const good = { "strict-transport-security": "max-age=63072000; includeSubDomains", "content-security-policy": "default-src 'self'; frame-ancestors 'self'", "x-content-type-options": "nosniff", server: "nginx" };
    const raw: HttpRaw = { apex: "kunde-beispiel.de", hosts: [{ host: "kunde-beispiel.de", hstsHop: hop(good), contentHop: hop(good), httpCheck: { status: 301, location: "https://kunde-beispiel.de/" }, securityTxt: { status: 200, hasContact: true } }] };
    expect(new HttpHeadersAdapter().normalizeResults(raw).observations).toHaveLength(0);
  });
});

describe("Subfinder-Adapter", () => {
  it("parst echte JSON-Ausgabe und filtert fremde Hosts", () => {
    const hosts = parseSubfinderOutput(fx("subfinder.jsonl").split("\n"), "kunde-beispiel.de");
    expect(hosts.length).toBeGreaterThan(5);
    expect(hosts.every((h) => h.host.endsWith(".kunde-beispiel.de"))).toBe(true);
    expect(hosts.find((h) => h.host === "evil.example.org")).toBeUndefined();
    expect(hosts.find((h) => h.host === "wild.kunde-beispiel.de")).toBeDefined();
  });
  it("übergibt Argumente als Array (keine Shell) und meldet fehlendes Binary", async () => {
    const exec = vi.fn(async (_file: string, args: string[]) => {
      if (args[0] === "-version") return { stdout: "", stderr: "v2.17.0" };
      return { stdout: fx("subfinder.jsonl"), stderr: "" };
    });
    const a = new SubfinderAdapter(exec);
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.status).toBe("ok");
    const call = exec.mock.calls.find((c) => c[1][0] === "-d")!;
    expect(call[0]).toBe("subfinder");
    expect(call[1]).toContain("kunde-beispiel.de");
    const missing = new SubfinderAdapter(async () => { throw Object.assign(new Error("spawn subfinder ENOENT"), { code: "ENOENT" }); });
    expect((await runAdapter(missing, ctx())).output.status).toBe("unavailable");
  });
  it("verweigert ohne Verifikation bzw. Subdomain-Freigabe", async () => {
    const a = new SubfinderAdapter(async () => ({ stdout: "", stderr: "" }));
    expect((await runAdapter(a, ctx({ authorization: { domainVerified: false, scopes: ["passive"], includeSubdomains: true } }))).output.status).toBe("not_authorized");
    expect((await runAdapter(a, ctx({ authorization: { domainVerified: true, scopes: ["passive"], includeSubdomains: false } }))).output.status).toBe("not_authorized");
  });
});

describe("Certificate-Transparency-Adapter", () => {
  it("extrahiert nur Namen im Scope", () => {
    const names = (json("crtsh.json") as Array<{ name_value: string }>).map((e) => e.name_value);
    expect(extractCtNames(names, "kunde-beispiel.de").sort()).toEqual(["autodiscover.kunde-beispiel.de", "mail.kunde-beispiel.de", "portal.kunde-beispiel.de", "www.kunde-beispiel.de"]);
  });
  it("fällt bei crt.sh-Ausfall auf Cert Spotter zurück", async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      if (String(url).includes("crt.sh")) return new Response("Bad Gateway", { status: 502 });
      return jsonResponse([{ dns_names: ["shop.kunde-beispiel.de", "kunde-beispiel.de"] }]);
    });
    const a = new CtLogsAdapter(fetchImpl as unknown as typeof fetch);
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.status).toBe("partial");
    expect(run.output.discoveredAssets.map((d) => d.value)).toEqual(["shop.kunde-beispiel.de"]);
  });
});

describe("InternetDB-Adapter", () => {
  it("ist ohne Lizenz deaktiviert und in Produktion nicht im Evaluationsmodus nutzbar", async () => {
    const a = new InternetDbAdapter();
    a.initialize({});
    expect((await a.checkAvailability()).status).toBe("license_required");
    a.initialize({ SHODAN_INTERNETDB_LICENSE: "evaluation", NODE_ENV: "production" });
    expect((await a.checkAvailability()).status).toBe("license_required");
    a.initialize({ SHODAN_INTERNETDB_LICENSE: "enterprise", NODE_ENV: "production" });
    expect((await a.checkAvailability()).status).toBe("available");
  });
  it("bewertet riskante Ports, CVE-Hinweise (KEV) und ignoriert CDN-IPs", async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => (String(url).endsWith("1.1.1.1") ? jsonResponse(json("internetdb-cdn.json")) : jsonResponse(json("internetdb-exposed.json"))));
    const a = new InternetDbAdapter(fetchImpl as unknown as typeof fetch);
    a.initialize({ SHODAN_INTERNETDB_LICENSE: "enterprise" });
    const run = await runAdapter(a, ctx({ ips: ["1.1.1.1", "198.51.100.23", "10.0.0.1"], isKnownExploited: (c) => c === "CVE-2019-0708" }));
    expect(fetchImpl).toHaveBeenCalledTimes(1); // private (10/8) und reservierte Dokumentations-IPs (198.51.100/24) werden nie abgefragt
    expect(isCdnEntry(json("internetdb-cdn.json"))).toBe(true);
  });
  it("normalisiert Fixture (öffentliche IP)", () => {
    const a = new InternetDbAdapter();
    const out = a.normalizeResults({ results: [{ ip: "203.0.114.5", entry: { ...json("internetdb-exposed.json"), ip: "203.0.114.5" } }] }, ctx({ isKnownExploited: (c) => c === "CVE-2019-0708" }));
    const ports = out.observations.filter((o) => o.ruleId === "exposure.risky_service").map((o) => o.discriminator).sort();
    expect(ports).toEqual(["3389", "445"]);
    const kev = out.observations.find((o) => o.discriminator === "CVE-2019-0708")!;
    const n = normalizeObservation(kev, "internetdb", "kunde-beispiel.de");
    expect(n.certainty).toBe("potential"); // nie als bestätigte Schwachstelle
    expect(n.severity).toBe("high");
    expect(n.priorityReasons.join(" ")).toContain("CISA");
    const other = normalizeObservation(out.observations.find((o) => o.discriminator === "CVE-2018-15473")!, "internetdb", "kunde-beispiel.de");
    expect(other.severity).toBe("medium");
    expect(other.confidence).toBe("low");
  });
  it("meldet API-Ausfall als Fehler statt leerer Ergebnisse", async () => {
    const a = new InternetDbAdapter((async () => new Response("err", { status: 503 })) as unknown as typeof fetch);
    a.initialize({ SHODAN_INTERNETDB_LICENSE: "enterprise" });
    const run = await runAdapter(a, ctx({ ips: ["8.8.8.8"] }));
    expect(run.output.status).toBe("error");
    expect(run.output.coverage).toHaveLength(0);
  });
});

describe("HIBP-Adapter", () => {
  const breaches = json("hibp-breaches.json");
  const fetchFor = (subscribed: unknown, domainRes: Response | null) =>
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      const headers = init?.headers as Record<string, string>;
      expect(headers["user-agent"]).toMatch(/CyberSafe24/);
      if (u.endsWith("/breaches")) {
        expect(headers["hibp-api-key"]).toBeUndefined();
        return jsonResponse(breaches);
      }
      expect(headers["hibp-api-key"]).toBe("k".repeat(32));
      if (u.endsWith("/subscribeddomains")) return jsonResponse(subscribed);
      if (u.includes("/breacheddomain/")) return domainRes ?? new Response(null, { status: 404 });
      return new Response(null, { status: 404 });
    });
  it("ist ohne Schlüssel inaktiv (keine erfundenen Daten)", async () => {
    const a = new HibpAdapter();
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.status).toBe("unavailable");
    expect(run.output.observations).toHaveLength(0);
  });
  it("liefert 'nicht prüfbar', wenn die Domain im HIBP-Konto nicht verifiziert ist", async () => {
    const a = new HibpAdapter(fetchFor([], null) as unknown as typeof fetch);
    a.initialize({ HIBP_API_KEY: "k".repeat(32) });
    const run = await runAdapter(a, ctx());
    expect(run.output.observations.map((o) => o.ruleId)).toEqual(["breach.provider_domain_unverified"]);
    expect(normalizeObservation(run.output.observations[0], "hibp", "kunde-beispiel.de").certainty).toBe("not_checkable");
  });
  it("gruppiert Konten je Breach, bewertet Passwortlecks nach Alter", async () => {
    const a = new HibpAdapter(fetchFor(json("hibp-subscribeddomains.json"), jsonResponse(json("hibp-breacheddomain.json"))) as unknown as typeof fetch);
    a.initialize({ HIBP_API_KEY: "k".repeat(32) });
    const run = await runAdapter(a, ctx());
    expect(run.output.status).toBe("ok");
    const adobe = run.output.observations.find((o) => o.discriminator === "Adobe")!;
    expect(adobe.facts.accountCount).toBe(2);
    expect(normalizeObservation(adobe, "hibp", "kunde-beispiel.de").severity).toBe("medium"); // Passwörter, aber > 2 Jahre alt
    expect(run.output.breachRecords).toHaveLength(4);
    expect(JSON.stringify(run.output.observations)).not.toContain("anna.schmidt"); // keine Konten in Findings
  });
  it("respektiert retry-after bei 429", async () => {
    let calls = 0;
    const sleep = vi.fn(async () => {});
    const fetchImpl = vi.fn(async (url: string | URL) => {
      if (String(url).endsWith("/subscribeddomains") && calls++ === 0) return new Response(null, { status: 429, headers: { "retry-after": "3" } });
      if (String(url).endsWith("/subscribeddomains")) return jsonResponse([]);
      return jsonResponse([]);
    });
    const a = new HibpAdapter(fetchImpl as unknown as typeof fetch, sleep);
    a.initialize({ HIBP_API_KEY: "k".repeat(32) });
    await runAdapter(a, ctx());
    expect(sleep).toHaveBeenCalledWith(3000);
  });
  it("verweigert ohne Tarif-Freischaltung oder im öffentlichen Kurzcheck", async () => {
    const a = new HibpAdapter(fetchFor([], null) as unknown as typeof fetch);
    a.initialize({ HIBP_API_KEY: "k".repeat(32) });
    expect((await runAdapter(a, ctx({ limits: { maxHosts: 2, breachMonitoring: false, vulnScan: false } }))).output.status).toBe("not_authorized");
    expect((await runAdapter(a, ctx({ mode: "public_check" }))).output.status).toBe("not_authorized");
  });
});

describe("Nuclei-Adapter", () => {
  it("ist standardmäßig deaktiviert", async () => {
    const a = new NucleiAdapter(async () => ({ stdout: "", stderr: "" }));
    a.initialize({});
    expect((await a.checkAvailability()).status).toBe("disabled");
  });
  it("verlangt Asset-Freigabe, Scope und Tarif", async () => {
    const a = new NucleiAdapter(async () => ({ stdout: "", stderr: "" }));
    a.initialize({ NUCLEI_ENABLED: "true", NUCLEI_TEMPLATE_IDS: "git-config" });
    expect((await runAdapter(a, ctx({ limits: { maxHosts: 5, breachMonitoring: true, vulnScan: true }, authorization: { domainVerified: true, scopes: ["passive", "config", "vuln_scan"], includeSubdomains: true } }))).output.status).toBe("not_authorized");
    expect((await runAdapter(a, ctx({ vulnScanHosts: ["shop.kunde-beispiel.de"], limits: { maxHosts: 5, breachMonitoring: true, vulnScan: true } }))).output.status).toBe("not_authorized");
  });
  it("übergibt nur Allowlist-Templates, schließt destruktive Tags aus, ignoriert Treffer außerhalb", async () => {
    const exec = vi.fn(async (_f: string, args: string[]) => (args[0] === "-version" ? { stdout: "", stderr: "" } : { stdout: fx("nuclei.jsonl"), stderr: "" }));
    const a = new NucleiAdapter(exec);
    a.initialize({ NUCLEI_ENABLED: "true", NUCLEI_TEMPLATE_IDS: "git-config, bad id;rm -rf" });
    const run = await runAdapter(a, ctx({ vulnScanHosts: ["shop.kunde-beispiel.de"], limits: { maxHosts: 5, breachMonitoring: true, vulnScan: true }, authorization: { domainVerified: true, scopes: ["passive", "config", "vuln_scan"], includeSubdomains: true } }));
    const args = exec.mock.calls.find((c) => c[1][0] === "-jsonl")![1];
    expect(args[args.indexOf("-id") + 1]).toBe("git-config");
    expect(args[args.indexOf("-etags") + 1]).toContain("dos");
    expect(args).toContain("-ni");
    expect(run.output.observations).toHaveLength(1);
    expect(run.output.observations[0].asset).toBe("shop.kunde-beispiel.de");
    expect(parseNucleiOutput(["garbage"], ["x.de"], "x.de")).toHaveLength(0);
  });
});

describe("Laufzeit: Timeout & Abbruch", () => {
  const slow: ScannerAdapter = {
    key: "slow", label: "slow", requiredScope: "passive", requiresVerification: false, timeoutMs: 50,
    initialize() {}, checkAvailability: async () => ({ status: "available" }), validateAuthorization: () => ({ ok: true }),
    execute: () => new Promise((r) => setTimeout(r, 1000)),
    normalizeResults: () => { throw new Error("nicht erwartet"); },
    reportErrors: (e) => ({ status: "error", observations: [], coverage: [], discoveredAssets: [], targets: [], data: {}, message: String((e as Error).message) }),
  };
  it("bricht nach Timeout ab und meldet Fehler", async () => {
    const run = await runAdapter(slow, ctx());
    expect(run.output.status).toBe("error");
    expect(run.output.message).toMatch(/Zeitlimit/);
  });
  it("respektiert Abbruchsignal", async () => {
    const c = new AbortController();
    const p = runAdapter({ ...slow, timeoutMs: 5000 }, ctx({ signal: c.signal }));
    c.abort();
    expect((await p).output.status).toBe("skipped");
  });
});

describe("Risk Engine: Deduplizierung, Änderungserkennung, Nachprüfung", () => {
  const apex = "kunde-beispiel.de";
  const obs = (ruleId: string, asset = apex, discriminator?: string) => normalizeObservation({ ruleId, asset, discriminator, facts: { hasMx: true }, evidence: {} }, "dns", apex);
  const existing = (f: ReturnType<typeof obs>, status: ExistingFinding["status"], verificationState: ExistingFinding["verificationState"] = null): ExistingFinding => ({
    id: f.fingerprint.slice(0, 8), fingerprint: f.fingerprint, status, checkKey: f.check, assetValue: f.asset, severity: f.severity, verificationState,
  });
  const cov = (check: string, asset = apex) => ({ asset, check });

  it("alle Regeln haben gültige deutsche Texte", () => {
    for (const r of RULES.values()) {
      const o = { ruleId: r.id, asset: apex, facts: {}, evidence: {} };
      expect(r.title(o).length).toBeGreaterThan(5);
      expect(r.recommendation(o).length).toBeGreaterThan(10);
      expect(r.evaluate(o).reasons.length).toBeGreaterThan(0);
    }
  });
  it("identische Befunde erzeugen keine neuen Einträge", () => {
    const f = obs("email.dmarc.missing");
    const ops = reconcile([existing(f, "action_required")], [f, f], [cov("email.dmarc")]);
    expect(ops).toEqual([expect.objectContaining({ type: "seen_again" })]);
  });
  it("neu, behoben (bestätigt), wieder aufgetreten, akzeptiert", () => {
    const a = obs("email.dmarc.missing");
    const b = obs("dns.caa.missing");
    const c = obs("email.spf.missing");
    const d = obs("dns.dnssec.unsigned");
    const ops = reconcile([existing(a, "new"), existing(c, "resolved"), existing(d, "accepted_risk")], [b, c, d], [cov("email.dmarc"), cov("dns.caa"), cov("email.spf"), cov("dns.dnssec")]);
    expect(ops.find((o) => o.type === "create")).toMatchObject({ finding: { ruleId: "dns.caa.missing" } });
    expect(ops.find((o) => o.type === "verified_fixed")).toMatchObject({ id: existing(a, "new").id, alreadyClosed: false });
    expect(ops.find((o) => o.type === "reappeared")).toMatchObject({ wasMarkedFixed: false });
    expect(ops.find((o) => o.type === "seen_closed")).toBeDefined();
  });
  it("behauptet keine Behebung, wenn die Prüfung nicht lief", () => {
    const a = obs("email.dmarc.missing");
    expect(reconcile([existing(a, "new")], [], [cov("email.spf")])).toHaveLength(0);
    expect(reconcile([existing(a, "new")], [], [cov("email.dmarc", "www.kunde-beispiel.de")])).toHaveLength(0);
  });
  it("vom Kunden als behoben markiert, aber weiterhin vorhanden -> still_present", () => {
    const a = obs("email.dmarc.missing");
    const ops = reconcile([existing(a, "resolved", "unverified")], [a], [cov("email.dmarc")]);
    expect(ops[0]).toMatchObject({ type: "reappeared", wasMarkedFixed: true });
    const fixed = reconcile([existing(a, "resolved", "unverified")], [], [cov("email.dmarc")]);
    expect(fixed[0]).toMatchObject({ type: "verified_fixed", alreadyClosed: true });
  });
  it("Priorität ist deterministisch und begrenzt", () => {
    const x = obs("dns.dangling_cname", "old.kunde-beispiel.de", "t");
    const y = obs("dns.dangling_cname", "old.kunde-beispiel.de", "t");
    expect(x.priorityScore).toBe(y.priorityScore);
    expect(x.priorityScore).toBe(Math.round(70 * 0.85));
    expect(x.fingerprint).toBe(y.fingerprint);
  });
});
