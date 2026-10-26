import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { StaticResolver } from "@/lib/core/net/dns";
import { normalizeObservation } from "@/lib/core/risk/engine";
import { HudsonRockAdapter } from "@/lib/core/scanners/hudsonrock";
import { generatePermutations, LookalikeAdapter } from "@/lib/core/scanners/lookalike";
import { matchVictims, RansomwareLiveAdapter } from "@/lib/core/scanners/ransomware-live";
import { runAdapter } from "@/lib/core/scanners/runner";
import type { ScanContext } from "@/lib/core/scanners/types";

const fx = (n: string) => JSON.parse(readFileSync(new URL(`../fixtures/${n}`, import.meta.url), "utf8"));
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
const apex = "kunde-beispiel.de";
const ctx = (o: Partial<ScanContext> = {}): ScanContext => ({
  mode: "customer", orgId: "o", domainId: "d", apex, hosts: [apex], ips: [], vulnScanHosts: [],
  authorization: { domainVerified: true, scopes: ["passive", "config"], includeSubdomains: true },
  resolver: new StaticResolver({}), signal: new AbortController().signal, log: { info() {}, warn() {}, error() {} },
  limits: { maxHosts: 5, breachMonitoring: true, vulnScan: false }, ...o,
});

describe("Hudson Rock (Infostealer)", () => {
  it("bewertet infizierte Mitarbeitergeräte und Kundenkonten ohne Zugangsdaten zu speichern", async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      expect(String(url)).toContain(`domain=${apex}`);
      return json(fx("hudsonrock-domain.json"));
    });
    const a = new HudsonRockAdapter(fetchImpl as unknown as typeof fetch);
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.status).toBe("ok");
    const emp = run.output.observations.find((o) => o.ruleId === "intel.infostealer_employees")!;
    expect(emp.facts.employees).toBe(5);
    expect(emp.facts.urls).toContain("http://ftp.kunde-beispiel.de");
    const n = normalizeObservation(emp, "hudsonrock", apex);
    expect(n.certainty).toBe("potential");
    expect(["critical", "high", "medium"]).toContain(n.severity);
    expect(run.output.observations.some((o) => o.ruleId === "intel.infostealer_users")).toBe(true);
    expect(JSON.stringify(run.output)).not.toMatch(/password"\s*:\s*"/i);
    expect(run.output.coverage).toEqual([{ asset: apex, check: "intel.infostealer" }]);
  });
  it("Schweregrad richtet sich nach Aktualität der Infektion", () => {
    const o = (ageDays: number) => normalizeObservation({ ruleId: "intel.infostealer_employees", asset: apex, facts: { employees: 2, ageDays, urls: [] }, evidence: {} }, "hudsonrock", apex).severity;
    expect(o(30)).toBe("critical");
    expect(o(400)).toBe("high");
    expect(o(1200)).toBe("medium");
  });
  it("keine Treffer -> keine Befunde, aber vollständig geprüft", async () => {
    const a = new HudsonRockAdapter((async () => json(fx("hudsonrock-clean.json"))) as unknown as typeof fetch);
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.observations).toHaveLength(0);
    expect(run.output.coverage).toHaveLength(1);
  });
  it("in Produktion ohne bestätigte Nutzungsbedingungen gesperrt; nie im öffentlichen Check", async () => {
    const a = new HudsonRockAdapter();
    a.initialize({ NODE_ENV: "production" });
    expect((await a.checkAvailability()).status).toBe("license_required");
    a.initialize({ NODE_ENV: "production", HUDSONROCK_TERMS_CONFIRMED: "true" });
    expect((await a.checkAvailability()).status).toBe("available");
    const b = new HudsonRockAdapter((async () => json({})) as unknown as typeof fetch);
    b.initialize({});
    expect((await runAdapter(b, ctx({ mode: "public_check" }))).output.status).toBe("not_authorized");
    expect((await runAdapter(b, ctx({ authorization: { domainVerified: false, scopes: ["passive"], includeSubdomains: false } }))).output.status).toBe("not_authorized");
  });
  it("API-Ausfall wird als Fehler gemeldet (kein falsches 'sauber')", async () => {
    const a = new HudsonRockAdapter((async () => new Response("x", { status: 503 })) as unknown as typeof fetch);
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.status).toBe("error");
    expect(run.output.coverage).toHaveLength(0);
  });
});

describe("ransomware.live", () => {
  it("findet nur exakte Domain-Treffer (keine unscharfe Namenssuche)", () => {
    expect(matchVictims(fx("ransomwarelive-search.json"), apex).map((v) => v.victim)).toEqual(["Kunde Beispiel GmbH"]);
    expect(matchVictims([{ victim: "x", group: "g", domain: "evil-kunde-beispiel.de" }], apex)).toHaveLength(0);
    expect(matchVictims([{ victim: "x", group: "g", domain: "https://www.kunde-beispiel.de/" }], apex)).toHaveLength(1);
  });
  it("Eintrag wird als kritischer möglicher Befund gemeldet; 404 = kein Eintrag", async () => {
    const a = new RansomwareLiveAdapter((async () => json(fx("ransomwarelive-search.json"))) as unknown as typeof fetch);
    a.initialize({});
    const run = await runAdapter(a, ctx());
    expect(run.output.observations).toHaveLength(1);
    const n = normalizeObservation(run.output.observations[0], "ransomware_live", apex);
    expect(n.certainty).toBe("potential");
    const none = new RansomwareLiveAdapter((async () => json({ error: "No victims" }, 404)) as unknown as typeof fetch);
    none.initialize({});
    const r2 = await runAdapter(none, ctx());
    expect(r2.output.observations).toHaveLength(0);
    expect(r2.output.coverage).toHaveLength(1);
  });
});

describe("Nachgemachte Domains", () => {
  it("erzeugt typische Varianten ohne das Original", () => {
    const p = generatePermutations("muster-bau.de").map((x) => x.domain);
    expect(p).toContain("muster-bau.com");
    expect(p).toContain("musterbau.de");
    expect(p).toContain("muster-bau-rechnung.de");
    expect(p).toContain("muster-baau.de");
    expect(p).not.toContain("muster-bau.de");
    expect(new Set(p).size).toBe(p.length);
    expect(generatePermutations("firma.de").map((x) => x.domain)).toContain("f1rma.de");
  });
  it("meldet registrierte Varianten, gewichtet nach E-Mail-Fähigkeit", async () => {
    const resolver = new StaticResolver({
      "kunde-beispiel.com|A": { answers: [{ type: 1, data: "203.0.113.5" }] },
      "kunde-beispiel.com|MX": { answers: [{ type: 15, data: "10 mx.phish.example." }] },
      "kundebeispiel.de|A": { answers: [{ type: 1, data: "203.0.113.6" }] },
      "kundebeispiel.de|MX": { answers: [] },
      "kunde-beispiel.de|A": { answers: [{ type: 1, data: "198.51.100.9" }] },
      "kunde-beispiel.at|A": { answers: [{ type: 1, data: "198.51.100.9" }] },
    });
    const run = await runAdapter(new LookalikeAdapter(), ctx({ resolver, mode: "public_check", authorization: { domainVerified: false, scopes: ["passive", "config"], includeSubdomains: false } }));
    const sev = Object.fromEntries(run.output.observations.map((o) => [o.discriminator, normalizeObservation(o, "lookalike", apex).severity]));
    expect(sev).toEqual({ "kunde-beispiel.com": "medium", "kundebeispiel.de": "low" });
    expect(run.output.coverage).toHaveLength(1);
  });
});
