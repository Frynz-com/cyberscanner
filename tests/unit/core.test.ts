import { describe, expect, it } from "vitest";
import { decryptField, encryptField, hmac, maskAccount } from "@/lib/core/crypto";
import { isWithinScope, normalizeHostname, registrableDomain } from "@/lib/core/domain";
import { isPublicIp } from "@/lib/core/net/ip";
import { computeMonitoringStatus } from "@/lib/core/monitoring-status";
import { subscriptionIsActive } from "@/lib/core/plans";
import { StaticResolver, unquoteTxt } from "@/lib/core/net/dns";
import { resolveSafeTarget, safeHttpRequest, ScopeError } from "@/lib/core/net/safe-connect";

describe("Domain-Normalisierung", () => {
  it("normalisiert URLs, Groß-/Kleinschreibung und www", () => {
    expect(normalizeHostname("https://WWW.Firma.de/kontakt?x=1")).toEqual({ ok: true, hostname: "firma.de" });
    expect(normalizeHostname("shop.firma.de.")).toEqual({ ok: true, hostname: "shop.firma.de" });
    expect(normalizeHostname("müller-bau.de")).toEqual({ ok: true, hostname: "xn--mller-bau-q9a.de" });
  });
  it("lehnt IPs, interne Namen, E-Mails und Unsinn ab", () => {
    for (const bad of ["127.0.0.1", "[::1]", "localhost", "intranet.local", "router.lan", "firma", "max@firma.de", "", "a..b.de", "-x.de", "metadata.google.internal"]) {
      expect(normalizeHostname(bad).ok, bad).toBe(false);
    }
  });
  it("erlaubt .example nur im Demo-Modus", () => {
    expect(normalizeHostname("muster.example").ok).toBe(false);
    expect(normalizeHostname("muster.example", { allowDemo: true }).ok).toBe(true);
  });
  it("prüft Scope label-basiert", () => {
    expect(isWithinScope("a.firma.de", "firma.de")).toBe(true);
    expect(isWithinScope("firma.de", "firma.de")).toBe(true);
    expect(isWithinScope("evilfirma.de", "firma.de")).toBe(false);
    expect(isWithinScope("firma.de.evil.com", "firma.de")).toBe(false);
    expect(registrableDomain("a.b.firma.co.uk")).toBe("firma.co.uk");
  });
});

describe("IP-Klassifizierung (SSRF-Schutz)", () => {
  it.each([
    ["10.1.2.3"], ["172.16.0.1"], ["192.168.1.1"], ["127.0.0.1"], ["169.254.169.254"], ["100.100.100.200"], ["0.0.0.0"],
    ["::1"], ["fd00:ec2::254"], ["fe80::1"], ["::ffff:127.0.0.1"], ["::ffff:7f00:1"], ["64:ff9b::a9fe:a9fe"], ["2002:c0a8:0101::1"], ["224.0.0.1"], ["198.18.0.1"],
  ])("%s ist nicht öffentlich", (ip) => expect(isPublicIp(ip)).toBe(false));
  it.each([["1.1.1.1"], ["93.184.215.14"], ["2606:4700:4700::1111"], ["::ffff:1.1.1.1"]])("%s ist öffentlich", (ip) => expect(isPublicIp(ip)).toBe(true));
  it("lehnt Nicht-IPs ab", () => expect(isPublicIp("example.com")).toBe(false));
});

describe("Sichere Zielauflösung", () => {
  const resolver = new StaticResolver({
    "firma.de|A": { answers: [{ type: 1, data: "93.184.215.14" }] },
    "intern.firma.de|A": { answers: [{ type: 1, data: "10.0.0.5" }] },
    "rebind.firma.de|A": { answers: [{ type: 1, data: "93.184.215.14" }, { type: 1, data: "127.0.0.1" }] },
    "meta.firma.de|A": { answers: [{ type: 5, data: "x.example.org." }, { type: 1, data: "169.254.169.254" }] },
  });
  it("akzeptiert öffentliche Ziele im Scope", async () => {
    await expect(resolveSafeTarget("firma.de", resolver, ["firma.de"])).resolves.toMatchObject({ ip: "93.184.215.14", family: 4 });
  });
  it("blockiert private, gemischte (Rebinding) und Metadaten-Adressen", async () => {
    for (const host of ["intern.firma.de", "rebind.firma.de", "meta.firma.de"]) {
      await expect(resolveSafeTarget(host, resolver, ["firma.de"])).rejects.toMatchObject({ code: "non_public_address" });
    }
  });
  it("blockiert Ziele außerhalb der Freigabe", async () => {
    await expect(resolveSafeTarget("google.com", resolver, ["firma.de"])).rejects.toBeInstanceOf(ScopeError);
  });
  it("lehnt fremde Ports, Protokolle und Zugangsdaten in URLs ab", async () => {
    await expect(safeHttpRequest("https://firma.de:8443/", resolver, ["firma.de"])).rejects.toMatchObject({ code: "port_not_allowed" });
    await expect(safeHttpRequest("file:///etc/passwd", resolver, ["firma.de"])).rejects.toMatchObject({ code: "invalid_url" });
    await expect(safeHttpRequest("gopher://firma.de/", resolver, ["firma.de"])).rejects.toMatchObject({ code: "invalid_url" });
    await expect(safeHttpRequest("https://user:pw@firma.de/", resolver, ["firma.de"])).rejects.toMatchObject({ code: "invalid_url" });
  });
});

describe("DNS-Hilfen", () => {
  it("fügt TXT-Fragmente zusammen", () => {
    expect(unquoteTxt('"v=spf1 include:a" " -all"')).toBe("v=spf1 include:a -all");
    expect(unquoteTxt('"a\\"b"')).toBe('a"b');
  });
});

describe("Verschlüsselung & Datenminimierung", () => {
  it("verschlüsselt authentifiziert und entschlüsselt korrekt", () => {
    const enc = encryptField("anna@firma.de");
    expect(enc).not.toContain("anna");
    expect(decryptField(enc)).toBe("anna@firma.de");
    expect(encryptField("anna@firma.de")).not.toBe(enc); // zufälliger IV
  });
  it("erkennt Manipulation", () => {
    const enc = encryptField("x@y.de");
    const parts = enc.split(".");
    parts[3] = Buffer.from("manipuliert").toString("base64");
    expect(() => decryptField(parts.join("."))).toThrow();
  });
  it("hasht deterministisch und maskiert", () => {
    expect(hmac("A@B.de")).toBe(hmac("a@b.de"));
    expect(maskAccount("max.mustermann@firma.de")).toBe("ma***@firma.de");
  });
});

describe("Abo-Status", () => {
  it("wertet Status serverseitig aus", () => {
    expect(subscriptionIsActive({ status: "active", trial_ends_at: null })).toBe(true);
    expect(subscriptionIsActive({ status: "trialing", trial_ends_at: new Date(Date.now() + 1000).toISOString() })).toBe(true);
    expect(subscriptionIsActive({ status: "trialing", trial_ends_at: new Date(Date.now() - 1000).toISOString() })).toBe(false);
    expect(subscriptionIsActive({ status: "canceled", trial_ends_at: null })).toBe(false);
    expect(subscriptionIsActive(null)).toBe(false);
  });
});

describe("Überwachungsstatus", () => {
  const base = { orgPaused: false, subscriptionActive: true, lastDomainJobStatus: "succeeded", missingIntegrations: [] };
  const d = (o: Partial<{ verification_status: string; monitoring_enabled: boolean; last_scan_at: string | null; hasAuthorization: boolean }> = {}) => ({ verification_status: "verified", monitoring_enabled: true, last_scan_at: "2026-10-01", hasAuthorization: true, ...o });
  it("liefert ehrliche Zustände", () => {
    expect(computeMonitoringStatus({ ...base, domains: [] }).state).toBe("verification_required");
    expect(computeMonitoringStatus({ ...base, domains: [d({ verification_status: "pending" })] }).state).toBe("verification_required");
    expect(computeMonitoringStatus({ ...base, domains: [d({ hasAuthorization: false })] }).title).toBe("Freigabe erforderlich");
    expect(computeMonitoringStatus({ ...base, subscriptionActive: false, domains: [d()] }).state).toBe("paused");
    expect(computeMonitoringStatus({ ...base, lastDomainJobStatus: "failed", domains: [d()] }).state).toBe("scan_failed");
    expect(computeMonitoringStatus({ ...base, domains: [d({ last_scan_at: null })] }).state).toBe("pending_first_scan");
    const ok = computeMonitoringStatus({ ...base, missingIntegrations: ["hibp"], domains: [d()] });
    expect(ok.state).toBe("active");
    expect(ok.integrationMissing).toBe(true);
  });
});
