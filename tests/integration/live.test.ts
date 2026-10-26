import { describe, expect, it } from "vitest";
import { DohResolver } from "@/lib/core/net/dns";
import { runAdapter } from "@/lib/core/scanners/runner";
import { SubfinderAdapter } from "@/lib/core/scanners/subfinder";
import { processJob } from "../../worker/index";
import { log, service } from "./helpers";

/**
 * Echte Scanner gegen echte, öffentliche Ziele. Nur mit LIVE_SCANS=1 (benötigt Internetzugang).
 * Ziel example.com (IANA, für Dokumentation/Tests vorgesehen).
 */
describe.skipIf(!process.env.LIVE_SCANS)("Live-Scanner (echte Netzwerkprüfungen)", () => {
  it("öffentlicher Kurzcheck läuft vollständig durch den Worker", async () => {
    const { data: check } = await service.from("public_checks").insert({ hostname: "example.com", ip_hash: "test" }).select("id").single();
    const { data: job } = await service.from("scan_jobs").insert({ kind: "public_check", trigger: "public", payload: { public_check_id: check!.id }, idempotency_key: `live-${Date.now()}`, status: "running", attempts: 1 }).select("*").single();
    await processJob(job!, { db: service, env: { ...process.env, TLS_INTERCEPT_ISSUER_PATTERN: process.env.TLS_INTERCEPT_ISSUER_PATTERN } as Record<string, string | undefined>, log, workerId: "live" });
    const { data } = await service.from("public_checks").select("status, result").eq("id", check!.id).single();
    expect(data!.status).toBe("done");
    const result = data!.result as { modules: Array<{ key: string; status: string }>; findings: Array<{ title: string }> };
    expect(result.modules.find((m) => m.key === "dns")!.status).toBe("ok");
    expect(result.modules.find((m) => m.key === "http_headers")!.status).toBe("ok");
    expect(result.findings.length).toBeGreaterThan(0);
  }, 120_000);

  it("Subfinder liefert echte Subdomains", async () => {
    const a = new SubfinderAdapter();
    a.initialize({});
    const run = await runAdapter(a, {
      mode: "customer", orgId: "x", domainId: "x", apex: "example.com", hosts: [], ips: [], vulnScanHosts: [],
      authorization: { domainVerified: true, scopes: ["passive"], includeSubdomains: true },
      resolver: new DohResolver(), signal: new AbortController().signal, log, limits: { maxHosts: 5, breachMonitoring: false, vulnScan: false },
    });
    expect(run.output.status).toBe("ok");
    expect(run.output.discoveredAssets.length).toBeGreaterThan(0);
  }, 400_000);
});
