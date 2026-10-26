import { execFile } from "node:child_process";
import { isValidHostname, isWithinScope } from "../domain";
import { emptyOutput, errorMessage, standardAuthorization, type AdapterOutput, type ScanContext, type ScannerAdapter } from "./types";

export interface SubfinderRaw {
  apex: string;
  lines: string[];
}

export interface ExecResult {
  stdout: string;
  stderr: string;
}

export type ExecFn = (file: string, args: string[], opts: { timeoutMs: number; signal: AbortSignal }) => Promise<ExecResult>;

/**
 * Sichere Prozessausführung: execFile ohne Shell, Argumente als Array,
 * minimale Umgebung, Zeit- und Ausgabelimit.
 */
function minimalEnv(): NodeJS.ProcessEnv {
  const env: Record<string, string> = { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", HOME: process.env.HOME ?? "/tmp" };
  for (const k of ["HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE", "NO_PROXY", "no_proxy"]) {
    const v = process.env[k];
    if (v) env[k] = v;
  }
  return env as NodeJS.ProcessEnv;
}

export const safeExec: ExecFn = (file, args, opts) =>
  new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      {
        timeout: opts.timeoutMs,
        maxBuffer: 8 * 1024 * 1024,
        killSignal: "SIGKILL",
        signal: opts.signal,
        windowsHide: true,
        env: minimalEnv(),
        encoding: "utf8",
      },
      (err, stdout, stderr) => {
        if (err) reject(Object.assign(err, { stderr: String(stderr).slice(0, 2000) }));
        else resolve({ stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });

export function parseSubfinderOutput(lines: string[], apex: string): Array<{ host: string; source: string }> {
  const out = new Map<string, string>();
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let host: string;
    let source = "subfinder";
    try {
      const j = JSON.parse(trimmed) as { host?: string; source?: string };
      if (!j.host) continue;
      host = j.host;
      source = j.source ? `subfinder:${j.source}` : source;
    } catch {
      host = trimmed;
    }
    host = host.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    if (!isValidHostname(host) || !isWithinScope(host, apex) || host === apex) continue;
    if (!out.has(host)) out.set(host, source);
  }
  return [...out.entries()].map(([host, source]) => ({ host, source }));
}

export class SubfinderAdapter implements ScannerAdapter<SubfinderRaw> {
  key = "subfinder";
  label = "Subdomain-Erkennung (ProjectDiscovery Subfinder)";
  requiredScope = "passive" as const;
  requiresVerification = true;
  timeoutMs = 6 * 60_000;
  private bin = "subfinder";
  private providerConfig: string | undefined;

  constructor(private exec: ExecFn = safeExec) {}

  initialize(env: Record<string, string | undefined>): void {
    this.bin = env.SUBFINDER_BIN || "subfinder";
    this.providerConfig = env.SUBFINDER_PROVIDER_CONFIG || undefined;
  }

  async checkAvailability() {
    try {
      await this.exec(this.bin, ["-version"], { timeoutMs: 10_000, signal: AbortSignal.timeout(10_000) });
      return { status: "available" as const };
    } catch (err) {
      return { status: "unavailable" as const, message: `Subfinder nicht installiert oder nicht ausführbar (${errorMessage(err)})` };
    }
  }

  validateAuthorization(ctx: ScanContext) {
    const base = standardAuthorization(this, ctx);
    if (!base.ok) return base;
    if (!ctx.authorization.includeSubdomains) return { ok: false as const, reason: "Subdomains sind nicht in der Freigabe enthalten" };
    return base;
  }

  async execute(ctx: ScanContext): Promise<SubfinderRaw> {
    if (!isValidHostname(ctx.apex)) throw new Error("Ungültige Domain");
    const args = ["-d", ctx.apex, "-silent", "-oJ", "-nc", "-timeout", "30", "-max-time", "5", "-disable-update-check"];
    if (this.providerConfig) args.push("-provider-config", this.providerConfig);
    const { stdout } = await this.exec(this.bin, args, { timeoutMs: this.timeoutMs - 5000, signal: ctx.signal });
    return { apex: ctx.apex, lines: stdout.split("\n") };
  }

  normalizeResults(raw: SubfinderRaw): AdapterOutput {
    const hosts = parseSubfinderOutput(raw.lines, raw.apex);
    return {
      status: "ok",
      observations: [],
      coverage: [],
      discoveredAssets: hosts.map((h) => ({ kind: "subdomain" as const, value: h.host, source: h.source })),
      targets: [raw.apex],
      data: { subdomainCount: hosts.length },
    };
  }

  reportErrors(error: unknown): AdapterOutput {
    return emptyOutput("error", `Subfinder fehlgeschlagen: ${errorMessage(error)}`);
  }
}
