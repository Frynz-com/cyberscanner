import "server-only";
import { z } from "zod";
import { AuthzError } from "./auth";

export type ActionResult<T = undefined> =
  | { ok: true; data?: T; message?: string }
  | { ok: false; error: string; fieldErrors?: Record<string, string> };

export class UserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UserError";
  }
}

/** Einheitliche Fehlerbehandlung für Server Actions: keine internen Details an den Client. */
export async function runAction<T>(fn: () => Promise<ActionResult<T>>): Promise<ActionResult<T>> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof z.ZodError) {
      const fieldErrors: Record<string, string> = {};
      for (const issue of err.issues) fieldErrors[issue.path.join(".")] ??= issue.message;
      return { ok: false, error: Object.values(fieldErrors)[0] ?? "Ungültige Eingabe", fieldErrors };
    }
    if (err instanceof AuthzError || err instanceof UserError) return { ok: false, error: err.message };
    // Next.js-Redirects/NotFound weiterreichen
    if (err && typeof err === "object" && "digest" in err && String((err as { digest: unknown }).digest).startsWith("NEXT_")) throw err;
    console.error(JSON.stringify({ level: "error", msg: "server action failed", error: err instanceof Error ? err.message : String(err) }));
    return { ok: false, error: "Es ist ein unerwarteter Fehler aufgetreten. Bitte versuchen Sie es erneut." };
  }
}

export function formToObject(fd: FormData): Record<string, string> {
  const out: Record<string, string> = {};
  fd.forEach((v, k) => {
    if (typeof v === "string") out[k] = v;
  });
  return out;
}
