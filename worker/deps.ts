import { createClient } from "@supabase/supabase-js";
import type { Database } from "../src/lib/database.types";
import type { Logger } from "../src/lib/core/scanners/types";

import type { Db } from "../src/lib/core/db";
export type { Db };

export interface WorkerDeps {
  db: Db;
  env: Record<string, string | undefined>;
  log: Logger;
  workerId: string;
}

export function createServiceClient(env: Record<string, string | undefined>): Db {
  const url = env.SUPABASE_URL ?? env.NEXT_PUBLIC_SUPABASE_URL;
  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("SUPABASE_URL und SUPABASE_SERVICE_ROLE_KEY müssen gesetzt sein");
  return createClient<Database>(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

/** Strukturiertes JSON-Logging (für Log-Aggregation / Fehlerüberwachung). Keine personenbezogenen Daten loggen. */
export function createLogger(base: Record<string, unknown> = {}): Logger {
  const write = (level: string, msg: string, data?: Record<string, unknown>) =>
    console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...base, ...data }));
  return {
    info: (m, d) => write("info", m, d),
    warn: (m, d) => write("warn", m, d),
    error: (m, d) => write("error", m, d),
  };
}

export class NonRetryableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NonRetryableError";
  }
}
