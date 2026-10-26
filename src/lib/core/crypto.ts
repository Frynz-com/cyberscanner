import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Feldverschlüsselung für personenbezogene Daten (AES-256-GCM) und
 * deterministische Pseudonymisierung (HMAC-SHA256) für Deduplizierung.
 * Schlüssel: DATA_ENCRYPTION_KEY (32 Byte, base64).
 */
function key(raw: string | undefined): Buffer {
  if (!raw) throw new Error("DATA_ENCRYPTION_KEY ist nicht gesetzt");
  const k = Buffer.from(raw, "base64");
  if (k.length !== 32) throw new Error("DATA_ENCRYPTION_KEY muss 32 Byte (base64) lang sein");
  return k;
}

export function encryptField(plain: string, rawKey = process.env.DATA_ENCRYPTION_KEY): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(rawKey), iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return `v1.${iv.toString("base64")}.${cipher.getAuthTag().toString("base64")}.${enc.toString("base64")}`;
}

export function decryptField(payload: string, rawKey = process.env.DATA_ENCRYPTION_KEY): string {
  const [v, iv, tag, data] = payload.split(".");
  if (v !== "v1" || !iv || !tag || !data) throw new Error("Unbekanntes Verschlüsselungsformat");
  const decipher = createDecipheriv("aes-256-gcm", key(rawKey), Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64")), decipher.final()]).toString("utf8");
}

export function hmac(value: string, rawKey = process.env.DATA_ENCRYPTION_KEY): string {
  return createHmac("sha256", key(rawKey)).update(value.toLowerCase()).digest("hex");
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Zufälliges, URL-sicheres Token (für Einladungen / Verifikation). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** IP-Adressen werden nur gehasht gespeichert (Datenminimierung). */
export function hashIp(ip: string | null | undefined, salt = process.env.DATA_ENCRYPTION_KEY ?? ""): string {
  return createHash("sha256").update(`${salt}|${ip ?? "unknown"}`).digest("hex").slice(0, 32);
}

/** Maskiert ein Konto für die Anzeige: max.mustermann@firma.de -> ma***@firma.de */
export function maskAccount(email: string): string {
  const [local, domain] = email.split("@");
  if (!domain) return "***";
  return `${local.slice(0, Math.min(2, local.length))}***@${domain}`;
}
