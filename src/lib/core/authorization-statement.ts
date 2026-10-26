import { createHash } from "node:crypto";
import { SCOPE_DESCRIPTIONS } from "./scope-descriptions";

export { SCOPE_DESCRIPTIONS };

export const AUTHORIZATION_STATEMENT_VERSION = "2026-10-v1";



export function authorizationStatement(p: { orgName: string; domain: string; scopes: string[]; includeSubdomains: boolean; signerName: string; signerRole: string }): string {
  const scopes = p.scopes.map((s) => `- ${SCOPE_DESCRIPTIONS[s as keyof typeof SCOPE_DESCRIPTIONS]?.title ?? s}`).join("\n");
  return [
    `Scan-Autorisierung (Version ${AUTHORIZATION_STATEMENT_VERSION})`,
    ``,
    `Hiermit bestätige ich, ${p.signerName} (${p.signerRole}), dass ich berechtigt bin, im Namen von „${p.orgName}“ zu handeln, und dass die Domain ${p.domain}${p.includeSubdomains ? " einschließlich ihrer Subdomains" : ""} von dieser Organisation betrieben wird oder sie zur Beauftragung von Sicherheitsprüfungen berechtigt ist.`,
    ``,
    `Ich beauftrage die CyberSafe24 GmbH, folgende Prüfungen wiederkehrend durchzuführen:`,
    scopes,
    ``,
    `Systeme Dritter (z. B. Hosting-, Cloud- oder E-Mail-Anbieter) werden nur im Rahmen der freigegebenen Prüfarten und nur soweit sie unter der genannten Domain erreichbar sind geprüft. Ich kann diese Autorisierung jederzeit widerrufen.`,
  ].join("\n");
}

export function statementHash(statement: string): string {
  return createHash("sha256").update(statement).digest("hex");
}
