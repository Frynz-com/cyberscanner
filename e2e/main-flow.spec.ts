import { expect, test } from "@playwright/test";
import { drainJobs, register, service, simulateDnsVerification } from "./helpers";

/**
 * Hauptnutzerfluss (Definition of Done 1–14): Registrierung → Organisation → Domain → Verifikation →
 * Freigabe → echter Scan → Befunde → IT-Dienstleister → Nachprüfung → Bericht → Notfall.
 */
test("Hauptnutzerfluss mit echtem Scanner", async ({ page, browser }) => {
  const stamp = Date.now();
  const email = `e2e-${stamp}@example.org`;
  const orgName = `E2E Test GmbH ${stamp}`;

  // 1–2: Registrierung und Organisation
  await register(page, email);
  await page.fill("#name", orgName);
  await page.getByRole("button", { name: "Weiter" }).click();

  // 3: Domain (URL-Eingabe wird normalisiert)
  await page.fill("#domain", "https://www.Example.com/start");
  await page.getByRole("button", { name: "Domain hinzufügen" }).click();
  await expect(page.getByText("Bestätigen Sie, dass example.com Ihnen gehört")).toBeVisible();
  await expect(page.getByText(/^cs24-verify=/)).toBeVisible();

  // 4: echte DNS-Prüfung – Eintrag existiert nicht -> ehrliche Meldung
  await page.getByRole("button", { name: "Eintrag jetzt prüfen" }).click();
  await expect(page.getByText("Eintrag noch nicht gefunden")).toBeVisible();
  const orgId = await simulateDnsVerification("example.com", orgName);

  // 5: Prüfberechtigung
  await page.reload();
  await page.fill("#signerRole", "Geschäftsführerin");
  await page.getByText("Ich bestätige").click();
  await page.getByRole("button", { name: "Freigabe erteilen" }).click();

  // 6: erste Prüfung – echter Worker-Code, echte Netzwerkprüfung
  await page.getByRole("button", { name: "Erste Prüfung starten" }).click();
  await expect(page.getByText("Prüfung läuft")).toBeVisible();
  await drainJobs(1);
  await expect(page.getByText("Erste Prüfung abgeschlossen")).toBeVisible({ timeout: 30_000 });

  // 7–8: Ergebnisse gespeichert und im Dashboard sichtbar
  await page.getByRole("button", { name: "Ergebnisse ansehen" }).click();
  await expect(page.getByTestId("monitoring-status")).toHaveAttribute("data-state", "active");
  const { count } = await service.from("findings").select("id", { count: "exact", head: true }).eq("org_id", orgId);
  expect(count).toBeGreaterThan(0);
  await expect(page.getByText("Ihre Aufmerksamkeit ist gefragt")).toBeVisible();

  // 9: Maßnahme verstehen
  await page.goto("/app/findings");
  await page.getByText("HSTS-Header fehlt").first().click();
  await expect(page.getByText("Warum ist das wichtig?")).toBeVisible();
  await expect(page.getByText("Was sollte ich jetzt tun?")).toBeVisible();
  await page.getByRole("tab", { name: "Für IT-Dienstleister" }).click();
  await expect(page.getByText("Reproduzierbare Prüfschritte")).toBeVisible();
  const findingUrl = page.url();

  // 10: an IT-Dienstleister weitergeben
  await page.getByRole("button", { name: "An IT-Dienstleister senden" }).click();
  await page.fill("#companyName", "IT-Service E2E");
  await page.fill("input#email", "it@partner.example.org");
  await page.getByRole("button", { name: "Freigeben" }).click();
  const link = await page.locator("input[readonly]").inputValue();
  expect(link).toContain("/partner/");
  await page.getByRole("button", { name: "Fertig" }).click();

  // Partner sieht nur den freigegebenen Befund (eigener, nicht angemeldeter Browser-Kontext)
  const partnerCtx = await browser.newContext();
  const partner = await partnerCtx.newPage();
  await partner.goto(link);
  await expect(partner.getByTestId("partner-finding")).toHaveCount(1);
  await expect(partner.getByText("HSTS-Header fehlt")).toBeVisible();
  await partner.getByRole("button", { name: /Maßnahme umgesetzt/ }).click();
  await expect(partner.getByText(/Nachprüfung wurde gestartet/)).toBeVisible();

  // 11: zulässige Nachprüfung – Scanner stellt fest: weiterhin vorhanden (example.com setzt kein HSTS)
  await drainJobs(2);
  await page.goto(findingUrl);
  await expect(page.getByText("Nachprüfung: weiterhin vorhanden.")).toBeVisible();
  await expect(page.getByTestId("finding-events")).toContainText("IT informiert");
  await expect(page.getByTestId("finding-events")).toContainText("Weiterhin vorhanden");
  await partnerCtx.close();

  // Als behoben markieren behauptet keine Behebung ohne Bestätigung
  await page.getByRole("button", { name: "Als behoben markieren" }).click();
  await expect(page.getByText("Die technische Bestätigung steht noch aus")).toBeVisible();

  // 12: Benachrichtigungen vorhanden (dedupliziert)
  const { data: notes } = await service.from("notifications").select("dedupe_key").eq("org_id", orgId);
  expect(new Set(notes!.map((n) => n.dedupe_key)).size).toBe(notes!.length);

  // 13: PDF-Bericht
  await page.goto("/app/reports");
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: /Aktuellen Bericht erstellen/ }).click()]);
  expect(download.suggestedFilename()).toMatch(/\.pdf$/);

  // 14: Notfall als Incident
  await page.goto("/app/emergency");
  await page.getByTestId("report-incident").click();
  await page.getByText("Phishing-Vorfall").first().click();
  await expect(page.getByRole("heading", { name: "Sofortmaßnahmen" })).toBeVisible();
  await page.fill("#description", "Klick auf Link in gefälschter Lieferanten-Mail.");
  await page.getByRole("button", { name: "Vorfall melden" }).click();
  await page.waitForURL(/\/app\/emergency\/[0-9a-f-]{36}/);
  await expect(page.getByText("Vorfall-Timeline")).toBeVisible();

  // 16: anderer Kunde kann diese Daten nicht sehen
  const otherCtx = await browser.newContext();
  const other = await otherCtx.newPage();
  await register(other, `e2e-other-${stamp}@example.org`);
  await other.fill("#name", `Andere GmbH ${stamp}`);
  await other.getByRole("button", { name: "Weiter" }).click();
  await other.waitForSelector("#domain");
  await other.goto(findingUrl.replace(/^https?:\/\/[^/]+/, ""));
  await expect(other.getByRole("heading", { name: "Seite nicht gefunden" })).toBeVisible();
  await otherCtx.close();
});

test("Anmeldung schützt geschützte Bereiche", async ({ page }) => {
  await page.goto("/app/findings");
  await expect(page).toHaveURL(/\/login\?next=%2Fapp%2Ffindings/);
  await page.fill("#email", "niemand@example.org");
  await page.fill("#password", "Falsch1234567");
  await page.getByRole("button", { name: "Anmelden" }).click();
  await expect(page.getByText("E-Mail-Adresse oder Passwort ist nicht korrekt.")).toBeVisible();
});

test("Öffentlicher Kurzcheck führt zur Registrierung", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Wissen Sie, welche Cyberrisiken/ })).toBeVisible();
  await page.getByPlaceholder("ihre-firma.de").first().fill("example.com");
  await page.getByLabel("Hinweis bestätigen").first().click();
  await page.getByRole("button", { name: /Kostenlosen Sicherheitscheck starten/ }).first().click();
  await page.waitForURL(/\/check\//);
  await drainJobs(2);
  await expect(page.getByTestId("public-check-result")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Was dieser Kurzcheck nicht abdeckt")).toBeVisible();
  await page.getByRole("link", { name: /Jetzt aktivieren/ }).click();
  await expect(page).toHaveURL(/\/register\?domain=example\.com/);
});

test("Demo-Modus ist klar gekennzeichnet und vom Kundenbetrieb getrennt", async ({ page }) => {
  await page.goto("/demo");
  await page.getByTestId("start-demo").click();
  await page.waitForURL("**/app");
  await expect(page.getByText(/DEMO-MODUS/)).toBeVisible();
  await page.goto("/app/findings");
  await page.locator('a[href^="/app/findings/"]').first().click();
  await expect(page.getByText("DEMO", { exact: true }).first()).toBeVisible();
  await page.getByRole("button", { name: "Erneut überprüfen" }).click();
  await expect(page.getByText(/Demo-Modus: Es werden keine echten Prüfungen/)).toBeVisible();
});

