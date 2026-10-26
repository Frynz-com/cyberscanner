import { expect, test } from "@playwright/test";

async function noHorizontalScroll(page: import("@playwright/test").Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
}

test("Landingpage ist mobil nutzbar", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Wissen Sie/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Kostenlosen Sicherheitscheck starten/ }).first()).toBeVisible();
  await noHorizontalScroll(page);
});

test("Dashboard, Befunde und Notfall sind mobil nutzbar (Demo)", async ({ page }) => {
  await page.goto("/demo");
  await page.getByTestId("start-demo").click();
  await page.waitForURL("**/app");
  for (const path of ["/app", "/app/findings", "/app/emergency", "/app/timeline", "/app/partners", "/app/assets"]) {
    await page.goto(path);
    await noHorizontalScroll(page);
  }
  await page.goto("/app");
  await page.getByRole("button", { name: "Menü öffnen" }).click();
  await page.getByRole("link", { name: "Befunde" }).click();
  await expect(page).toHaveURL(/\/app\/findings/);
});
