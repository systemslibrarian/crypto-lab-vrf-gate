import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the VRF + VDF crypto lab.
 *
 * The app is a single-page demo (main.ts renders VRF, VDF, beacon, and
 * deployment sections). Several output regions (proof bytes, verification
 * status pills, VDF proof bundle, the beacon log, math-reveal <details>) are
 * only populated after a "run/compute/verify" button fires. So we DRIVE every
 * live demo, expand ALL <details>, and neutralize motion, then run an axe scan
 * covering WCAG 2.0/2.1 A + AA in both themes; assert zero violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states (spinner,
// progress fade) can't hide text from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Force every <details> open and reveal any [hidden] region so axe scans the
// whole page (math-reveal panels and deployment cards are collapsed by default).
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Drive every live demo so injected/updated output regions exist during the
// scan (VRF proof + verification, VDF proof bundle, beacon round log).
async function driveDemos(page: Page): Promise<void> {
  // VRF: compute, uniqueness check, then verify a real proof.
  await page.locator('#vrf-compute').click();
  await expect(page.locator('#vrf-beta')).not.toHaveText('—', { timeout: 30_000 });
  await page.locator('#vrf-uniqueness').click();
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toBeVisible();
  // Tamper then re-verify so the "bad" status tone is painted.
  await page.locator('#vrf-tamper').click();
  await page.locator('#vrf-verify').click();

  // VDF: evaluate (worker squarings) then verify the Wesolowski proof.
  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });
  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toBeVisible();

  // Beacon: run a full round so the log region fills.
  await page.locator('#beacon-run').click();
  await expect(page.locator('#beacon-log')).not.toBeEmpty({ timeout: 60_000 });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  // App is rendered by main.ts; wait for the shared header toggle + first demo.
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#vrf-compute')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all demos driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (all demos driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
