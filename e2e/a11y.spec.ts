import { test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along the exhibits it teaches: both skip links focused, the
 * VDF verifier pressed before anything has been evaluated so its refusal is
 * painted, all four VRF verdicts (valid, retired, invalid, unparseable), the
 * producer readouts blanked back to em-dashes by editing α and then recomputed,
 * both branches of the α′ comparison, both "See the math" disclosures opened
 * through their summaries, the non-hex input error, the λ shortcut taken once
 * before and once after the squaring chain so both halves of its fork are
 * scanned, all six deployment disclosures opened one at a time from an
 * all-closed start, a withholding beacon round whose transient mid-round log
 * line is captured from inside the page, that round retired by moving a control,
 * and two honest rounds at different validator counts. Every one of those states
 * is scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
    // The baseline ratchet's third rule. `nonTextSeen` is module state and
    // `fullyParallel` gives every test its own worker, so each configuration
    // accumulates its own set and a single call site would ratchet only one of
    // the four. After `reportCollected()` so an `A11Y_COLLECT` run still throws
    // there first.
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
    expectBaselineNotStale();
  });
}
