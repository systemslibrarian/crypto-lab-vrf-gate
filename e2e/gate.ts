import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/** Exhibit 5 lists six real-world deployments, each behind its own `<details>`. */
export const DEPLOYMENT_COUNT = 6;

/**
 * The delay exponent the beacon is driven to for its first round: the slider's
 * maximum, both because the top of a control's range is a state worth painting
 * and because it gives the mid-round capture in `armMidRoundCapture` the widest
 * window the UI can offer. Even so, 2^18 squarings of a 512-bit modulus is only
 * about 64ms here, which is why that capture cannot be a round-trip measurement.
 */
export const BEACON_SLOW_EXP = 18;

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     pushed `*{opacity:1!important}` through `addStyleTag` before every scan,
 *     and force-opened every `<details>` and stripped every `[hidden]` from
 *     script. Both fabricate results. The opacity override handed axe the
 *     declared colour of `.cl-hero-sub` (which really paints at `opacity: .85`)
 *     and of every disabled button (`opacity: .6`); the forced reveal scanned a
 *     document with all six deployment disclosures and both "See the math"
 *     panels open at once, which no visitor can produce with a single click and
 *     which is not the layout any of them get.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and half this page is empty at first paint: `#beacon-log` has no
 *     children at all, `#vdf-output`, `#vdf-prime`, `#vdf-proof` and the whole
 *     `#vdf-skip-exponent` card are em-dashes or "press this to populate me"
 *     placeholders, every `.status-pill` is in its neutral tone (the `good`,
 *     `bad` and `warn` palettes exist nowhere on screen), and five of the six
 *     deployment disclosures plus both `.math-reveal` panels are closed.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. Every
 * `.section-card` and the footer run `rise-in`, which starts at `opacity: 0`,
 * so this page is exactly that shape. It is safe for two independent reasons:
 * the reduced-motion block collapses the duration to 0.001ms rather than
 * setting `animation: none` (so the `both` fill still lands on the end state),
 * and it additionally re-states `opacity: 1; transform: none` for those three
 * selectors. This assertion is what keeps either of those from being deleted
 * silently.
 *
 * `aria-hidden` subtrees are excluded. That exclusion costs nothing on this
 * page today — the only `aria-hidden` nodes are the shared header's two SVG
 * marks, which contain no text — and `expectNoHiddenLiveOutput` asserts it
 * stays that way.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * No element carrying text may be `aria-hidden`.
 *
 * Both axe's `color-contrast` rule and the arithmetic oracle in `contrast.ts`
 * skip `aria-hidden` subtrees, so text hidden there is checked by nothing —
 * a shared blind spot that has hidden a 2.77:1 live value elsewhere in this
 * fleet. This page writes a great deal at runtime (`#beacon-log` is rebuilt
 * with `innerHTML` on every worker progress callback, and eighteen `<code>`
 * readouts are rewritten with `textContent`), so the cheapest guarantee is to
 * assert the exemption stays empty: today the only `aria-hidden` elements are
 * the header's hamburger and GitHub SVGs, and neither owns a character.
 */
export async function expectNoHiddenLiveOutput(page: Page, label: string): Promise<void> {
  const hidden = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[aria-hidden="true"]'))
      .filter((el) => (el.textContent ?? '').trim().length > 0)
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}` +
          `.${(el.getAttribute('class') ?? '').trim()} — "${(el.textContent ?? '').trim().slice(0, 40)}"`
      )
  );
  expect(hidden, `aria-hidden elements carrying text in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. An emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to:
 * this stylesheet's reduced-motion block is what collapses `rise-in` and the
 * progress-bar width transition, and `settle` would then be waiting on real
 * 540ms animations it believes are disabled.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is rendered by main.ts, then `boot()` key-gens a P-256 VRF
  // key, proves twice (alpha and alpha-prime), runs the five-way uniqueness
  // check and hashes the default VDF input to the group. None of the readouts
  // below exist until all of that lands.
  await expect(page.locator('main.page-shell')).toBeVisible();
  await expect(page.locator('#vrf-public-key')).not.toHaveText('loading...');
  await expect(page.locator('#vrf-beta')).not.toHaveText('—');
  await expect(page.locator('#vdf-group')).not.toHaveText('—');
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('run 1:');

  // The regions that carry the lab's claims do not exist here, which is the
  // whole reason `driveAllStates` exists.
  await expect(page.locator('#beacon-log')).toBeEmpty();
  await expect(page.locator('#vdf-output')).toHaveText('—');
  await expect(page.locator('#vdf-proof')).toHaveText('—');
  await expect(page.locator('#vdf-skip-exponent')).toContainText('Skip the delay to populate');
  await expect(page.locator('.status-pill[data-tone="good"]')).toHaveCount(0);
  await expect(page.locator('.status-pill[data-tone="bad"]')).toHaveCount(0);
  await expect(page.locator('.status-pill[data-tone="warn"]')).toHaveCount(0);
  await expect(page.locator('.math-reveal[open]')).toHaveCount(0);
  await expect(page.locator('details.deployment-card[open]')).toHaveCount(1);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex readouts and a pretty-printed
 * JSON proof, lays five exhibits on two- and three-column grids above 768px,
 * and carries a comparison table with `min-width: 420px` — wider than the
 * 380px viewport this runs at. That table is the reason `.comparison-wrap`
 * exists as an `overflow-x: auto` scroller, and the reason this helper has to
 * distinguish a real culprit from a clipped one.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has exactly that decoy in
    // `.comparison-table` inside `.comparison-wrap`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Assert a revealed element is wholly on screen and wholly unclipped.
 *
 * Neither axe nor the contrast oracle has anything to say about this, and both
 * are content to measure a box whose right-hand third is not painted. The
 * oracle is pointed at the blocks that only exist after driving and that each
 * carry a value a reader has to be able to read in full: the verifier's verdict
 * pill, the reduced exponent the λ shortcut prints, and the Wesolowski identity
 * inside the VDF disclosure. All three sit several boxes deep — `.section-card`
 * > `.split-pane` > `.pane-card` > `.metric-grid` > `.metric-card` — beside two
 * deliberate `overflow` scrollers, so an `overflow` added one level up would cut
 * them without failing any other assertion here.
 */
export async function expectNotClipped(page: Page, selector: string, label: string): Promise<void> {
  // Measure the settled frame, the same one `scan` measures.
  await settle(page);
  const cut = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return `no element matched ${sel}`;
    const b = el.getBoundingClientRect();
    if (b.width <= 0 || b.height <= 0) return `${sel} has an empty box`;
    const out: string[] = [];
    if (b.left < -0.5 || b.right > window.innerWidth + 0.5) {
      out.push(
        `outside the viewport (${Math.round(b.left)}..${Math.round(b.right)} of ${window.innerWidth})`
      );
    }
    for (let n = el.parentElement; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (!/auto|scroll|hidden|clip/.test(cs.overflowX + ' ' + cs.overflowY)) continue;
      const c = n.getBoundingClientRect();
      const lost =
        Math.max(0, c.left - b.left) +
        Math.max(0, b.right - c.right) +
        Math.max(0, c.top - b.top) +
        Math.max(0, b.bottom - c.bottom);
      if (lost > 0.5) {
        out.push(
          `${Math.round(lost)}px clipped by ${n.tagName.toLowerCase()}` +
            `${n.id ? '#' + n.id : ''}.${(n.getAttribute('class') ?? '').trim()}`
        );
      }
    }
    return out.length ? out.join('; ') : null;
  }, selector);
  expect(cut, `${selector} must be fully painted in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints a banner and fails at the
 * end, so a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every surface on the page is translucent over a gradient and axe declines
 *    to resolve essentially all of them. Everything else in that bucket is a
 *    real result axe simply could not finish — including `aria-prohibited-attr`,
 *    which is where an `aria-label` on a role-less `<code>` hides, a defect that
 *    never reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  await expectNoHiddenLiveOutput(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

interface LogLineStyle {
  color: string;
  opacity: string;
  fontSize: string;
  fontWeight: string;
  background: string;
  text: string;
}

/**
 * Catch the beacon's mid-round log line, which no scan can be timed to hit.
 *
 * While the beacon's VDF runs, `runBeaconDemo` renders one extra line —
 * `VDF progress: N% after M squarings (…ms elapsed)` — into `#beacon-log` on
 * every worker progress callback. That line is NOT part of the array written
 * when the round finishes, so it exists only while the worker is busy. It is a
 * real state: it is the only feedback the log gives during the longest wait the
 * page has.
 *
 * It is also unmeasurable by a scan, and the honest thing is to say why rather
 * than to write an assertion that passes by luck. At 2^18 squarings — the
 * beacon slider's maximum, which the gate sets before pressing Run — the whole
 * chain is about 64ms on current hardware. That is shorter than the pair of
 * Playwright round-trips a `toHaveCount` + `auditContrast` + `toHaveCount`
 * sandwich costs, so an earlier version of this helper measured the line when
 * the machine was loaded and missed it when it was not. A sometimes-measured
 * assertion is worse than none.
 *
 * So the window is taken out of the equation: a MutationObserver installed
 * BEFORE the click resolves in the same task as the first progress render and
 * captures the line's computed ink and its container's computed background
 * right there. The caller then compares that against a line from the settled
 * round. If they match, the settled scan — which runs the full arithmetic
 * oracle over `#beacon-log p` on the same surface — has already measured this
 * text's colours, and the transient frame introduces no pair of colours the
 * gate has not judged. The day someone gives the progress line a class, an
 * inline style or its own tone, this stops matching and the state has to be
 * dealt with properly.
 */
export async function armMidRoundCapture(page: Page): Promise<void> {
  await page.evaluate(() => {
    const w = window as unknown as { __midRound?: Promise<unknown> };
    const log = document.querySelector('#beacon-log');
    if (!log) throw new Error('#beacon-log is missing');
    w.__midRound = new Promise((resolve) => {
      const snapshot = (): boolean => {
        const line = Array.from(log.querySelectorAll('p')).find((p) =>
          (p.textContent ?? '').startsWith('VDF progress:')
        );
        if (!line) return false;
        const cs = getComputedStyle(line);
        resolve({
          color: cs.color,
          opacity: cs.opacity,
          fontSize: cs.fontSize,
          fontWeight: cs.fontWeight,
          background: getComputedStyle(log).backgroundColor,
          text: (line.textContent ?? '').slice(0, 60),
        });
        observer.disconnect();
        return true;
      };
      const observer = new MutationObserver(snapshot);
      observer.observe(log, { childList: true, subtree: true, characterData: true });
      snapshot();
    });
  });
}

/** Await the armed capture. Fails on the default 20s timeout if it never fires. */
export async function readMidRoundCapture(page: Page): Promise<LogLineStyle> {
  return page.evaluate(
    () => (window as unknown as { __midRound: Promise<LogLineStyle> }).__midRound
  ) as Promise<LogLineStyle>;
}

/** The same measurements, taken from a line of the settled round. */
export async function settledLogLineStyle(page: Page): Promise<LogLineStyle> {
  return page.evaluate(() => {
    const log = document.querySelector('#beacon-log');
    if (!log) throw new Error('#beacon-log is missing');
    const line = log.querySelector('p');
    if (!line) throw new Error('the settled beacon log has no lines');
    const cs = getComputedStyle(line);
    return {
      color: cs.color,
      opacity: cs.opacity,
      fontSize: cs.fontSize,
      fontWeight: cs.fontWeight,
      background: getComputedStyle(log).backgroundColor,
      text: (line.textContent ?? '').slice(0, 60),
    };
  });
}

/** Type into a field firing only `input`, so `change` handlers stay unfired. */
async function typeWithoutBlur(page: Page, selector: string, text: string): Promise<void> {
  const field = page.locator(selector);
  await field.click();
  await field.press('ControlOrMeta+a');
  await field.pressSequentially(text);
}

/**
 * Move a range slider with the arrow keys — the way a keyboard user does.
 *
 * `fill()` is not an option on `input[type=range]`, and setting `.value` from
 * script fires no `input` event at all, so the three sliders' listeners (which
 * are what retire a stale proof bundle or a stale beacon round) would never
 * run. Driving the real key events also puts each slider through its
 * `:focus-visible` rendering, which is a painted state of its own.
 */
async function setSlider(page: Page, selector: string, target: number): Promise<void> {
  const slider = page.locator(selector);
  await slider.focus();
  const start = Number(await slider.inputValue());
  const key = target > start ? 'ArrowRight' : 'ArrowLeft';
  for (let i = 0; i < Math.abs(target - start); i++) await slider.press(key);
  expect(Number(await slider.inputValue()), `${selector} must reach ${target}`).toBe(target);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The order is forced by the page's own prerequisites:
 *
 *   - the VDF verifier must be pressed BEFORE anything is evaluated, because
 *     `verifyCurrentVdf` reads `appState.vdf.result` and its "Evaluate the VDF
 *     before verifying it" refusal is unreachable once a result exists;
 *   - the λ shortcut must be pressed once BEFORE and once AFTER an evaluation,
 *     because `renderVdfShortcutStatus` forks on whether a squaring chain with
 *     the same (g, T) is on screen, and the two branches print different text
 *     in different tones;
 *   - editing α must come after the verifier states, because
 *     `retireVrfProducerReadout` blanks β, π and the whole math trace back to
 *     em-dashes, and the verifier fields are repopulated only by a recompute;
 *   - the beacon's "controls changed" retirement can only be reached from a
 *     finished round, so a round has to be run first.
 *
 * Four things are deliberately NOT driven. They are recorded here so the next
 * reader does not add a click that can only hang — this repo has already
 * produced one mutation that looked inert because it landed in a branch no
 * visitor can reach:
 *
 *   - `skipVdfDelay`'s two null returns, and the
 *     "The λ shortcut does not apply to these parameters" pill they produce.
 *     The first fires when `params.N !== TOY_P * TOY_Q`, and `currentVdfParams`
 *     spreads `TOY_PARAMS` on every call, so N is that product on every code
 *     path the UI has. The second fires when `gcd(g, N) !== 1`, and g is
 *     `ensurePositiveGroupElement(SHA-256(x))` — hitting a multiple of either
 *     256-bit prime factor is a ~2^-255 event. That pill is unreachable.
 *   - the "CHECK FAILED — β agree: false…" uniqueness verdict, the
 *     "It does NOT match the chain's output, which should be impossible" pill,
 *     and "Beacon verification failed". All three are internal-consistency
 *     alarms: they fire only if ECVRF or Wesolowski is broken in this build, in
 *     which case `claims.spec.ts` fails first and much louder.
 *   - the `<h1>Initialization failed</h1>` screen, which replaces `#app`
 *     wholesale if `boot()` rejects. Reaching it needs WebCrypto or the module
 *     graph to fail, not a click.
 *   - the lab's own `#theme-toggle`. The shared header sets
 *     `display: none !important` on it and exposes `#cl-theme-toggle` instead,
 *     so it is in the DOM (its click handler is what `initThemeToggle` binds)
 *     but paints nothing and is out of the accessibility tree. The header
 *     toggle IS driven, at the end of the run.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint');

  // ── Both skip links ───────────────────────────────────────────────────────
  // Each parks off-screen until focused, so the focused rendering is the only
  // one that paints — and they are two different pairs of colours, the header's
  // fixed `#0b1512` on `#eafff8` and the lab's themed `--text` on
  // `--panel-strong`.
  await page.locator('a.cl-skip-link').focus();
  await scanAt('header skip link focused');
  await page.locator('a.skip-link').focus();
  await scanAt('lab skip link focused');

  // ── Exhibit 2's verifier, before anything has been evaluated ──────────────
  // A prerequisite refusal: this is the only route to it.
  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toHaveText('Evaluate the VDF before verifying it.');
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'bad');
  await scanAt('VDF verify pressed before evaluating (refusal)');

  // ── Exhibit 1: the verifier's three verdicts ──────────────────────────────
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toContainText('✓ VALID');
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'good');
  await expectNotClipped(page, '#vrf-verify-status', `${theme} / VRF verdict VALID`);
  await scanAt('VRF verdict: VALID');

  // Tampering rewrites β in the verifier and retires the standing verdict, so
  // the neutral "inputs changed" pill is a state of its own.
  await page.locator('#vrf-tamper').click();
  await expect(page.locator('#vrf-verify-status')).toContainText('Inputs changed');
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'neutral');
  await scanAt('VRF verdict retired after tampering');

  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toContainText('✗ INVALID');
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'bad');
  await scanAt('VRF verdict: INVALID (tampered β)');

  // The other failure path: a proof that cannot even be parsed. Different text,
  // same tone, and the only state where the verdict is an exception message.
  await page.locator('#vrf-verify-proof').fill('{ not json');
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toContainText('could not even be parsed');
  await scanAt('VRF verdict: unparseable proof');

  // ── Exhibit 1: the producer's retired (placeholder) state ─────────────────
  // Editing α blanks β, π and all six math-trace readouts back to em-dashes.
  // This is the only state in which those eight `<code>` elements hold a
  // placeholder rather than 64 characters of hex, and it is reachable by typing.
  await typeWithoutBlur(page, '#vrf-alpha', 'block-1848-committee-sampling');
  await expect(page.locator('#vrf-beta')).toHaveText('—');
  await expect(page.locator('#vrf-math-gamma')).toHaveText('—');
  await expect(page.locator('#vrf-compare-result')).toContainText('α changed');
  await scanAt('VRF producer readouts retired after editing α');

  await page.locator('#vrf-compute').click();
  await expect(page.locator('#vrf-beta')).not.toHaveText('—');
  await expect(page.locator('#vrf-compare-result')).toContainText('β bytes differ');
  await scanAt('VRF recomputed for the edited α');

  // ── Exhibit 1: both branches of the α′ comparison ─────────────────────────
  // Typing without blurring reaches the "press Compute" interstitial; blurring
  // fires `change`, which recomputes.
  await typeWithoutBlur(page, '#vrf-alpha-compare', 'block-1848-committee-sampling');
  await expect(page.locator('#vrf-compare-result')).toContainText('α′ changed');
  await scanAt("α′ edited, comparison awaiting recompute");

  await page.locator('#vrf-alpha').focus();
  await expect(page.locator('#vrf-compare-result')).toContainText('α′ is identical to α');
  await scanAt("α′ identical to α — determinism branch");

  await page.locator('#vrf-uniqueness').click();
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('all 5 runs returned');
  await scanAt('uniqueness check re-run');

  // ── Exhibit 1: the math disclosure ────────────────────────────────────────
  // Opened through its <summary>, the route a reader has, not by setting .open.
  await page.locator('#exhibit-vrf .math-reveal > summary').click();
  await expect(page.locator('#exhibit-vrf .math-reveal')).toHaveAttribute('open', '');
  await expect(page.locator('#vrf-math-h')).not.toHaveText('—');
  await expect(page.locator('#vrf-math-h-ctr')).toContainText('valid point found at counter');
  await scanAt('VRF "see the math" disclosure open');

  // ── Exhibit 2: the non-hex input error ────────────────────────────────────
  await page.locator('#vdf-input').fill('not-hex');
  await expect(page.locator('#vdf-verify-status')).toContainText('not valid hex');
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'bad');
  await expect(page.locator('#vdf-group')).toHaveText('—');
  await scanAt('VDF input is not hex (error state)');

  // Back to a usable x, and down to the cheapest delay the slider offers so the
  // chain below finishes without the gate having to wait on 65,536 squarings in
  // four configurations.
  await page.locator('#vdf-input').fill('a3f1'.repeat(16));
  await expect(page.locator('#vdf-group')).not.toHaveText('—');
  await setSlider(page, '#vdf-exp', 12);
  await expect(page.locator('#vdf-exp-label')).toHaveText('2^12 = 4,096 squarings');
  await expect(page.locator('#vdf-verify-status')).toContainText('Parameters changed');
  await scanAt('VDF parameters changed, proof bundle retired');

  // ── Exhibit 2: the λ shortcut, both branches ──────────────────────────────
  // No chain on screen yet: the pill asks for one.
  await page.locator('#vdf-skip').click();
  await expect(page.locator('#vdf-skip-status')).toContainText('Press “Evaluate VDF”');
  await expect(page.locator('#vdf-skip-status')).toHaveAttribute('data-tone', 'warn');
  await expect(page.locator('#vdf-skip-exponent')).not.toContainText('Skip the delay to populate');
  await expectNotClipped(page, '#vdf-skip-exponent', `${theme} / λ shortcut exponent`);
  await scanAt('λ shortcut taken before the chain is run');

  // Now the chain, which makes the shortcut pill state the equality instead.
  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-progress-text')).toHaveText('100%');
  await expect(page.locator('#vdf-output')).not.toHaveText('—');
  await expect(page.locator('#vdf-skip-status')).toContainText('Byte-identical to the');
  await scanAt('VDF chain evaluated; shortcut matches it byte for byte');

  // ── Exhibit 2: the math disclosure, before and after r is populated ───────
  await page.locator('#exhibit-vdf .math-reveal > summary').click();
  await expect(page.locator('#exhibit-vdf .math-reveal')).toHaveAttribute('open', '');
  await expect(page.locator('#vdf-math-r')).toHaveText('Verify a proof to populate r.');
  await expectNotClipped(page, '.math-equation', `${theme} / Wesolowski identity`);
  await scanAt('VDF "see the math" open, r still a placeholder');

  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toContainText('✓ VERIFIED');
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'good');
  await expect(page.locator('#vdf-math-r')).not.toHaveText('Verify a proof to populate r.');
  await scanAt('VDF proof verified; r populated');

  // ── Exhibit 5: every deployment disclosure ────────────────────────────────
  // One is open at first paint; close it so the all-closed state is scanned
  // too, then open each in turn.
  await page.locator('.deployment-card').first().locator('summary').click();
  await expect(page.locator('details.deployment-card[open]')).toHaveCount(0);
  await scanAt('all deployment disclosures closed');

  for (let i = 0; i < DEPLOYMENT_COUNT; i++) {
    const card = page.locator('details.deployment-card').nth(i);
    await card.locator('summary').click();
    await expect(card).toHaveAttribute('open', '');
    await expect(card.locator('p.tiny-note')).toBeVisible();
    await scanAt(`deployment disclosure ${i + 1} of ${DEPLOYMENT_COUNT} open`);
  }

  // ── Exhibit 4: a full beacon round with a withholding validator ───────────
  // The delay is pushed to the slider's maximum first, purely so the mid-round
  // log line below has a window wide enough to measure on a fast machine.
  await setSlider(page, '#beacon-exp', BEACON_SLOW_EXP);
  await expect(page.locator('#beacon-exp-label')).toHaveText(`2^${BEACON_SLOW_EXP} squarings`);
  await expect(page.locator('#beacon-malicious')).toBeChecked();
  // Armed before the click, so the observer cannot miss the first render.
  await armMidRoundCapture(page);
  await page.locator('#beacon-run').click();
  const midRound = await readMidRoundCapture(page);
  await expect(page.locator('#beacon-summary')).toContainText('Residual bias remains');
  await expect(page.locator('#beacon-log p', { hasText: 'Beacon verification: ✓' })).toHaveCount(1);
  await expect(page.locator('#beacon-progress-text')).toContainText('100%');
  await expectNotClipped(page, '#beacon-log', `${theme} / beacon round complete`);
  await scanAt('beacon round complete, malicious validator withheld');

  // The transient progress line and the settled lines have to be the same ink
  // on the same surface, because the scan above is what measures them. See
  // `armMidRoundCapture`.
  const { text: midText, ...midStyle } = midRound;
  const { text: settledText, ...settledStyle } = await settledLogLineStyle(page);
  expect(midText, 'the captured line must be the mid-round one').toContain('VDF progress:');
  expect(settledText, 'the settled log must not still show a progress line').not.toContain(
    'VDF progress:'
  );
  expect(
    midStyle,
    `mid-round beacon log line must be painted exactly like the settled ones: ${theme}`
  ).toEqual(settledStyle);

  // Changing a control retires the round — the log is replaced by a single
  // "controls changed" line and the summary returns to its idle paragraph.
  await page.locator('#beacon-malicious').uncheck();
  await expect(page.locator('#beacon-log p')).toHaveCount(1);
  await expect(page.locator('#beacon-log')).toContainText('Controls changed');
  await expect(page.locator('#beacon-summary')).toContainText('Run a beacon round');
  await scanAt('beacon round retired after a control moved');

  // The honest branch: every validator reveals, so the summary is the other
  // paragraph and the log has no "withheld" line.
  await setSlider(page, '#beacon-exp', 12);
  await page.locator('#beacon-run').click();
  await expect(page.locator('#beacon-summary')).toContainText('Honest round complete');
  await expect(page.locator('#beacon-log p', { hasText: 'withheld its reveal' })).toHaveCount(0);
  await scanAt('beacon round complete, all validators honest');

  // The validator slider retires it as well; drive it so a broken listener
  // fails here rather than leaving a stale round on screen.
  await setSlider(page, '#beacon-validators', 7);
  await expect(page.locator('#beacon-validators-label')).toHaveText('7 validators');
  await expect(page.locator('#beacon-log')).toContainText('Controls changed');
  await page.locator('#beacon-run').click();
  await expect(page.locator('#beacon-summary')).toContainText('Honest round complete');
  await expect(page.locator('#beacon-log p', { hasText: 'V7 (honest)' })).toHaveCount(1);
  await scanAt('beacon round with seven validators');

  // ── The theme toggle ──────────────────────────────────────────────────────
  // The header control is the visible one. Flipping it repaints every token on
  // a page that is now fully driven, which is a different rendering from the
  // opposite configuration's first paint.
  const other = theme.startsWith('dark') ? 'light' : 'dark';
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', other);
  await scanAt(`toggled to ${other} with every exhibit driven`);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    theme.startsWith('dark') ? 'dark' : 'light'
  );
}
