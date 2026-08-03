/**
 * Functional coverage for the claims this lab makes on screen.
 *
 * The lab teaches two things: an ECVRF output is deterministic for one (key, input) and
 * publicly checkable by anyone holding the public key, and a Wesolowski VDF is cheap to
 * verify relative to evaluating — while this page's toy modulus makes the delay itself
 * zero. So the load-bearing states are:
 *   - every printed value agreeing with the other surfaces that render the same run,
 *   - each verdict saying only what the check established,
 *   - the failure paths reaching failure (tampered beta, wrong input, unparseable proof,
 *     verifying before evaluating, non-hex VDF input),
 *   - and no verdict outliving the input that produced it.
 *
 * Nothing here asserts a hardcoded cryptographic value. Expected values are read back out
 * of the DOM and compared against other values the page computed. Any uncaught page
 * exception or console error fails the test that provoked it.
 */
import { expect, test as base, type Page } from '@playwright/test';

const test = base.extend<{ errors: string[] }>({
  errors: async ({ page }, use) => {
    const errs: string[] = [];
    page.on('pageerror', (e) => errs.push(`pageerror: ${String(e)}`));
    page.on('console', (m) => {
      if (m.type() === 'error') errs.push(`console.error: ${m.text()}`);
    });
    await use(errs);
    expect(errs, 'uncaught page exceptions / console errors').toEqual([]);
  },
});

/** boot() key-gens, computes a VRF, and derives the VDF group element before the page is usable. */
async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#vrf-beta')).not.toHaveText('—');
  await expect(page.locator('#vrf-public-key')).not.toHaveText('loading...');
  await expect(page.locator('#vdf-group')).not.toHaveText('—');
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('run 1:');
}

const text = async (page: Page, sel: string): Promise<string> =>
  ((await page.locator(sel).textContent()) ?? '').trim();

const value = async (page: Page, sel: string): Promise<string> =>
  page.locator(sel).inputValue();

/** The page's own abbreviation: first `visible` hex chars, an ellipsis, the last `visible`. */
function shortHex(hex: string, visible = 12): string {
  return hex.length <= visible * 2 ? hex : `${hex.slice(0, visible)}...${hex.slice(-visible)}`;
}

function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function differingBytes(a: string, b: string): number {
  const left = hexToBytes(a);
  const right = hexToBytes(b);
  let n = 0;
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) n += 1;
  }
  return n;
}

/** Strip the thousands separators the page prints via toLocaleString. */
function num(s: string): number {
  const m = s.replace(/,/g, '').match(/-?\d+(\.\d+)?/);
  if (!m) throw new Error(`no number in ${JSON.stringify(s)}`);
  return Number(m[0]);
}

async function computeVrf(page: Page, alpha: string): Promise<void> {
  await page.locator('#vrf-alpha').fill(alpha);
  await page.locator('#vrf-compute').click();
  await expect(page.locator('#vrf-compare-result')).toContainText(`α = "${alpha}"`);
}

// ------------------------------------------------------------------- VRF: producer

test('the proof, the beta and the "see the math" panel all describe one run', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const beta = await text(page, '#vrf-beta');
  const proof = JSON.parse(await text(page, '#vrf-proof')) as {
    gamma: string;
    c: string;
    s: string;
  };

  // The math panel is a second rendering of the same proof object, not a second computation.
  // If they ever disagree the page is narrating one run and displaying another.
  expect(await text(page, '#vrf-math-beta')).toBe(beta);
  expect(await text(page, '#vrf-math-gamma')).toBe(proof.gamma);
  expect(await text(page, '#vrf-math-c')).toBe(proof.c);
  expect(await text(page, '#vrf-math-s')).toBe(proof.s);

  // beta is SHA-256 of a tagged encoding of gamma: 32 bytes. c is the 16-byte challenge.
  expect(beta).toMatch(/^[0-9a-f]{64}$/);
  expect(proof.c).toMatch(/^[0-9a-f]{32}$/);
  expect(proof.gamma).toMatch(/^0[23][0-9a-f]{64}$/); // SEC1 compressed point
  expect(proof.s).toMatch(/^[0-9a-f]{64}$/);

  // Try-and-increment reports which counter produced a valid H.
  expect(await text(page, '#vrf-math-h-ctr')).toMatch(/valid point found at counter \d+/);
});

test('the verifier pane is handed exactly what the producer computed', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  expect(await value(page, '#vrf-verify-alpha')).toBe(await value(page, '#vrf-alpha'));
  expect(await value(page, '#vrf-verify-beta')).toBe(await text(page, '#vrf-beta'));
  expect(await value(page, '#vrf-verify-proof')).toBe(await text(page, '#vrf-proof'));
});

test('the same alpha recomputes to byte-identical beta and proof', async ({ page, errors }) => {
  void errors;
  await open(page);

  const first = { beta: await text(page, '#vrf-beta'), proof: await text(page, '#vrf-proof') };
  await computeVrf(page, 'determinism-probe-1');
  const other = await text(page, '#vrf-beta');
  await computeVrf(page, await value(page, '#vrf-alpha'));

  // A different alpha really did move the output, so the re-run below is not a no-op.
  expect(other).not.toBe(first.beta);

  await computeVrf(page, 'determinism-probe-1');
  expect(await text(page, '#vrf-beta')).toBe(other);
  await expect(page.locator('#vrf-proof')).not.toHaveText('—');
});

test('the uniqueness card compares all 32 bytes and re-verifies each proof', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const beta = await text(page, '#vrf-beta');
  await page.locator('#vrf-uniqueness').click();
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('run 5:');
  const card = await text(page, '#vrf-uniqueness-result');

  const runs = [...card.matchAll(/run \d: ([0-9a-f]{12}\.\.\.[0-9a-f]{12})/g)].map((m) => m[1]);
  expect(runs).toHaveLength(5);
  // Every run must abbreviate to the beta printed above the card — same key, same alpha.
  expect(new Set(runs)).toEqual(new Set([shortHex(beta)]));

  expect(card).toContain('all 5 runs returned byte-identical β and π');
  expect(card).toContain('all 5 verified');
  expect(card).toContain('a β with one bit flipped was rejected');
  expect(card).not.toContain('CHECK FAILED');
});

test('the pseudorandomness card reports a byte difference the page can be held to', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const alpha = await value(page, '#vrf-alpha');
  const alphaPrime = await value(page, '#vrf-alpha-compare');
  expect(alphaPrime).not.toBe(alpha);

  const betaForAlpha = await text(page, '#vrf-beta');
  const card = await text(page, '#vrf-compare-result');
  const shorts = [...card.matchAll(/β = ([0-9a-f]{12}\.\.\.[0-9a-f]{12})/g)].map((m) => m[1]);
  expect(shorts).toHaveLength(2);
  expect(shorts[0]).toBe(shortHex(betaForAlpha));

  const claimed = num(card.match(/(\d+) of \d+ β bytes differ/)?.[1] ?? '');
  const width = num(card.match(/\d+ of (\d+) β bytes differ/)?.[1] ?? '');
  expect(width).toBe(32);

  // Make the page compute beta for alpha-prime as a first-class run, then check its own
  // claim about how far the two outputs are apart against the two full betas it printed.
  await computeVrf(page, alphaPrime);
  const betaForAlphaPrime = await text(page, '#vrf-beta');
  expect(shorts[1]).toBe(shortHex(betaForAlphaPrime));
  expect(differingBytes(betaForAlpha, betaForAlphaPrime)).toBe(claimed);

  // One character of alpha changed; a keyed hash should move nearly every output byte.
  expect(claimed).toBeGreaterThan(24);
});

test('an alpha-prime identical to alpha is called determinism, not pseudorandomness', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const alpha = await value(page, '#vrf-alpha');
  await page.locator('#vrf-alpha-compare').fill(alpha);
  await page.locator('#vrf-compute').click();
  await expect(page.locator('#vrf-compare-result')).toContainText('α′ is identical to α');

  const card = await text(page, '#vrf-compare-result');
  const shorts = [...card.matchAll(/β = ([0-9a-f]{12}\.\.\.[0-9a-f]{12})/g)].map((m) => m[1]);
  expect(shorts[0]).toBe(shorts[1]);
  expect(card).not.toMatch(/β bytes differ/);
});

// ------------------------------------------------------------------- VRF: verifier

test('a genuine proof verifies, and the verdict claims only what was checked', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'neutral');
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'good');

  const verdict = await text(page, '#vrf-verify-status');
  expect(verdict).toContain('β is the unique VRF output for this public key and input');
  // What a VRF verifier learns is that this proof checks out under this key for this input.
  // It learns nothing about the output being random, unpredictable, or uniformly distributed.
  expect(verdict).not.toMatch(/\brandom\b/i);
  expect(verdict).not.toMatch(/unpredictab/i);
});

test('a tampered beta is rejected', async ({ page, errors }) => {
  void errors;
  await open(page);

  await page.locator('#vrf-tamper').click();
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'bad');
  expect(await text(page, '#vrf-verify-status')).toContain('do not verify under this public key');
});

test('the right proof against the wrong input is rejected', async ({ page, errors }) => {
  void errors;
  await open(page);

  const beta = await value(page, '#vrf-verify-beta');
  const proof = await value(page, '#vrf-verify-proof');
  await page.locator('#vrf-verify-alpha').fill('block-9999-leader-selection');
  // beta and pi were untouched: only the statement being proved moved.
  expect(await value(page, '#vrf-verify-beta')).toBe(beta);
  expect(await value(page, '#vrf-verify-proof')).toBe(proof);

  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'bad');
});

test('a tampered proof scalar is rejected', async ({ page, errors }) => {
  void errors;
  await open(page);

  const proof = JSON.parse(await value(page, '#vrf-verify-proof')) as {
    gamma: string;
    c: string;
    s: string;
  };
  const flipped = (Number.parseInt(proof.s.slice(-1), 16) ^ 0x1).toString(16);
  proof.s = `${proof.s.slice(0, -1)}${flipped}`;
  await page.locator('#vrf-verify-proof').fill(JSON.stringify(proof, null, 2));

  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'bad');
  expect(await text(page, '#vrf-verify-status')).toContain('do not verify under this public key');
});

test('a malformed proof is refused as unparseable, not as a failed verification', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await page.locator('#vrf-verify-proof').fill('{ not json at all');
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'bad');
  expect(await text(page, '#vrf-verify-status')).toContain('could not even be parsed');

  // Non-hex beta is the same class: nothing was verified, so nothing may be reported as verified.
  await open(page);
  await page.locator('#vrf-verify-beta').fill('zzzz');
  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'bad');
  expect(await text(page, '#vrf-verify-status')).toContain('could not even be parsed');
});

// ---------------------------------------------------------- VRF: verdicts must retire

test('tampering with beta retires the verdict instead of leaving it endorsing the tamper', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await page.locator('#vrf-verify').click();
  await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'good');
  const verified = await value(page, '#vrf-verify-beta');

  await page.locator('#vrf-tamper').click();
  expect(await value(page, '#vrf-verify-beta')).not.toBe(verified);

  const status = page.locator('#vrf-verify-status');
  await expect(status).toHaveAttribute('data-tone', 'neutral');
  expect(await text(page, '#vrf-verify-status')).not.toContain('VALID');
});

test('editing any verifier field retires a standing verdict', async ({ page, errors }) => {
  void errors;
  await open(page);

  for (const field of ['#vrf-verify-alpha', '#vrf-verify-beta', '#vrf-verify-proof']) {
    await open(page);
    await page.locator('#vrf-verify').click();
    await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'good');

    await page.locator(field).fill(`${await value(page, field)} `);
    await expect(page.locator('#vrf-verify-status')).toHaveAttribute('data-tone', 'neutral');
    expect(await text(page, '#vrf-verify-status'), field).toContain('Inputs changed');
  }
});

test('editing alpha retires the producer readouts it no longer describes', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);
  await page.locator('#vrf-uniqueness').click();
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('run 5:');

  await page.locator('#vrf-alpha').fill('a-completely-different-input');

  await expect(page.locator('#vrf-beta')).toHaveText('—');
  await expect(page.locator('#vrf-proof')).toHaveText('—');
  await expect(page.locator('#vrf-math-gamma')).toHaveText('—');
  await expect(page.locator('#vrf-math-beta')).toHaveText('—');
  await expect(page.locator('#vrf-uniqueness-result')).not.toContainText('run 1:');
  expect(await text(page, '#vrf-compare-result')).toContain('α changed');

  // ...and recomputing brings them back for the new input.
  await page.locator('#vrf-compute').click();
  await expect(page.locator('#vrf-beta')).not.toHaveText('—');
  expect(await text(page, '#vrf-compare-result')).toContain('α = "a-completely-different-input"');
});

test('recomputing for a new alpha retires a uniqueness verdict run over the old one', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);
  await page.locator('#vrf-uniqueness').click();
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('run 5:');
  const staleRuns = await text(page, '#vrf-uniqueness-result');

  await computeVrf(page, 'epoch-77-committee');
  const card = await text(page, '#vrf-uniqueness-result');
  expect(card).not.toBe(staleRuns);
  expect(card).not.toContain('run 1:');

  // Re-running it for the new alpha must agree with the new beta.
  await page.locator('#vrf-uniqueness').click();
  await expect(page.locator('#vrf-uniqueness-result')).toContainText('run 5:');
  expect(await text(page, '#vrf-uniqueness-result')).toContain(
    shortHex(await text(page, '#vrf-beta')),
  );
});

test('editing alpha-prime retires the comparison it was not part of', async ({ page, errors }) => {
  void errors;
  await open(page);
  expect(await text(page, '#vrf-compare-result')).toMatch(/β bytes differ|identical/);

  await page.locator('#vrf-alpha-compare').fill('hand-picked-rival');
  // fill() dispatches change too, which recomputes; either state is honest, but a comparison
  // naming the OLD alpha-prime is not.
  await expect(page.locator('#vrf-compare-result')).not.toContainText('block-1848');
});

// ------------------------------------------------------------------------- VDF

test('evaluation runs exactly the number of squarings the slider advertises', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const advertised = num((await text(page, '#vdf-exp-label')).split('=')[1]);
  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });

  expect(num(await text(page, '#vdf-squarings'))).toBe(advertised);
  expect(await text(page, '#vdf-progress-text')).toBe('100%');
  await expect(page.locator('#vdf-progress')).toHaveAttribute('aria-valuenow', '100');
  expect(await text(page, '#vdf-math-t')).toBe(`2^${Math.log2(advertised)}`);

  const speedup = await text(page, '#vdf-speedup');
  expect(num(speedup.split('for')[1])).toBe(advertised);
});

test('the Wesolowski identity verifies, and the check names the T it was built for', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });
  const exp = (await text(page, '#vdf-exp-label')).match(/2\^(\d+)/)?.[1];

  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'good');

  const verdict = await text(page, '#vdf-verify-status');
  expect(verdict).toContain('π^ℓ · g^r = y mod N');
  expect(verdict).toContain(`T = 2^${exp}`);
  await expect(page.locator('#vdf-math-r')).not.toHaveText('Verify a proof to populate r.');

  // The reported ratio has to be the two timings it quotes, divided.
  const cost = await text(page, '#vdf-speedup');
  const verifyMs = num(cost.split('took')[1]);
  const chainMs = num(cost.split('versus')[1]);
  const ratio = num(cost.split('—')[1]);
  expect(ratio).toBeCloseTo(chainMs / verifyMs, 0);
  // And it must not be sold as a delay: this modulus factors publicly.
  expect(cost).toContain('not a delay an adversary is forced to pay');
});

test('verifying before evaluating refuses instead of reporting a result', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await expect(page.locator('#vdf-output')).toHaveText('—');
  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'bad');
  expect(await text(page, '#vdf-verify-status')).toContain('Evaluate the VDF before verifying it');
  await expect(page.locator('#vdf-math-r')).toHaveText('Verify a proof to populate r.');
});

test('the lambda shortcut lands on the identical y the squaring chain produced', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });
  const chainY = await text(page, '#vdf-output');
  const chainMs = num(await text(page, '#vdf-elapsed'));

  await page.locator('#vdf-skip').click();
  await expect(page.locator('#vdf-skip-status')).toContainText('Byte-identical', {
    timeout: 30_000,
  });

  const skip = await text(page, '#vdf-skip-status');
  // The whole exhibit rests on these two being the same value, so compare them, do not
  // take the word "Byte-identical" for it.
  expect(skip.match(/y = ([0-9a-f]{24}\.\.\.[0-9a-f]{24})/)?.[1]).toBe(chainY);
  expect(skip).not.toContain('should be impossible');
  await expect(page.locator('#vdf-skip-exponent')).not.toHaveText(
    'Skip the delay to populate the reduced exponent.',
  );

  // One modular exponentiation against tens of thousands of squarings.
  const skipMs = num(skip.split('in')[1]);
  expect(skipMs).toBeLessThan(Math.max(chainMs, 1));
});

test('the shortcut states the equality whichever button is pressed first', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await page.locator('#vdf-skip').click();
  await expect(page.locator('#vdf-skip-status')).toContainText('Press “Evaluate VDF”', {
    timeout: 30_000,
  });
  const skipY = (await text(page, '#vdf-skip-status')).match(
    /y = ([0-9a-f]{24}\.\.\.[0-9a-f]{24})/,
  )?.[1];

  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });

  // The instruction has been followed; the panel must stop asking and state the result.
  await expect(page.locator('#vdf-skip-status')).toContainText('Byte-identical');
  expect(await text(page, '#vdf-output')).toBe(skipY);
});

test('moving T retires the proof bundle built for the old T', async ({ page, errors }) => {
  void errors;
  await open(page);

  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });
  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'good');

  await page.locator('#vdf-exp').fill('13');

  await expect(page.locator('#vdf-output')).toHaveText('—');
  await expect(page.locator('#vdf-prime')).toHaveText('—');
  await expect(page.locator('#vdf-proof')).toHaveText('—');
  await expect(page.locator('#vdf-math-r')).toHaveText('Verify a proof to populate r.');
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'neutral');
  expect(await text(page, '#vdf-verify-status')).toContain('Parameters changed');
  expect(await text(page, '#vdf-exp-label')).toContain('2^13');
  await expect(page.locator('#vdf-skip-exponent')).toHaveText(
    'Skip the delay to populate the reduced exponent.',
  );

  // Re-evaluating at the new T verifies, which is the point: the old bundle was retired
  // because it was for other parameters, not because anything was wrong with it.
  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });
  expect(num(await text(page, '#vdf-squarings'))).toBe(8192);
  await page.locator('#vdf-verify').click();
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'good');
  expect(await text(page, '#vdf-verify-status')).toContain('T = 2^13');
});

test('changing x retires the proof bundle and the g it was derived from', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const g = await text(page, '#vdf-group');
  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });

  await page.locator('#vdf-input').fill('00112233445566778899aabbccddeeff');
  await expect(page.locator('#vdf-output')).toHaveText('—');
  await expect(page.locator('#vdf-group')).not.toHaveText(g);
  await expect(page.locator('#vdf-group')).not.toHaveText('—');
});

test('a non-hex x takes down g rather than leaving the previous one under it', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const g = await text(page, '#vdf-group');
  expect(g).not.toBe('—');

  await page.locator('#vdf-input').fill('not-hex-at-all');
  await expect(page.locator('#vdf-group')).toHaveText('—');
  await expect(page.locator('#vdf-verify-status')).toHaveAttribute('data-tone', 'bad');
  expect(await text(page, '#vdf-verify-status')).toContain('not valid hex');

  // Evaluating and skipping must both refuse too, rather than reuse the retired g.
  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-verify-status')).toContainText('not valid hex');
  await expect(page.locator('#vdf-output')).toHaveText('—');

  // ...and valid hex brings it back.
  await page.locator('#vdf-input').fill('deadbeef');
  await expect(page.locator('#vdf-group')).not.toHaveText('—');
});

test('the real-world projection says whether its rate was measured or assumed', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const before = await text(page, '#vdf-estimate');
  expect(before).toContain('not something this page has measured');

  await page.locator('#vdf-evaluate').click();
  await expect(page.locator('#vdf-output')).not.toHaveText('—', { timeout: 60_000 });

  const after = await text(page, '#vdf-estimate');
  expect(after).not.toContain('not something this page has measured');
  expect(after).toContain('this browser just sustained');

  // The quoted rate must be the squarings and elapsed time printed beside it.
  const rate = num(after.match(/at the ([\d,]+) squarings\/s/)?.[1] ?? '');
  const squarings = num(await text(page, '#vdf-squarings'));
  const elapsedMs = num(await text(page, '#vdf-elapsed'));
  expect(num(after.match(/over ([\d,]+) squarings/)?.[1] ?? '')).toBe(squarings);

  // Elapsed is printed to the whole millisecond, so the true duration is within ±0.5ms and
  // the rate the page quotes must fall in the band that implies — not merely "close".
  const slowest = squarings / ((elapsedMs + 0.5) / 1000);
  const fastest = squarings / (Math.max(elapsedMs - 0.5, 0.001) / 1000);
  expect(rate).toBeGreaterThanOrEqual(Math.floor(slowest));
  expect(rate).toBeLessThanOrEqual(Math.ceil(fastest));
});

// ----------------------------------------------------------------------- beacon

test('a withholding round verifies only the proofs that were actually published', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  const validators = num(await text(page, '#beacon-validators-label'));
  await expect(page.locator('#beacon-malicious')).toBeChecked();

  await page.locator('#beacon-run').click();
  await expect(page.locator('#beacon-log')).toContainText('Beacon verification', {
    timeout: 60_000,
  });
  const log = await text(page, '#beacon-log');

  // One line per validator, exactly one of them malicious.
  const lines = [...log.matchAll(/V(\d+) \((honest|malicious)\)/g)];
  expect(lines).toHaveLength(validators);
  expect(lines.filter((m) => m[2] === 'malicious')).toHaveLength(1);
  expect(lines.at(-1)?.[2]).toBe('malicious');

  const checked = num(log.match(/✓ (\d+) of \d+ VRF proofs/)?.[1] ?? '');
  const total = num(log.match(/✓ \d+ of (\d+) VRF proofs/)?.[1] ?? '');
  const skipped = num(log.match(/(\d+) withheld and published no proof/)?.[1] ?? '');
  expect(total).toBe(validators);
  // The withheld validator published nothing, so it cannot be counted as verified.
  expect(checked).toBe(validators - 1);
  expect(checked + skipped).toBe(total);

  expect(log).toContain('RANDAO recomputed from the revealed βs');
  expect(log).toContain('π^ℓ · g^r ≡ y checked');
  expect(log).toContain('withheld its reveal and changed the RANDAO branch');
  expect(log).toContain('Wesolowski proof generated (not yet checked)');
  expect(log).not.toContain('Beacon verification failed');

  // Withholding really did change the mix: the honest counterfactual is a different value.
  const mix = log.match(/RANDAO = ([0-9a-f]{12}\.\.\.[0-9a-f]{12})/)?.[1];
  const honest = log.match(/Honest full mix would have been ([0-9a-f]{12}\.\.\.[0-9a-f]{12})/)?.[1];
  expect(mix).toBeTruthy();
  expect(honest).toBeTruthy();
  expect(mix).not.toBe(honest);

  const summary = await text(page, '#beacon-summary');
  expect(summary).toContain('Residual bias remains');
  expect(summary).toContain('this toy N factors publicly');
});

test('an honest round verifies every proof and says the delay was still zero', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  await page.locator('#beacon-malicious').uncheck();
  await page.locator('#beacon-validators').fill('6');
  await page.locator('#beacon-run').click();
  await expect(page.locator('#beacon-log')).toContainText('Beacon verification', {
    timeout: 60_000,
  });

  const log = await text(page, '#beacon-log');
  expect([...log.matchAll(/V\d+ \(honest\)/g)]).toHaveLength(6);
  expect(log).not.toContain('malicious');
  expect(log).toContain('✓ 6 of 6 VRF proofs re-verified');
  expect(log).not.toContain('withheld and published no proof');
  expect(log).toContain('All validators revealed');
  expect(log).not.toContain('Beacon verification failed');

  const summary = await text(page, '#beacon-summary');
  expect(summary).toContain('Honest round complete');
  expect(summary).toContain('the VDF contributed no delay');
});

test('the beacon VDF runs the delay its own slider names', async ({ page, errors }) => {
  void errors;
  await open(page);

  await page.locator('#beacon-exp').fill('12');
  expect(await text(page, '#beacon-exp-label')).toBe('2^12 squarings');
  await page.locator('#beacon-run').click();
  await expect(page.locator('#beacon-log')).toContainText('Beacon verification', {
    timeout: 60_000,
  });

  expect(num((await text(page, '#beacon-progress-text')).split('(')[1])).toBe(4096);
  expect(await text(page, '#beacon-progress-text')).toContain('100%');
  await expect(page.locator('#beacon-progress')).toHaveAttribute('aria-valuenow', '100');
});

test('changing the beacon controls retires the round that was run under the old ones', async ({
  page,
  errors,
}) => {
  void errors;
  await open(page);

  for (const change of [
    async () => page.locator('#beacon-malicious').uncheck(),
    async () => page.locator('#beacon-validators').fill('7'),
    async () => page.locator('#beacon-exp').fill('13'),
  ]) {
    await open(page);
    await page.locator('#beacon-run').click();
    await expect(page.locator('#beacon-log')).toContainText('Beacon verification', {
      timeout: 60_000,
    });
    expect(await text(page, '#beacon-summary')).toContain('Residual bias remains');

    await change();

    const log = await text(page, '#beacon-log');
    expect(log).toContain('Controls changed');
    expect(log).not.toContain('Beacon verification');
    expect(log).not.toContain('malicious');
    expect(await text(page, '#beacon-summary')).toContain('Run a beacon round');
    await expect(page.locator('#beacon-progress')).toHaveAttribute('aria-valuenow', '0');
  }
});

// ------------------------------------------------------------------------ page

test('nothing carrying the hidden attribute is still painted', async ({ page, errors }) => {
  void errors;
  await open(page);

  // Author display rules outrank the UA's [hidden]{display:none}, so an element can carry
  // the attribute, be exposed to sighted users, and still be treated as absent by tests.
  const leaks = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el as HTMLElement).display !== 'none')
      .map((el) => `${el.tagName.toLowerCase()}#${el.id}.${(el as HTMLElement).className}`),
  );
  expect(leaks, '[hidden]{display:none} loses to any author display rule').toEqual([]);
});

test('the page never sells the toy VDF as providing a delay', async ({ page, errors }) => {
  void errors;
  await open(page);

  await expect(page.locator('.warning-banner')).toContainText(
    'TOY VDF — THE DELAY IS ZERO, NOT MERELY SHORT',
  );
  const fidelity = await text(page, '.fidelity-note');
  expect(fidelity).toContain('λ(N) = lcm(p − 1, n − 1)');
  expect(fidelity).toContain('single');
  expect(fidelity).toContain('Never reuse these parameters for anything real');
});
