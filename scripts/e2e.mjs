// Headless end-to-end + accessibility smoke test for the built app.
// Boots the production preview, drives the real UI, and runs an axe scan in both themes.
// Self-contained: spawns `vite preview` itself unless E2E_URL points at a running server.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from 'playwright';
import { AxeBuilder } from '@axe-core/playwright';

const PORT = 4173;
const URL = process.env.E2E_URL ?? `http://localhost:${PORT}/crypto-lab-vrf-gate/`;

let server;
async function startServerIfNeeded() {
  if (process.env.E2E_URL) return; // an external server was provided
  server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--port', String(PORT), '--strictPort'], {
    stdio: 'ignore',
  });
  for (let i = 0; i < 60; i += 1) {
    try {
      const response = await fetch(URL);
      if (response.ok) return;
    } catch {
      // server not up yet
    }
    await sleep(500);
  }
  throw new Error('preview server did not start within 30s');
}
const failures = [];
const note = (ok, label) => {
  console.log(`  ${ok ? 'ok ' : 'FAIL'} ${label}`);
  if (!ok) failures.push(label);
};

async function textOf(page, selector) {
  return (await page.locator(selector).textContent())?.trim() ?? '';
}

async function runAxe(page, label) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  const serious = violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
  for (const v of violations) {
    const nodes = v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ');
    console.log(`     [${v.impact}] ${v.id}: ${v.help} -> ${nodes}`);
  }
  note(serious.length === 0, `axe (${label}): ${serious.length} serious/critical, ${violations.length} total`);
}

await startServerIfNeeded();

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const page = await context.newPage();

const consoleErrors = [];
page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${err.message}`));
page.on('console', (msg) => {
  if (msg.type() === 'error' && !/favicon/i.test(msg.text())) {
    consoleErrors.push(`console.error: ${msg.text()}`);
  }
});

try {
  await page.goto(URL, { waitUntil: 'networkidle' });

  // Boot must populate the VRF output and the live "see the math" trace.
  await page.waitForFunction(() => {
    const beta = document.querySelector('#vrf-beta')?.textContent ?? '';
    return beta && beta !== '—' && beta !== 'loading...';
  }, { timeout: 15000 });
  note(true, 'app boots and computes a VRF output');

  for (const id of ['#vrf-math-h', '#vrf-math-gamma', '#vrf-math-u', '#vrf-math-v', '#vrf-math-c', '#vrf-math-s', '#vrf-math-beta']) {
    note((await textOf(page, id)) !== '—', `trace populated: ${id}`);
  }
  note((await textOf(page, '#vrf-math-beta')) === (await textOf(page, '#vrf-beta')), 'trace beta equals output beta');

  // VRF verification should round-trip to VALID.
  await page.locator('#vrf-verify').click();
  await page.waitForFunction(() => /VALID/.test(document.querySelector('#vrf-verify-status')?.textContent ?? '') , { timeout: 10000 });
  note((await page.locator('#vrf-verify-status').getAttribute('data-tone')) === 'good', 'verify accepts the honest proof');

  // Tampering must be rejected.
  await page.locator('#vrf-tamper').click();
  await page.locator('#vrf-verify').click();
  await page.waitForFunction(() => (document.querySelector('#vrf-verify-status')?.getAttribute('data-tone')) === 'bad', { timeout: 10000 });
  note(true, 'verify rejects a tampered beta');

  // VDF evaluate + verify (toy delay, runs in a worker).
  await page.locator('#vdf-evaluate').click();
  await page.waitForFunction(() => (document.querySelector('#vdf-progress-text')?.textContent ?? '') === '100%', { timeout: 60000 });
  await page.locator('#vdf-verify').click();
  await page.waitForFunction(() => /VERIFIED/.test(document.querySelector('#vdf-verify-status')?.textContent ?? ''), { timeout: 20000 });
  note((await page.locator('#vdf-verify-status').getAttribute('data-tone')) === 'good', 'VDF evaluate + verify works');
  note((await textOf(page, '#vdf-math-r')) !== '—', 'VDF Wesolowski r is shown');

  // Accessibility — dark theme (default).
  await runAxe(page, 'dark');

  // Accessibility — light theme. The shared crypto-lab header hides the lab's
  // own #theme-toggle and exposes its own #cl-theme-toggle; both drive the same
  // documentElement[data-theme]. Click the visible header control.
  await page.locator('#cl-theme-toggle').click();
  await page.waitForFunction(() => document.documentElement.getAttribute('data-theme') === 'light', { timeout: 5000 });
  note(true, 'theme toggle switches to light');
  await runAxe(page, 'light');

  // Mobile viewport sanity: no horizontal overflow.
  await page.setViewportSize({ width: 360, height: 740 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  note(overflow <= 1, `no horizontal overflow at 360px (overflow=${overflow}px)`);

  note(consoleErrors.length === 0, `no console/page errors (${consoleErrors.length})`);
  consoleErrors.forEach((e) => console.log(`     ${e}`));
} catch (error) {
  console.error(error);
  failures.push(`exception: ${error.message}`);
} finally {
  await browser.close();
  server?.kill();
}

if (failures.length > 0) {
  console.log(`\ne2e FAILED: ${failures.length} issue(s)`);
  process.exitCode = 1;
} else {
  console.log('\ne2e + axe passed');
}
