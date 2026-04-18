import './style.css';

import {
  commitPhase,
  initBeaconRound,
  revealPhase,
  verifyBeaconRound,
  type BeaconRound,
} from './beacon.js';
import {
  proofToHash,
  vrfKeyGen,
  vrfProve,
  vrfVerify,
  type VRFKeyPair,
  type VRFOutput,
  type VRFProof,
} from './ecvrf.js';
import {
  bigintToBytes,
  bytesToHex,
  concatBytes,
  equalBytes,
  hexToBytes,
  utf8ToBytes,
  xorBytes,
} from './utils/bytes.js';
import {
  TOY_PARAMS,
  estimateVDFTime,
  hashToGroup,
  vdfEval,
  vdfProve,
  vdfVerify,
  type VDFParams,
  type VDFResult,
} from './vdf.js';

interface AppState {
  vrf: {
    keyPair: VRFKeyPair | null;
    output: VRFOutput | null;
    uniquenessRuns: string[];
    comparison: { current: string; changed: string } | null;
  };
  vdf: {
    inputHex: string;
    groupElement: bigint | null;
    result: VDFResult | null;
    verifyMs: number | null;
    progress: number;
    squarings: number;
    elapsedMs: number;
    etaMs: number;
  };
  beacon: {
    round: BeaconRound | null;
    logLines: string[];
    progress: number;
    squarings: number;
    summary: string;
  };
}

const problemAttempts = [
  {
    title: 'Attempt 1: block.timestamp',
    body: 'Validators can move timestamps within a permitted range and pick favorable outcomes.',
    attack: 'Grinding timestamps until the lottery or leader election looks profitable.',
  },
  {
    title: 'Attempt 2: future blockhash',
    body: 'A miner who owns that block can discard an unfavorable block and try again.',
    attack: 'Grinding future block production when the reward is worth more than the discarded block.',
  },
  {
    title: 'Attempt 3: commit-reveal',
    body: 'The last revealer sees everyone else first and can choose not to reveal.',
    attack: 'Last-reveal bias: abstain when the XOR output is not the one you wanted.',
  },
];

const deploymentCards = [
  {
    title: 'Ethereum RANDAO + VDF',
    detail:
      'RANDAO is live for validator shuffling and committee selection. VDF integration remains an active engineering effort rather than a completed mainnet primitive.',
    note: 'Use: beacon-chain randomness. Status: RANDAO deployed, VDF research and integration ongoing.',
  },
  {
    title: 'Chainlink VRF v2',
    detail:
      'An on-chain verifiable randomness service built on similar principles to ECVRF, used for NFT mints, games, lotteries, and betting markets across multiple chains.',
    note: 'Use: verifiable request-response randomness. Not this exact ciphersuite.',
  },
  {
    title: 'Filecoin Leader Election',
    detail:
      'Storage providers run VRFs over epoch data to determine whether they won the right to propose a block in a given round.',
    note: 'Use: leader election proportional to storage power.',
  },
  {
    title: 'Cardano Ouroboros',
    detail:
      'Cardano uses VRFs to determine slot leadership and committee assignments with deterministic verifiability.',
    note: 'Use: slot leader selection. RFC 9381-standardized VRF family relevance is direct here.',
  },
  {
    title: 'Algorand',
    detail:
      'Participants privately determine if they are selected, revealing the proof only when selected, reducing targeted denial-of-service risk.',
    note: 'Use: private committee sampling with later reveal.',
  },
  {
    title: 'drand',
    detail:
      'A distributed randomness beacon based on threshold cryptography rather than VRFs or VDFs, useful as a contrast point for public randomness design.',
    note: 'Use: public beacon consumed by Filecoin and others.',
  },
];

const appState: AppState = {
  vrf: {
    keyPair: null,
    output: null,
    uniquenessRuns: [],
    comparison: null,
  },
  vdf: {
    inputHex: '',
    groupElement: null,
    result: null,
    verifyMs: null,
    progress: 0,
    squarings: 0,
    elapsedMs: 0,
    etaMs: 0,
  },
  beacon: {
    round: null,
    logLines: [],
    progress: 0,
    squarings: 0,
    summary: 'Run a beacon round to see how withholding changes the RANDAO mix and why the VDF still blocks selective prediction.',
  },
};

const appRoot = document.querySelector<HTMLDivElement>('#app');

if (!appRoot) {
  throw new Error('App root not found');
}

const app = appRoot;

function shortHex(value: Uint8Array | bigint | null, visible = 12): string {
  if (value === null) {
    return '—';
  }

  const hex = typeof value === 'bigint' ? value.toString(16) : bytesToHex(value);

  if (hex.length <= visible * 2) {
    return hex;
  }

  return `${hex.slice(0, visible)}...${hex.slice(-visible)}`;
}

function requireElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);

  if (!element) {
    throw new Error(`Missing element: ${selector}`);
  }

  return element;
}

function setStatus(element: HTMLElement, text: string, tone: 'neutral' | 'good' | 'bad' | 'warn'): void {
  element.textContent = text;
  element.dataset.tone = tone;
}

function serializeProof(proof: VRFProof): string {
  return JSON.stringify(
    {
      gamma: bytesToHex(proof.gamma),
      c: bytesToHex(proof.c),
      s: bytesToHex(proof.s),
    },
    null,
    2,
  );
}

function parseProof(text: string): VRFProof {
  const parsed = JSON.parse(text) as { gamma: string; c: string; s: string };

  return {
    gamma: hexToBytes(parsed.gamma),
    c: hexToBytes(parsed.c),
    s: hexToBytes(parsed.s),
  };
}

async function sha256Bytes(...parts: Uint8Array[]): Promise<Uint8Array> {
  const merged = concatBytes(...parts);
  const copy = new Uint8Array(merged.length);
  copy.set(merged);
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer);
  return new Uint8Array(digest);
}

function currentVdfParams(explicitExp?: number): VDFParams {
  const exponent = explicitExp ?? Number(requireElement<HTMLInputElement>('#vdf-exp').value);

  return {
    ...TOY_PARAMS,
    T_exp: exponent,
    T: 1 << exponent,
  };
}

function renderApp(): void {
  app.innerHTML = `
    <main class="page-shell">
      <header class="hero-panel">
        <div class="hero-copy">
          <p class="kicker">crypto-lab-vrf-gate</p>
          <h1>VRFs and VDFs: Provable Randomness in Time</h1>
          <p class="hero-text">
            A browser lab for deterministic public-key randomness, sequential time-locks, and why
            blockchains need both when the cost of bias is high.
          </p>
          <div class="hero-ribbon">
            <span class="badge beta">VRF: sealed output</span>
            <span class="badge proof">VDF: elapsed time proof</span>
            <span class="badge valid">No fake math</span>
          </div>
        </div>
        <div class="hero-ornament" aria-hidden="true">
          <div class="clock-face">
            <span class="clock-core"></span>
            <span class="clock-hand clock-hand-hour"></span>
            <span class="clock-hand clock-hand-minute"></span>
          </div>
          <div class="seal-stack">
            <div class="seal-card">
              <span class="seal-title">Verifier</span>
              <span class="seal-stamp">✓ public proof</span>
            </div>
            <div class="seal-card offset">
              <span class="seal-title">Producer</span>
              <span class="seal-stamp">sk → β, π</span>
            </div>
          </div>
        </div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle dark and light theme">☀️</button>
      </header>

      <section class="section-card split-pane" id="exhibit-vrf">
        <div class="section-heading">
          <p class="section-index">Exhibit 1</p>
          <h2>What Is a VRF? The Public-Key Hash</h2>
          <p>
            The output is deterministic for the same secret key and input, yet publicly verifiable by
            anyone holding only the public key.
          </p>
        </div>
        <div class="vrf-grid">
          <article class="pane-card producer-card">
            <div class="pane-header">
              <span class="pane-label">Producer</span>
              <span class="tiny-note">Only the keyholder can compute the proof</span>
            </div>
            <div class="field-group">
              <label for="vrf-alpha">Input α</label>
              <input id="vrf-alpha" type="text" value="block-1847-leader-selection" />
            </div>
            <div class="info-strip">
              <div>
                <span class="strip-label">Secret key</span>
                <strong>sk = ●●●●●●●●</strong>
              </div>
              <div>
                <span class="strip-label">Public key</span>
                <code id="vrf-public-key" class="proof-bytes" role="code" aria-label="VRF public key bytes">loading...</code>
              </div>
            </div>
            <div class="button-row">
              <button id="vrf-compute" type="button">Compute VRF Output</button>
              <button id="vrf-uniqueness" class="ghost-button" type="button">Run 5× Uniqueness</button>
            </div>
            <div class="result-panel">
              <div>
                <span class="strip-label">Output β</span>
                <code id="vrf-beta" class="proof-bytes beta-text" role="code" aria-label="VRF output beta">—</code>
              </div>
              <div>
                <span class="strip-label">Proof π</span>
                <pre id="vrf-proof" class="proof-box proof-text" role="code" aria-label="VRF proof bytes">—</pre>
              </div>
            </div>
            <div class="property-grid">
              <article class="property-card">
                <h3>Uniqueness</h3>
                <p id="vrf-uniqueness-result">Run the deterministic check to compare five proofs.</p>
              </article>
              <article class="property-card">
                <h3>Pseudorandomness</h3>
                <p id="vrf-compare-result">Change α and compare outputs that look unrelated to the eye.</p>
              </article>
            </div>
          </article>

          <article class="pane-card verifier-card">
            <div class="pane-header">
              <span class="pane-label">Verifier</span>
              <span class="tiny-note">Anyone with the public key can check the proof</span>
            </div>
            <div class="field-group">
              <label for="vrf-verify-alpha">Input α</label>
              <input id="vrf-verify-alpha" type="text" />
            </div>
            <div class="field-group">
              <label for="vrf-verify-beta">Beta β</label>
              <textarea id="vrf-verify-beta" rows="3"></textarea>
            </div>
            <div class="field-group">
              <label for="vrf-verify-proof">Proof π</label>
              <textarea id="vrf-verify-proof" rows="7"></textarea>
            </div>
            <div class="button-row">
              <button id="vrf-verify" type="button">Verify</button>
              <button id="vrf-tamper" class="ghost-button" type="button">Tamper with β</button>
            </div>
            <p id="vrf-verify-status" class="status-pill" data-tone="neutral">Verification status is waiting for a proof.</p>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-vdf">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 2</p>
          <h2>What Is a VDF? The Time-Lock</h2>
          <p>
            Evaluation requires real sequential squarings. Verification checks a proof that is far
            cheaper than replaying the whole delay.
          </p>
        </div>
        <div class="split-pane vdf-layout">
          <article class="pane-card vdf-card">
            <p class="warning-banner">TOY VDF — NOT PRODUCTION SECURE</p>
            <div class="field-group">
              <label for="vdf-input">Input x (hex)</label>
              <textarea id="vdf-input" rows="3"></textarea>
            </div>
            <div class="slider-row">
              <label for="vdf-exp">Delay T</label>
              <input id="vdf-exp" type="range" min="12" max="18" value="16" />
              <span id="vdf-exp-label">2^16 = 65,536 squarings</span>
            </div>
            <div class="metric-grid">
              <div class="metric-card">
                <span class="strip-label">Toy modulus N</span>
                <code id="vdf-modulus" class="proof-bytes" role="code" aria-label="Toy VDF modulus">—</code>
              </div>
              <div class="metric-card">
                <span class="strip-label">g = H(x) mod N</span>
                <code id="vdf-group" class="proof-bytes" role="code" aria-label="VDF group element">—</code>
              </div>
            </div>
            <div class="button-row">
              <button id="vdf-evaluate" type="button">Evaluate VDF</button>
              <button id="vdf-verify" class="ghost-button" type="button">Verify Proof</button>
            </div>
            <div class="progress-block">
              <div class="progress-headline">
                <span>Progress</span>
                <strong id="vdf-progress-text">0%</strong>
              </div>
              <div id="vdf-progress" class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                <span class="progress-fill amber-fill"></span>
              </div>
              <div class="metric-grid timing-grid">
                <div class="metric-card">
                  <span class="strip-label">Elapsed</span>
                  <strong id="vdf-elapsed">0 ms</strong>
                </div>
                <div class="metric-card">
                  <span class="strip-label">ETA</span>
                  <strong id="vdf-eta">—</strong>
                </div>
                <div class="metric-card">
                  <span class="strip-label">Squarings</span>
                  <strong id="vdf-squarings">0</strong>
                </div>
              </div>
            </div>
          </article>

          <article class="pane-card proof-card">
            <div class="metric-grid">
              <div class="metric-card">
                <span class="strip-label">Result y</span>
                <code id="vdf-output" class="proof-bytes beta-text" role="code" aria-label="VDF output">—</code>
              </div>
              <div class="metric-card">
                <span class="strip-label">Prime ℓ</span>
                <code id="vdf-prime" class="proof-bytes proof-text" role="code" aria-label="VDF Wesolowski prime">—</code>
              </div>
              <div class="metric-card wide">
                <span class="strip-label">Proof π</span>
                <code id="vdf-proof" class="proof-bytes proof-text" role="code" aria-label="VDF proof value">—</code>
              </div>
            </div>
            <p id="vdf-verify-status" class="status-pill" data-tone="neutral">Evaluate the VDF to produce a proof bundle.</p>
            <div class="timing-callouts">
              <div class="callout-card">
                <h3>Measured in this browser</h3>
                <p id="vdf-speedup">Verification will report its speedup after a proof is checked.</p>
              </div>
              <div class="callout-card">
                <h3>Real-world scaling</h3>
                <p id="vdf-estimate"></p>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-problem">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 3</p>
          <h2>The Blockchain Randomness Problem</h2>
          <p>Bias enters any protocol where a validator can still choose after partial information is revealed.</p>
        </div>
        <div class="attempt-grid">
          ${problemAttempts
            .map(
              (attempt) => `
                <article class="attempt-card">
                  <h3>${attempt.title}</h3>
                  <p>${attempt.body}</p>
                  <p class="attack-note">Attack: ${attempt.attack}</p>
                </article>
              `,
            )
            .join('')}
        </div>
        <div class="timeline-grid">
          <article class="timeline-card danger">
            <h3>Commit-reveal without VDF</h3>
            <pre class="timeline-block">Round: Block 100
Validators commit hashes.

Round: Block 101 reveal
A reveals r_A.
B reveals r_B.
C sees the partial XOR and asks:
  reveal -> final_1
  withhold -> final_2

If C dislikes final_1, C withholds.
Result: the final randomness is biased.</pre>
          </article>
          <article class="timeline-card good">
            <h3>RANDAO followed by VDF</h3>
            <pre class="timeline-block">Reveal closes.
RANDAO mix is fixed.

Now the attacker still has a binary choice,
but cannot know which branch gives the preferred
future outcome without evaluating the VDF first.

The delay turns strategic choice into blind choice.</pre>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-beacon">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 4</p>
          <h2>Live Beacon Simulation</h2>
          <p>Simulate validators, VRF commitments, withholding, RANDAO mixing, and the delayed VDF output.</p>
        </div>
        <div class="split-pane beacon-layout">
          <article class="pane-card beacon-controls">
            <div class="slider-row">
              <label for="beacon-validators">Validators</label>
              <input id="beacon-validators" type="range" min="3" max="8" value="4" />
              <span id="beacon-validators-label">4 validators</span>
            </div>
            <div class="slider-row">
              <label for="beacon-exp">VDF delay</label>
              <input id="beacon-exp" type="range" min="12" max="18" value="14" />
              <span id="beacon-exp-label">2^14 squarings</span>
            </div>
            <label class="switch-row" for="beacon-malicious">
              <span>Add malicious validator</span>
              <input id="beacon-malicious" type="checkbox" checked />
            </label>
            <button id="beacon-run" type="button">Run Full Beacon Round</button>
            <div class="progress-block compact-progress">
              <div class="progress-headline">
                <span>Beacon VDF</span>
                <strong id="beacon-progress-text">0%</strong>
              </div>
              <div id="beacon-progress" class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                <span class="progress-fill green-fill"></span>
              </div>
            </div>
            <p id="beacon-summary" class="summary-copy">${appState.beacon.summary}</p>
          </article>
          <article class="pane-card beacon-log-card">
            <div class="log-heading">
              <h3>Epoch 42 Randomness Beacon</h3>
              <span class="tiny-note">aria-live log for the current round</span>
            </div>
            <div id="beacon-log" class="beacon-log" aria-live="polite"></div>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-deployments">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 5</p>
          <h2>Real-World Deployments</h2>
          <p>VRFs and VDF-adjacent randomness beacons already shape production consensus, lotteries, and validator selection.</p>
        </div>
        <div class="deployment-grid">
          ${deploymentCards
            .map(
              (card, index) => `
                <details class="deployment-card" ${index === 0 ? 'open' : ''}>
                  <summary>${index + 1}. ${card.title}</summary>
                  <p>${card.detail}</p>
                  <p class="tiny-note">${card.note}</p>
                </details>
              `,
            )
            .join('')}
        </div>
        <div class="comparison-wrap">
          <table class="comparison-table">
            <thead>
              <tr>
                <th>Property</th>
                <th>VRF</th>
                <th>VDF</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Key required?</td><td>Yes</td><td>No</td></tr>
              <tr><td>Deterministic output?</td><td>Yes</td><td>Yes</td></tr>
              <tr><td>Verifiable?</td><td>Yes</td><td>Yes</td></tr>
              <tr><td>Unpredictable without secret?</td><td>Yes</td><td>Only after T sequential steps</td></tr>
              <tr><td>Sequential computation?</td><td>No</td><td>Yes</td></tr>
              <tr><td>Resists last-reveal alone?</td><td>Partially</td><td>Helps by delaying prediction</td></tr>
              <tr><td>Post-quantum secure?</td><td>No</td><td>No</td></tr>
            </tbody>
          </table>
        </div>
        <article class="post-quantum-note">
          <h3>Post-Quantum Caveat</h3>
          <p>
            Neither construction shown here is post-quantum secure. P-256 and RSA-style groups are both
            vulnerable to Shor's algorithm. Post-quantum VRFs exist only as emerging designs, and
            post-quantum VDFs remain an open research problem as of 2026.
          </p>
        </article>
      </section>

      <footer>
        <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God." — 1 Corinthians 10:31</p>
      </footer>
    </main>
  `;
}

function syncThemeToggle(): void {
  const currentTheme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  requireElement<HTMLButtonElement>('#theme-toggle').textContent = currentTheme === 'dark' ? '☀️' : '🌙';
}

function updateVdfProgress(progress: number, squarings: number, elapsedMs: number, etaMs: number): void {
  const progressTrack = requireElement<HTMLElement>('#vdf-progress');
  const progressFill = requireElement<HTMLElement>('#vdf-progress .progress-fill');
  const progressText = requireElement<HTMLElement>('#vdf-progress-text');
  progressTrack.setAttribute('aria-valuenow', String(progress));
  progressFill.style.width = `${progress}%`;
  progressText.textContent = `${progress}%`;
  requireElement<HTMLElement>('#vdf-squarings').textContent = squarings.toLocaleString();
  requireElement<HTMLElement>('#vdf-elapsed').textContent = `${elapsedMs.toFixed(0)} ms`;
  requireElement<HTMLElement>('#vdf-eta').textContent = etaMs > 0 ? `${etaMs.toFixed(0)} ms` : '—';
}

function updateBeaconProgress(progress: number, squarings: number): void {
  const progressTrack = requireElement<HTMLElement>('#beacon-progress');
  const progressFill = requireElement<HTMLElement>('#beacon-progress .progress-fill');
  progressTrack.setAttribute('aria-valuenow', String(progress));
  progressFill.style.width = `${progress}%`;
  requireElement<HTMLElement>('#beacon-progress-text').textContent = `${progress}% (${squarings.toLocaleString()} sq)`;
}

function writeBeaconLog(lines: string[]): void {
  const log = requireElement<HTMLElement>('#beacon-log');
  log.innerHTML = lines.map((line) => `<p>${line}</p>`).join('');
}

async function populateVrfForAlpha(alphaText: string): Promise<void> {
  const keyPair = appState.vrf.keyPair;

  if (!keyPair) {
    return;
  }

  const alpha = utf8ToBytes(alphaText);
  const output = await vrfProve(keyPair, alpha);
  const comparisonAlpha = utf8ToBytes('block-1848-leader-selection');
  const changedOutput = await vrfProve(keyPair, comparisonAlpha);

  appState.vrf.output = output;
  appState.vrf.comparison = {
    current: shortHex(output.beta),
    changed: shortHex(changedOutput.beta),
  };

  requireElement<HTMLElement>('#vrf-public-key').textContent = bytesToHex(keyPair.publicKeyBytes);
  requireElement<HTMLElement>('#vrf-beta').textContent = bytesToHex(output.beta);
  requireElement<HTMLElement>('#vrf-proof').textContent = serializeProof(output.proof);
  requireElement<HTMLInputElement>('#vrf-verify-alpha').value = alphaText;
  requireElement<HTMLTextAreaElement>('#vrf-verify-beta').value = bytesToHex(output.beta);
  requireElement<HTMLTextAreaElement>('#vrf-verify-proof').value = serializeProof(output.proof);
  requireElement<HTMLElement>('#vrf-compare-result').textContent =
    `α = "${alphaText}" -> β = ${shortHex(output.beta)}; α = "block-1848-leader-selection" -> β = ${shortHex(changedOutput.beta)}.`;
  setStatus(requireElement<HTMLElement>('#vrf-verify-status'), 'Verification status is waiting for a proof.', 'neutral');
}

async function runVrfUniquenessDemo(): Promise<void> {
  const keyPair = appState.vrf.keyPair;
  const alphaText = requireElement<HTMLInputElement>('#vrf-alpha').value;

  if (!keyPair) {
    return;
  }

  const alpha = utf8ToBytes(alphaText);
  const runs = await Promise.all(Array.from({ length: 5 }, async () => vrfProve(keyPair, alpha)));
  appState.vrf.uniquenessRuns = runs.map((entry, index) => `run ${index + 1}: ${shortHex(entry.beta)}`);
  requireElement<HTMLElement>('#vrf-uniqueness-result').textContent = appState.vrf.uniquenessRuns.join(' • ');
}

async function verifyCurrentVrf(): Promise<void> {
  const keyPair = appState.vrf.keyPair;

  if (!keyPair) {
    return;
  }

  try {
    const alpha = utf8ToBytes(requireElement<HTMLInputElement>('#vrf-verify-alpha').value);
    const beta = hexToBytes(requireElement<HTMLTextAreaElement>('#vrf-verify-beta').value);
    const proof = parseProof(requireElement<HTMLTextAreaElement>('#vrf-verify-proof').value);
    const verification = await vrfVerify(keyPair.publicKeyBytes, alpha, { alpha, beta, proof });

    if (verification.valid) {
      setStatus(
        requireElement<HTMLElement>('#vrf-verify-status'),
        '✓ VALID — β is the unique VRF output for this public key and input.',
        'good',
      );
      return;
    }

    setStatus(requireElement<HTMLElement>('#vrf-verify-status'), '✗ INVALID — the proof or beta has been modified.', 'bad');
  } catch (error) {
    setStatus(
      requireElement<HTMLElement>('#vrf-verify-status'),
      `✗ INVALID — ${(error as Error).message}`,
      'bad',
    );
  }
}

async function refreshVdfDerivedState(): Promise<void> {
  const inputElement = requireElement<HTMLTextAreaElement>('#vdf-input');
  const params = currentVdfParams();
  const inputBytes = hexToBytes(inputElement.value);
  const groupElement = await hashToGroup(inputBytes, params.N);

  appState.vdf.inputHex = inputElement.value;
  appState.vdf.groupElement = groupElement;
  requireElement<HTMLElement>('#vdf-modulus').textContent = shortHex(params.N, 20);
  requireElement<HTMLElement>('#vdf-group').textContent = shortHex(groupElement, 20);
  requireElement<HTMLElement>('#vdf-exp-label').textContent = `2^${params.T_exp} = ${params.T.toLocaleString()} squarings`;

  const toyEstimate = estimateVDFTime(params.T);
  const longer = estimateVDFTime(1 << 20);
  const epochScale = estimateVDFTime(1 << 25);
  requireElement<HTMLElement>('#vdf-estimate').textContent =
    `Toy estimate at ${params.T.toLocaleString()} squarings: ${toyEstimate.seconds.toFixed(2)}s if the machine sustains 1M squarings/s. Real RSA-2048 VDFs are much slower. At 2^20 squarings that same back-of-envelope rate is ${longer.seconds.toFixed(2)}s, and at 2^25 it is ${epochScale.hours.toFixed(2)}h before accounting for the larger modulus cost.`;
}

async function runVdfDemo(): Promise<void> {
  const evaluateButton = requireElement<HTMLButtonElement>('#vdf-evaluate');
  evaluateButton.disabled = true;

  try {
    await refreshVdfDerivedState();

    if (appState.vdf.groupElement === null) {
      throw new Error('VDF group element is unavailable');
    }

    const params = currentVdfParams();
    const started = performance.now();
    updateVdfProgress(0, 0, 0, 0);
    const evaluation = await vdfEval(appState.vdf.groupElement, params, (pct, squarings) => {
      const elapsedMs = performance.now() - started;
      const etaMs = squarings > 0 ? (elapsedMs / squarings) * (params.T - squarings) : 0;
      updateVdfProgress(pct, squarings, elapsedMs, etaMs);
      appState.vdf.progress = pct;
      appState.vdf.squarings = squarings;
      appState.vdf.elapsedMs = elapsedMs;
      appState.vdf.etaMs = etaMs;
    });
    const proofBundle = await vdfProve(appState.vdf.groupElement, evaluation.y, params);

    appState.vdf.result = {
      input: appState.vdf.groupElement,
      output: evaluation.y,
      proof: proofBundle.proof,
      prime: proofBundle.prime,
      steps: evaluation.squarings,
      timeMs: evaluation.timeMs,
    };
    appState.vdf.verifyMs = null;
    updateVdfProgress(100, evaluation.squarings, evaluation.timeMs, 0);
    requireElement<HTMLElement>('#vdf-output').textContent = shortHex(evaluation.y, 24);
    requireElement<HTMLElement>('#vdf-prime').textContent = shortHex(proofBundle.prime, 24);
    requireElement<HTMLElement>('#vdf-proof').textContent = shortHex(proofBundle.proof, 24);
    setStatus(
      requireElement<HTMLElement>('#vdf-verify-status'),
      `VDF output computed in ${evaluation.timeMs.toFixed(0)}ms. Verify the proof to compare costs.`,
      'warn',
    );
    requireElement<HTMLElement>('#vdf-speedup').textContent =
      `Evaluation took ${evaluation.timeMs.toFixed(0)}ms for ${evaluation.squarings.toLocaleString()} sequential squarings.`;
  } catch (error) {
    setStatus(requireElement<HTMLElement>('#vdf-verify-status'), (error as Error).message, 'bad');
  } finally {
    evaluateButton.disabled = false;
  }
}

async function verifyCurrentVdf(): Promise<void> {
  const result = appState.vdf.result;

  if (!result) {
    setStatus(requireElement<HTMLElement>('#vdf-verify-status'), 'Evaluate the VDF before verifying it.', 'bad');
    return;
  }

  const params = currentVdfParams();
  const started = performance.now();
  const valid = await vdfVerify(result.input, result.output, result.proof, params);
  const verifyMs = performance.now() - started;
  appState.vdf.verifyMs = verifyMs;

  if (valid) {
    const speedup = result.timeMs / Math.max(verifyMs, 0.001);
    setStatus(
      requireElement<HTMLElement>('#vdf-verify-status'),
      `✓ VERIFIED in ${verifyMs.toFixed(2)}ms using the simplified Wesolowski check π^ℓ · g^r = y mod N.`,
      'good',
    );
    requireElement<HTMLElement>('#vdf-speedup').textContent =
      `Verification took ${verifyMs.toFixed(2)}ms versus ${result.timeMs.toFixed(0)}ms to evaluate. Observed speedup: ${speedup.toFixed(1)}×.`;
    return;
  }

  setStatus(requireElement<HTMLElement>('#vdf-verify-status'), '✗ INVALID — the VDF proof did not verify.', 'bad');
}

async function sha256BigInt(value: bigint): Promise<Uint8Array> {
  return sha256Bytes(bigintToBytes(value));
}

function allValidatorBetas(round: BeaconRound): Uint8Array[] {
  return round.validators
    .map((validator) => validator.vrfOutput?.beta)
    .filter((beta): beta is Uint8Array => beta instanceof Uint8Array);
}

async function runBeaconDemo(): Promise<void> {
  const runButton = requireElement<HTMLButtonElement>('#beacon-run');
  runButton.disabled = true;
  appState.beacon.logLines = [];
  updateBeaconProgress(0, 0);

  try {
    const validatorCount = Number(requireElement<HTMLInputElement>('#beacon-validators').value);
    const exp = Number(requireElement<HTMLInputElement>('#beacon-exp').value);
    const malicious = requireElement<HTMLInputElement>('#beacon-malicious').checked;
    const params = currentVdfParams(exp);
    const round = await initBeaconRound(validatorCount, utf8ToBytes('epoch-42'));
    appState.beacon.round = round;
    appState.beacon.logLines.push('Phase 1 — VRF Computation');
    await commitPhase(round);

    for (const validator of round.validators) {
      appState.beacon.logLines.push(
        `${validator.id} (${malicious && validator.id === round.validators.at(-1)?.id ? 'malicious' : 'honest'}): β = ${shortHex(validator.vrfOutput?.beta ?? null)}`,
      );
    }

    const withheldIds = malicious && round.validators.length > 0 ? [round.validators[round.validators.length - 1].id] : [];
    appState.beacon.logLines.push('Phase 2 — Reveal and RANDAO');
    await revealPhase(round, withheldIds);
    const fullMix = xorBytes(allValidatorBetas(round));
    appState.beacon.logLines.push(`RANDAO = ${shortHex(round.randaoMix ?? null)}`);

    if (withheldIds.length > 0) {
      appState.beacon.logLines.push(`${withheldIds[0]} withheld its reveal and changed the RANDAO branch.`);
      appState.beacon.logLines.push(`Honest full mix would have been ${shortHex(fullMix)}.`);
    } else {
      appState.beacon.logLines.push('All validators revealed, so the RANDAO mix uses every VRF contribution.');
    }

    appState.beacon.logLines.push('Phase 3 — VDF');
    writeBeaconLog(appState.beacon.logLines);
    const vdfInput = await hashToGroup(round.randaoMix ?? fullMix, params.N);
    const started = performance.now();
    const evaluation = await vdfEval(vdfInput, params, (pct, squarings) => {
      appState.beacon.progress = pct;
      appState.beacon.squarings = squarings;
      updateBeaconProgress(pct, squarings);
      writeBeaconLog([
        ...appState.beacon.logLines,
        `VDF progress: ${pct}% after ${squarings.toLocaleString()} squarings (${(performance.now() - started).toFixed(0)}ms elapsed).`,
      ]);
    });
    const proofBundle = await vdfProve(vdfInput, evaluation.y, params);
    round.vdfResult = {
      input: vdfInput,
      output: evaluation.y,
      proof: proofBundle.proof,
      prime: proofBundle.prime,
      steps: evaluation.squarings,
      timeMs: evaluation.timeMs,
    };
    round.finalRandomness = await sha256BigInt(evaluation.y);

    appState.beacon.logLines.push(`y = ${shortHex(evaluation.y)} (computed in ${evaluation.timeMs.toFixed(0)}ms)`);
    appState.beacon.logLines.push(`Proof π verified input: ℓ = ${shortHex(proofBundle.prime)}`);
    appState.beacon.logLines.push(`Final randomness = SHA-256(y) = ${shortHex(round.finalRandomness)}`);

    const verification = await verifyBeaconRound(round, params);
    appState.beacon.logLines.push(
      verification.valid
        ? 'Beacon verification: ✓ all VRF proofs, RANDAO, and VDF checks passed.'
        : `Beacon verification failed: ${verification.failures.join('; ')}`,
    );
    appState.beacon.summary = malicious
      ? 'Residual bias remains: a malicious validator still chooses whether to reveal, but the VDF prevents them from knowing which branch they prefer before the delay completes.'
      : 'Honest round complete: the final randomness is the VDF-delayed output of the fully revealed RANDAO mix.';
    requireElement<HTMLElement>('#beacon-summary').textContent = appState.beacon.summary;
    writeBeaconLog(appState.beacon.logLines);
    updateBeaconProgress(100, evaluation.squarings);
  } catch (error) {
    appState.beacon.summary = (error as Error).message;
    requireElement<HTMLElement>('#beacon-summary').textContent = appState.beacon.summary;
    appState.beacon.logLines.push(`Error: ${(error as Error).message}`);
    writeBeaconLog(appState.beacon.logLines);
  } finally {
    runButton.disabled = false;
  }
}

function bindThemeToggle(): void {
  const button = requireElement<HTMLButtonElement>('#theme-toggle');
  syncThemeToggle();
  button.addEventListener('click', () => {
    const nextTheme = (document.documentElement.getAttribute('data-theme') ?? 'dark') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('cv-theme', nextTheme);
    syncThemeToggle();
  });
}

function bindControls(): void {
  requireElement<HTMLButtonElement>('#vrf-compute').addEventListener('click', async () => {
    await populateVrfForAlpha(requireElement<HTMLInputElement>('#vrf-alpha').value);
  });
  requireElement<HTMLButtonElement>('#vrf-uniqueness').addEventListener('click', async () => {
    await runVrfUniquenessDemo();
  });
  requireElement<HTMLButtonElement>('#vrf-verify').addEventListener('click', async () => {
    await verifyCurrentVrf();
  });
  requireElement<HTMLButtonElement>('#vrf-tamper').addEventListener('click', () => {
    const betaField = requireElement<HTMLTextAreaElement>('#vrf-verify-beta');

    try {
      const beta = hexToBytes(betaField.value);
      beta[0] ^= 0x01;
      betaField.value = bytesToHex(beta);
    } catch {
      betaField.value = '00';
    }
  });
  requireElement<HTMLTextAreaElement>('#vdf-input').addEventListener('change', async () => {
    await refreshVdfDerivedState();
  });
  requireElement<HTMLInputElement>('#vdf-exp').addEventListener('input', async (event) => {
    const value = Number((event.currentTarget as HTMLInputElement).value);
    requireElement<HTMLElement>('#vdf-exp-label').textContent = `2^${value} = ${(1 << value).toLocaleString()} squarings`;
    await refreshVdfDerivedState();
  });
  requireElement<HTMLButtonElement>('#vdf-evaluate').addEventListener('click', async () => {
    await runVdfDemo();
  });
  requireElement<HTMLButtonElement>('#vdf-verify').addEventListener('click', async () => {
    await verifyCurrentVdf();
  });
  requireElement<HTMLInputElement>('#beacon-validators').addEventListener('input', (event) => {
    const count = Number((event.currentTarget as HTMLInputElement).value);
    requireElement<HTMLElement>('#beacon-validators-label').textContent = `${count} validators`;
  });
  requireElement<HTMLInputElement>('#beacon-exp').addEventListener('input', (event) => {
    const value = Number((event.currentTarget as HTMLInputElement).value);
    requireElement<HTMLElement>('#beacon-exp-label').textContent = `2^${value} squarings`;
  });
  requireElement<HTMLButtonElement>('#beacon-run').addEventListener('click', async () => {
    await runBeaconDemo();
  });
}

async function boot(): Promise<void> {
  renderApp();
  bindThemeToggle();
  bindControls();
  appState.vrf.keyPair = await vrfKeyGen();
  await populateVrfForAlpha(requireElement<HTMLInputElement>('#vrf-alpha').value);
  await runVrfUniquenessDemo();

  const defaultVdfInput = await sha256Bytes(utf8ToBytes('beacon-seed'));
  requireElement<HTMLTextAreaElement>('#vdf-input').value = bytesToHex(defaultVdfInput);
  await refreshVdfDerivedState();
  requireElement<HTMLElement>('#beacon-validators-label').textContent = '4 validators';
  requireElement<HTMLElement>('#beacon-exp-label').textContent = '2^14 squarings';
  updateBeaconProgress(0, 0);

  const initialProof = appState.vrf.output?.proof;

  if (initialProof && appState.vrf.output) {
    const betaCheck = await proofToHash(initialProof.gamma);

    if (!equalBytes(betaCheck, appState.vrf.output.beta)) {
      setStatus(requireElement<HTMLElement>('#vrf-verify-status'), 'VRF proof-to-hash self-check failed during boot.', 'bad');
    }
  }
}

void boot().catch((error: unknown) => {
  app.innerHTML = `<main class="page-shell"><section class="section-card"><h1>Initialization failed</h1><p>${(error as Error).message}</p></section></main>`;
});
