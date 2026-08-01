import { bigintToBytes, bytesToBigInt, concatBytes } from './utils/bytes.js';
import { gcd, lcm, mod, modPow, powerOfTwoDivmod, powerOfTwoMod, repeatedSquaring } from './utils/vdfMath.js';

export interface VDFParams {
  N: bigint;
  T: number;
  T_exp: number;
}

export interface VDFResult {
  input: bigint;
  output: bigint;
  proof: bigint;
  prime: bigint;
  steps: number;
  timeMs: number;
}

// TOY ONLY. These are the NIST P-256 field prime and the P-256 curve order,
// both published in FIPS 186-4 and already used by this repo's VRF exhibit.
// Their product is a valid modulus for the Wesolowski construction in form only:
// a VDF's delay guarantee requires that NOBODY knows how N factors, and here
// everybody does. Given p and n, an adversary computes lambda(N) = lcm(p-1, n-1),
// reduces the exponent to 2^T mod lambda(N), and reproduces the output with ONE
// modular exponentiation for any T. The sequential delay is not small; it is
// nonexistent. Real deployments use an RSA modulus from a ceremony where no
// participant learns the factors, or a class group of unknown order.
const TOY_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const TOY_Q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = concatBytes(...parts);
  const copy = new Uint8Array(total.length);
  copy.set(total);
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer);
  return new Uint8Array(digest);
}

function ensurePositiveGroupElement(value: bigint, modulus: bigint): bigint {
  return mod(value, modulus - 3n) + 2n;
}

function bigintMessage(value: bigint): Uint8Array {
  return bigintToBytes(value, Math.max(1, Math.ceil(value.toString(16).length / 2)));
}

function isOdd(value: bigint): boolean {
  return (value & 1n) === 1n;
}

function decompose(n: bigint): { r: bigint; d: bigint } {
  let r = 0n;
  let d = n - 1n;

  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1n;
  }

  return { r, d };
}

/**
 * Fixed-base Miller-Rabin witnesses. The first seven are the deterministic
 * witness set that decides primality exactly for n < 3.317 * 10^24
 * (Sorenson & Webster); the last two are spares. Because the base list is
 * fixed, this is a 9-round test and cannot be asked for more.
 *
 * That guarantee is a theorem about these exact integers, so they have to be
 * used verbatim. This code used to compute the witness as
 * `mod(base, n - 3) + 2`, which for every n it is actually asked about shifts
 * the whole list up by two — running bases 4, 327, 9377, ... instead. Base 4 in
 * particular is a strictly weaker witness than base 2, and no published
 * deterministic bound covers the shifted set, so the documented bound did not
 * apply to what ran.
 */
const MILLER_RABIN_BASES = [2n, 325n, 9375n, 28178n, 450775n, 9780504n, 1795265022n, 7952650221n, 113n];

/**
 * Miller-Rabin primality test over the fixed base set above.
 *
 * `k` caps the number of rounds and now defaults to the number of bases
 * available. It previously defaulted to 20, advertising more than twice the
 * rounds the base list could ever supply — `Math.min(k, bases.length)` silently
 * clamped it to 9, so the extra rounds were never run.
 *
 * Above the deterministic bound the answer is probabilistic, and `hashToPrime`
 * — the only caller — works on ~256-bit candidates, far above it. Be clear about
 * what a wrong answer would cost: a composite ell would NOT be caught by the
 * verifier. Prover and verifier both derive ell from the same
 * `hashToPrime(g, y, T)`, and the Wesolowski identity pi^ell * g^r = y holds for
 * any ell whatever, prime or not, because 2^T = q*ell + r is just division. ell's
 * primality is what makes the proof *sound* — what stops a cheating prover
 * producing a convincing pi without doing the squarings — not what makes the
 * verifier's arithmetic close.
 */
export function isProbablePrime(n: bigint, k = MILLER_RABIN_BASES.length): boolean {
  if (n < 2n) {
    return false;
  }

  const smallPrimes = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

  for (const prime of smallPrimes) {
    if (n === prime) {
      return true;
    }

    if (n % prime === 0n) {
      return false;
    }
  }

  if (!isOdd(n)) {
    return false;
  }

  const { r, d } = decompose(n);
  const bases = MILLER_RABIN_BASES;
  const rounds = Math.min(k, bases.length);

  for (let index = 0; index < rounds; index += 1) {
    // Use the witness verbatim. Only fold it into range when n is smaller than the
    // base itself; a in {0, 1, n-1} carries no information, so skip rather than
    // pretend a round happened.
    const a = mod(bases[index], n);

    if (a < 2n || a > n - 2n) {
      continue;
    }

    let x = modPow(a, d, n);

    if (x === 1n || x === n - 1n) {
      continue;
    }

    let witnessedComposite = true;

    for (let j = 1n; j < r; j += 1n) {
      x = modPow(x, 2n, n);

      if (x === n - 1n) {
        witnessedComposite = false;
        break;
      }
    }

    if (witnessedComposite) {
      return false;
    }
  }

  return true;
}

export async function hashToGroup(x: Uint8Array, N: bigint): Promise<bigint> {
  const digest = await sha256(x);
  return ensurePositiveGroupElement(bytesToBigInt(digest), N);
}

export async function hashToPrime(g: bigint, y: bigint, T: number): Promise<bigint> {
  const digest = await sha256(bigintMessage(g), bigintMessage(y), bigintToBytes(BigInt(T), 8));
  let candidate = bytesToBigInt(digest) | 1n;

  if (candidate < 3n) {
    candidate = 3n;
  }

  while (!isProbablePrime(candidate)) {
    candidate += 2n;
  }

  return candidate;
}

function evaluateDirect(
  g: bigint,
  params: VDFParams,
  onProgress?: (pct: number, squarings: number) => void,
): { y: bigint; timeMs: number; squarings: number } {
  const started = performance.now();
  const y = repeatedSquaring(g, params.N, params.T, onProgress);
  const timeMs = performance.now() - started;
  return { y, timeMs, squarings: params.T };
}

export async function vdfEval(
  g: bigint,
  params: VDFParams,
  onProgress?: (pct: number, squarings: number) => void,
): Promise<{ y: bigint; timeMs: number; squarings: number }> {
  if (typeof Worker === 'undefined' || typeof window === 'undefined') {
    return evaluateDirect(g, params, onProgress);
  }

  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./worker/vdfWorker.ts', import.meta.url), { type: 'module' });

    worker.onmessage = (event: MessageEvent<{ type: string; pct?: number; squarings?: number; y?: bigint; timeMs?: number; message?: string }>) => {
      if (event.data.type === 'progress' && onProgress && typeof event.data.pct === 'number' && typeof event.data.squarings === 'number') {
        onProgress(event.data.pct, event.data.squarings);
        return;
      }

      if (event.data.type === 'done' && typeof event.data.y === 'bigint' && typeof event.data.timeMs === 'number' && typeof event.data.squarings === 'number') {
        worker.terminate();
        resolve({ y: event.data.y, timeMs: event.data.timeMs, squarings: event.data.squarings });
        return;
      }

      if (event.data.type === 'error') {
        worker.terminate();
        reject(new Error(event.data.message ?? 'Unknown VDF worker error'));
      }
    };

    worker.onerror = (error) => {
      worker.terminate();
      reject(error instanceof ErrorEvent ? new Error(error.message) : new Error('Unknown VDF worker error'));
    };

    worker.postMessage({ g, N: params.N, T: params.T });
  });
}

export async function vdfProve(
  g: bigint,
  y: bigint,
  params: VDFParams,
): Promise<{ proof: bigint; prime: bigint }> {
  const prime = await hashToPrime(g, y, params.T);
  const { quotient } = powerOfTwoDivmod(params.T, prime);
  const proof = modPow(g, quotient, params.N);
  return { proof, prime };
}

export async function vdfVerify(
  g: bigint,
  y: bigint,
  proof: bigint,
  params: VDFParams,
): Promise<boolean> {
  const prime = await hashToPrime(g, y, params.T);
  const remainder = powerOfTwoMod(params.T, prime);
  const left = mod(modPow(proof, prime, params.N) * modPow(g, remainder, params.N), params.N);
  return left === mod(y, params.N);
}

export const TOY_PARAMS: VDFParams = {
  N: TOY_P * TOY_Q,
  T: 1 << 16,
  T_exp: 16,
};

export interface VDFShortcut {
  /** The same y the sequential chain produces — byte for byte. */
  y: bigint;
  /** lcm(p-1, q-1): the Carmichael function of the toy modulus, computable by anyone. */
  lambda: bigint;
  /** The reduced exponent 2^T mod lambda(N), which is what actually gets exponentiated. */
  exponent: bigint;
  timeMs: number;
}

/**
 * The shortcut this toy modulus cannot prevent — the fidelity note, executable.
 *
 * A VDF's entire guarantee is that reaching y costs T sequential squarings. That rests on
 * nobody knowing how N factors. Here everybody does: N = TOY_P * TOY_Q, two constants
 * published in FIPS 186-4. So anyone computes lambda(N) = lcm(p-1, q-1), reduces the
 * exponent to 2^T mod lambda(N), and gets the identical y from ONE modular exponentiation.
 * g^(2^T) = g^(2^T mod lambda(N)) (mod N) whenever gcd(g, N) = 1, for any T however large.
 *
 * Returns null when the shortcut genuinely does not apply — a modulus that is not this toy
 * one, or a g sharing a factor with N — so the page can never claim to have skipped a delay
 * it did not skip.
 */
export function skipVdfDelay(g: bigint, params: VDFParams): VDFShortcut | null {
  if (params.N !== TOY_P * TOY_Q) {
    return null;
  }

  const base = mod(g, params.N);

  if (gcd(base, params.N) !== 1n) {
    return null;
  }

  const started = performance.now();
  const lambda = lcm(TOY_P - 1n, TOY_Q - 1n);
  const exponent = modPow(2n, BigInt(params.T), lambda);
  const y = modPow(base, exponent, params.N);
  return { y, lambda, exponent, timeMs: performance.now() - started };
}

export async function runVdf(g: bigint, params: VDFParams): Promise<VDFResult> {
  const evaluation = await vdfEval(g, params);
  const proof = await vdfProve(g, evaluation.y, params);
  return {
    input: g,
    output: evaluation.y,
    proof: proof.proof,
    prime: proof.prime,
    steps: evaluation.squarings,
    timeMs: evaluation.timeMs,
  };
}
