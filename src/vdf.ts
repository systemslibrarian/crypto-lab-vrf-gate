import { bigintToBytes, bytesToBigInt, concatBytes } from './utils/bytes.js';
import { mod, modPow, powerOfTwoDivmod, powerOfTwoMod, repeatedSquaring } from './utils/vdfMath.js';

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

export function isProbablePrime(n: bigint, k = 20): boolean {
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
  const bases = [2n, 325n, 9375n, 28178n, 450775n, 9780504n, 1795265022n, 7952650221n, 113n];
  const rounds = Math.min(k, bases.length);

  for (let index = 0; index < rounds; index += 1) {
    const a = mod(bases[index], n - 3n) + 2n;
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

export function estimateVDFTime(T_squarings: number): { seconds: number; minutes: number; hours: number } {
  const seconds = T_squarings / 1_000_000;
  return {
    seconds,
    minutes: seconds / 60,
    hours: seconds / 3600,
  };
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
