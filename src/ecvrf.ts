import {
  bigintToBytes,
  bytesToBigInt,
  concatBytes,
  equalBytes,
  numberToBytes,
  utf8ToBytes,
} from './utils/bytes.js';
import {
  addPoints,
  AffinePoint,
  bytesToPoint,
  isOnCurve,
  mod,
  P256_G,
  P256_N,
  P256_P,
  pointToBytes,
  scalarFromBytes,
  scalarMultiply,
  scalarToBytes,
  sqrtModP,
} from './utils/p256.js';

const SUITE_STRING = utf8ToBytes('ECVRF-P256-SHA256');
const PROOF_TO_HASH_DOMAIN = utf8ToBytes('ECVRF_proof_to_hash');

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

export interface VRFKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export interface VRFProof {
  gamma: Uint8Array;
  c: Uint8Array;
  s: Uint8Array;
}

export interface VRFOutput {
  beta: Uint8Array;
  proof: VRFProof;
  alpha: Uint8Array;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', toArrayBuffer(concatBytes(...parts)));
  return new Uint8Array(hash);
}

function requirePoint(point: AffinePoint | null, label: string): AffinePoint {
  if (point === null) {
    throw new Error(`${label} is the point at infinity`);
  }

  return point;
}

async function exportPrivateScalar(privateKey: CryptoKey): Promise<bigint> {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);

  if (typeof jwk.d !== 'string') {
    throw new Error('Private key scalar is unavailable');
  }

  return scalarFromBytes(base64UrlDecode(jwk.d));
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const result = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    result[index] = binary.charCodeAt(index);
  }

  return result;
}

async function importRawPublicKey(pointBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(pointBytes),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

async function deriveEcdhXCoordinate(privateKey: CryptoKey, publicPointBytes: Uint8Array): Promise<Uint8Array> {
  const publicKey = await importRawPublicKey(publicPointBytes);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  return new Uint8Array(bits);
}

async function crossCheckXCoordinate(
  privateKey: CryptoKey,
  publicPointBytes: Uint8Array,
  expectedPoint: AffinePoint,
): Promise<void> {
  const derivedX = await deriveEcdhXCoordinate(privateKey, publicPointBytes);
  const expectedX = bigintToBytes(expectedPoint.x, 32);

  if (!equalBytes(derivedX, expectedX)) {
    throw new Error('WebCrypto ECDH cross-check failed');
  }
}

async function randomScalar(): Promise<bigint> {
  const buffer = new Uint8Array(32);

  while (true) {
    crypto.getRandomValues(buffer);
    const scalar = mod(bytesToBigInt(buffer), P256_N);

    if (scalar !== 0n) {
      return scalar;
    }
  }
}

/**
 * Generate a P-256 VRF keypair.
 */
export async function vrfKeyGen(): Promise<VRFKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyBytes,
  };
}

/**
 * ECVRF_encode_to_curve_try_and_increment (RFC 9381 Section 5.4.1.1).
 * Hashes (pk_bytes || alpha) to a P-256 curve point.
 * Tries ctr = 0, 1, 2, ... until valid point found.
 * Returns the curve point H as uncompressed bytes.
 */
export async function hashToCurve(
  pkBytes: Uint8Array,
  alpha: Uint8Array,
): Promise<Uint8Array> {
  for (let counter = 0; counter < 65536; counter += 1) {
    const digest = await sha256(SUITE_STRING, pkBytes, alpha, numberToBytes(counter, 4));
    const x = mod(bytesToBigInt(digest), P256_P);
    const rhs = mod(x * x * x - 3n * x + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn, P256_P);
    const y = sqrtModP(rhs);

    if (y !== null) {
      const point = { x, y: (y & 1n) === 0n ? y : P256_P - y };

      if (isOnCurve(point)) {
        return pointToBytes(point);
      }
    }
  }

  throw new Error('hashToCurve failed after exhausting try-and-increment counters');
}

/**
 * ECVRF_challenge_generation (RFC 9381 Section 5.4.3).
 * c = first 16 bytes of SHA-256(suite || 2 || H || Gamma || U || V)
 */
export async function challengeGeneration(
  H: Uint8Array,
  Gamma: Uint8Array,
  U: Uint8Array,
  V: Uint8Array,
): Promise<Uint8Array> {
  const digest = await sha256(SUITE_STRING, new Uint8Array([0x02]), H, Gamma, U, V);
  return digest.slice(0, 16);
}

/**
 * ECVRF_proof_to_hash (RFC 9381 Section 5.2).
 * beta = SHA-256("ECVRF_proof_to_hash" || cofactor*Gamma)
 */
export async function proofToHash(gamma: Uint8Array): Promise<Uint8Array> {
  return sha256(PROOF_TO_HASH_DOMAIN, gamma);
}

/**
 * ECVRF_prove (RFC 9381 Section 5.1).
 * Returns VRFOutput with beta and proof.
 */
export async function vrfProve(
  keyPair: VRFKeyPair,
  alpha: Uint8Array,
): Promise<VRFOutput> {
  const secretScalar = await exportPrivateScalar(keyPair.privateKey);
  const H = await hashToCurve(keyPair.publicKeyBytes, alpha);
  const HPoint = bytesToPoint(H);
  const gammaPoint = requirePoint(scalarMultiply(secretScalar, HPoint), 'Gamma');
  await crossCheckXCoordinate(keyPair.privateKey, H, gammaPoint);

  const nonceScalar = await randomScalar();
  const UPoint = requirePoint(scalarMultiply(nonceScalar, P256_G), 'U');
  const UBytes = pointToBytes(UPoint);
  const VPoint = requirePoint(scalarMultiply(nonceScalar, HPoint), 'V');

  const gammaBytes = pointToBytes(gammaPoint);
  const VBytes = pointToBytes(VPoint);
  const c = await challengeGeneration(H, gammaBytes, UBytes, VBytes);
  const challengeScalar = bytesToBigInt(c);
  const s = scalarToBytes(mod(nonceScalar - challengeScalar * secretScalar, P256_N));
  const beta = await proofToHash(gammaBytes);

  return {
    alpha: alpha.slice(),
    beta,
    proof: {
      gamma: gammaBytes,
      c,
      s,
    },
  };
}

/**
 * ECVRF_verify (RFC 9381 Section 5.3).
 * Returns { valid: boolean, beta?: Uint8Array }
 */
export async function vrfVerify(
  publicKeyBytes: Uint8Array,
  alpha: Uint8Array,
  output: VRFOutput,
): Promise<{ valid: boolean; beta?: Uint8Array }> {
  try {
    const publicKeyPoint = bytesToPoint(publicKeyBytes);
    const H = await hashToCurve(publicKeyBytes, alpha);
    const HPoint = bytesToPoint(H);
    const gammaPoint = bytesToPoint(output.proof.gamma);
    const sScalar = scalarFromBytes(output.proof.s);
    const cScalar = bytesToBigInt(output.proof.c);

    const UPoint = requirePoint(
      addPoints(scalarMultiply(sScalar, P256_G), scalarMultiply(cScalar, publicKeyPoint)),
      'U',
    );
    const VPoint = requirePoint(
      addPoints(scalarMultiply(sScalar, HPoint), scalarMultiply(cScalar, gammaPoint)),
      'V',
    );

    const expectedChallenge = await challengeGeneration(
      H,
      output.proof.gamma,
      pointToBytes(UPoint),
      pointToBytes(VPoint),
    );
    const beta = await proofToHash(output.proof.gamma);
    const valid = equalBytes(expectedChallenge, output.proof.c) && equalBytes(beta, output.beta);

    return valid ? { valid, beta } : { valid };
  } catch {
    return { valid: false };
  }
}
