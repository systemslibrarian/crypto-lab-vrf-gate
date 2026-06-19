import {
  bigintToBytes,
  bytesToBigInt,
  concatBytes,
  equalBytes,
} from './utils/bytes.js';
import {
  addPoints,
  AffinePoint,
  compressPoint,
  decompressPoint,
  mod,
  negatePoint,
  P256_G,
  P256_N,
  scalarMultiply,
  scalarToBytes,
  tryDecompressEvenX,
} from './utils/p256.js';

/**
 * ECVRF-P256-SHA256-TAI, implemented byte-exactly per RFC 9381.
 *
 * Verified against the official known-answer test vector in RFC 9381 Appendix B.1
 * (Example 10, alpha = "sample") by scripts/check-rfc9381.ts. Every domain-separation
 * octet, the SEC1 compressed point encoding, the RFC 6979 deterministic nonce, and the
 * `s = k + c*x` response are required for that vector to match — so this is a faithful,
 * interoperable VRF, not a look-alike.
 */

// Single-octet ciphersuite identifier for ECVRF-P256-SHA256-TAI (RFC 9381 Section 5.5).
const SUITE_STRING = new Uint8Array([0x01]);
// Fixed domain-separation octets used by the RFC's hash inputs.
const ONE_STRING = new Uint8Array([0x01]);
const TWO_STRING = new Uint8Array([0x02]);
const THREE_STRING = new Uint8Array([0x03]);
const ZERO_STRING = new Uint8Array([0x00]);

const CHALLENGE_LENGTH = 16; // cLen for this ciphersuite (RFC 9381 Section 5.5).
const SCALAR_LENGTH = 32; // qLen in octets.

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

export interface VRFKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** SEC1 compressed public-key point Y = x*B (33 bytes). */
  publicKeyBytes: Uint8Array;
  /** The secret scalar x. Kept in memory so proving is deterministic per RFC 9381. */
  secretScalar: bigint;
}

export interface VRFProof {
  /** Compressed Gamma = x*H (33 bytes). */
  gamma: Uint8Array;
  /** Challenge c (cLen = 16 bytes). */
  c: Uint8Array;
  /** Response s = k + c*x mod q (qLen = 32 bytes). */
  s: Uint8Array;
}

/** Intermediate values exposed so the UI can "show the work" of a proof. */
export interface VRFTrace {
  /** Compressed H = encode_to_curve(PK, alpha). */
  hPoint: Uint8Array;
  /** try-and-increment counter that produced a valid H. */
  counter: number;
  /** Compressed U = k*B. */
  uPoint: Uint8Array;
  /** Compressed V = k*H. */
  vPoint: Uint8Array;
  /** The deterministic RFC 6979 nonce k (32 bytes). Exposed for the KAT, not the UI. */
  nonce: Uint8Array;
}

export interface VRFOutput {
  beta: Uint8Array;
  proof: VRFProof;
  alpha: Uint8Array;
  trace: VRFTrace;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', toArrayBuffer(concatBytes(...parts)));
  return new Uint8Array(hash);
}

async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(message));
  return new Uint8Array(signature);
}

function requirePoint(point: AffinePoint | null, label: string): AffinePoint {
  if (point === null) {
    throw new Error(`${label} is the point at infinity`);
  }

  return point;
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

async function exportPrivateScalar(privateKey: CryptoKey): Promise<bigint> {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);

  if (typeof jwk.d !== 'string') {
    throw new Error('Private key scalar is unavailable');
  }

  return bytesToBigInt(base64UrlDecode(jwk.d));
}

/**
 * ECVRF_encode_to_curve_try_and_increment (RFC 9381 Section 5.4.1.1).
 *
 * H = first valid point from arbitrary_string_to_point(
 *       SHA-256(suite || 0x01 || salt || alpha || ctr || 0x00))
 * where the salt is the compressed public key and ctr is a single octet. The point is
 * read as a compressed encoding with even y; x >= p or a non-residue means "try ctr+1".
 */
export async function encodeToCurveTAI(
  saltPublicKey: Uint8Array,
  alpha: Uint8Array,
): Promise<{ point: AffinePoint; counter: number }> {
  for (let counter = 0; counter <= 0xff; counter += 1) {
    const hash = await sha256(
      SUITE_STRING,
      ONE_STRING,
      saltPublicKey,
      alpha,
      new Uint8Array([counter]),
      ZERO_STRING,
    );
    const point = tryDecompressEvenX(hash);

    if (point !== null) {
      return { point, counter };
    }
  }

  throw new Error('encode_to_curve failed: exhausted try-and-increment counters');
}

/**
 * ECVRF nonce generation via RFC 6979 (RFC 9381 Section 5.4.2.1).
 * Deterministic HMAC-SHA256 DRBG over the secret scalar and h_string = compressed H.
 */
export async function nonceGenerationRFC6979(secretScalar: bigint, hString: Uint8Array): Promise<bigint> {
  const h1 = await sha256(hString);
  const secretOctets = bigintToBytes(secretScalar, SCALAR_LENGTH); // int2octets(x)
  const messageOctets = bigintToBytes(mod(bytesToBigInt(h1), P256_N), SCALAR_LENGTH); // bits2octets(h1)

  let v: Uint8Array = new Uint8Array(SCALAR_LENGTH).fill(0x01);
  let k: Uint8Array = new Uint8Array(SCALAR_LENGTH).fill(0x00);

  k = await hmacSha256(k, concatBytes(v, ZERO_STRING, secretOctets, messageOctets));
  v = await hmacSha256(k, v);
  k = await hmacSha256(k, concatBytes(v, ONE_STRING, secretOctets, messageOctets));
  v = await hmacSha256(k, v);

  for (;;) {
    let t: Uint8Array = new Uint8Array(0);

    while (t.length < SCALAR_LENGTH) {
      v = await hmacSha256(k, v);
      t = concatBytes(t, v);
    }

    const candidate = bytesToBigInt(t.slice(0, SCALAR_LENGTH)); // bits2int over qlen = 256 bits

    if (candidate >= 1n && candidate < P256_N) {
      return candidate;
    }

    k = await hmacSha256(k, concatBytes(v, ZERO_STRING));
    v = await hmacSha256(k, v);
  }
}

/**
 * ECVRF_challenge_generation (RFC 9381 Section 5.4.3).
 * c = first cLen octets of SHA-256(suite || 0x02 || PK || H || Gamma || U || V || 0x00).
 * The public key Y is the first hashed point — omitting it breaks interoperability.
 */
export async function challengeGeneration(
  publicKey: AffinePoint,
  h: AffinePoint,
  gamma: AffinePoint,
  u: AffinePoint,
  v: AffinePoint,
): Promise<Uint8Array> {
  const digest = await sha256(
    SUITE_STRING,
    TWO_STRING,
    compressPoint(publicKey),
    compressPoint(h),
    compressPoint(gamma),
    compressPoint(u),
    compressPoint(v),
    ZERO_STRING,
  );
  return digest.slice(0, CHALLENGE_LENGTH);
}

/**
 * ECVRF_proof_to_hash (RFC 9381 Section 5.2).
 * beta = SHA-256(suite || 0x03 || point_to_string(cofactor*Gamma) || 0x00).
 * The P-256 cofactor is 1, so cofactor*Gamma is just Gamma (already compressed here).
 */
export async function proofToHash(gammaCompressed: Uint8Array): Promise<Uint8Array> {
  return sha256(SUITE_STRING, THREE_STRING, gammaCompressed, ZERO_STRING);
}

/** Core ECVRF_prove (RFC 9381 Section 5.1) operating directly on the secret scalar. */
export async function vrfProveScalar(secretScalar: bigint, alpha: Uint8Array): Promise<VRFOutput> {
  const publicKeyPoint = requirePoint(scalarMultiply(secretScalar, P256_G), 'public key');
  const publicKeyBytes = compressPoint(publicKeyPoint);

  const { point: hPoint, counter } = await encodeToCurveTAI(publicKeyBytes, alpha);
  const hCompressed = compressPoint(hPoint);
  const gammaPoint = requirePoint(scalarMultiply(secretScalar, hPoint), 'Gamma');

  const nonce = await nonceGenerationRFC6979(secretScalar, hCompressed);
  const uPoint = requirePoint(scalarMultiply(nonce, P256_G), 'U');
  const vPoint = requirePoint(scalarMultiply(nonce, hPoint), 'V');

  const c = await challengeGeneration(publicKeyPoint, hPoint, gammaPoint, uPoint, vPoint);
  const challengeScalar = bytesToBigInt(c);
  const s = scalarToBytes(mod(nonce + challengeScalar * secretScalar, P256_N));

  const gamma = compressPoint(gammaPoint);
  const beta = await proofToHash(gamma);

  return {
    alpha: alpha.slice(),
    beta,
    proof: { gamma, c, s },
    trace: {
      hPoint: hCompressed,
      counter,
      uPoint: compressPoint(uPoint),
      vPoint: compressPoint(vPoint),
      nonce: bigintToBytes(nonce, SCALAR_LENGTH),
    },
  };
}

/** Generate a P-256 VRF keypair and cache the secret scalar for deterministic proving. */
export async function vrfKeyGen(): Promise<VRFKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const secretScalar = await exportPrivateScalar(keyPair.privateKey);
  const publicKeyPoint = requirePoint(scalarMultiply(secretScalar, P256_G), 'public key');

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyBytes: compressPoint(publicKeyPoint),
    secretScalar,
  };
}

/** ECVRF_prove (RFC 9381 Section 5.1). */
export async function vrfProve(keyPair: VRFKeyPair, alpha: Uint8Array): Promise<VRFOutput> {
  return vrfProveScalar(keyPair.secretScalar, alpha);
}

/**
 * ECVRF_verify (RFC 9381 Section 5.3).
 * Reconstructs U = s*B - c*Y and V = s*H - c*Gamma, regenerates the challenge, and
 * accepts only if it matches c and beta is the proof_to_hash of Gamma.
 */
export async function vrfVerify(
  publicKeyBytes: Uint8Array,
  alpha: Uint8Array,
  output: Pick<VRFOutput, 'beta' | 'proof'>,
): Promise<{ valid: boolean; beta?: Uint8Array }> {
  try {
    const publicKeyPoint = decompressPoint(publicKeyBytes);
    const { point: hPoint } = await encodeToCurveTAI(publicKeyBytes, alpha);
    const gammaPoint = decompressPoint(output.proof.gamma);
    const challengeScalar = bytesToBigInt(output.proof.c);
    const sScalar = bytesToBigInt(output.proof.s);

    const cY = scalarMultiply(challengeScalar, publicKeyPoint);
    const uPoint = requirePoint(
      addPoints(scalarMultiply(sScalar, P256_G), cY === null ? null : negatePoint(cY)),
      'U',
    );
    const cGamma = scalarMultiply(challengeScalar, gammaPoint);
    const vPoint = requirePoint(
      addPoints(scalarMultiply(sScalar, hPoint), cGamma === null ? null : negatePoint(cGamma)),
      'V',
    );

    const expectedChallenge = await challengeGeneration(publicKeyPoint, hPoint, gammaPoint, uPoint, vPoint);
    const beta = await proofToHash(output.proof.gamma);
    const valid = equalBytes(expectedChallenge, output.proof.c) && equalBytes(beta, output.beta);

    return valid ? { valid, beta } : { valid };
  } catch {
    return { valid: false };
  }
}
