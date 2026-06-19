import { bigintToBytes, bytesToBigInt } from './bytes.js';

export interface AffinePoint {
  x: bigint;
  y: bigint;
}

export const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
export const P256_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
export const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
export const P256_G: AffinePoint = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

export function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = mod(base, modulus);
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = mod(result * factor, modulus);
    }

    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }

  return result;
}

export function invert(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = mod(value, modulus);

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (r !== 1n) {
    throw new Error('Value is not invertible');
  }

  return mod(t, modulus);
}

export function sqrtModP(value: bigint): bigint | null {
  const candidate = modPow(value, (P256_P + 1n) >> 2n, P256_P);
  return mod(candidate * candidate, P256_P) === mod(value, P256_P) ? candidate : null;
}

export function isOnCurve(point: AffinePoint): boolean {
  if (point.x < 0n || point.x >= P256_P || point.y < 0n || point.y >= P256_P) {
    return false;
  }

  const left = mod(point.y * point.y, P256_P);
  const right = mod(point.x * point.x * point.x + P256_A * point.x + P256_B, P256_P);
  return left === right;
}

export function negatePoint(point: AffinePoint): AffinePoint {
  return {
    x: point.x,
    y: mod(-point.y, P256_P),
  };
}

export function addPoints(left: AffinePoint | null, right: AffinePoint | null): AffinePoint | null {
  if (left === null) {
    return right;
  }

  if (right === null) {
    return left;
  }

  if (left.x === right.x) {
    if (mod(left.y + right.y, P256_P) === 0n) {
      return null;
    }

    return doublePoint(left);
  }

  const slope = mod((right.y - left.y) * invert(right.x - left.x, P256_P), P256_P);
  const x = mod(slope * slope - left.x - right.x, P256_P);
  const y = mod(slope * (left.x - x) - left.y, P256_P);
  return { x, y };
}

export function doublePoint(point: AffinePoint | null): AffinePoint | null {
  if (point === null) {
    return null;
  }

  if (point.y === 0n) {
    return null;
  }

  const slope = mod((3n * point.x * point.x + P256_A) * invert(2n * point.y, P256_P), P256_P);
  const x = mod(slope * slope - 2n * point.x, P256_P);
  const y = mod(slope * (point.x - x) - point.y, P256_P);
  return { x, y };
}

export function scalarMultiply(scalar: bigint, point: AffinePoint | null): AffinePoint | null {
  if (point === null || scalar === 0n) {
    return null;
  }

  let result: AffinePoint | null = null;
  let addend: AffinePoint | null = point;
  let remaining = mod(scalar, P256_N);

  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) {
      result = addPoints(result, addend);
    }

    addend = doublePoint(addend);
    remaining >>= 1n;
  }

  return result;
}

export function pointToBytes(point: AffinePoint): Uint8Array {
  const result = new Uint8Array(65);
  result[0] = 0x04;
  result.set(bigintToBytes(point.x, 32), 1);
  result.set(bigintToBytes(point.y, 32), 33);
  return result;
}

export function bytesToPoint(bytes: Uint8Array): AffinePoint {
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error('Expected uncompressed P-256 point bytes');
  }

  const point = {
    x: bytesToBigInt(bytes.slice(1, 33)),
    y: bytesToBigInt(bytes.slice(33, 65)),
  };

  if (!isOnCurve(point)) {
    throw new Error('Point is not on the P-256 curve');
  }

  return point;
}

/**
 * SEC1 compressed point encoding (33 bytes): 0x02/0x03 prefix (parity of y) || x.
 * RFC 9381 uses this `point_to_string` for every curve point it hashes or serializes.
 */
export function compressPoint(point: AffinePoint): Uint8Array {
  const result = new Uint8Array(33);
  result[0] = (point.y & 1n) === 0n ? 0x02 : 0x03;
  result.set(bigintToBytes(point.x, 32), 1);
  return result;
}

/**
 * Recover the affine point from a SEC1 compressed encoding (the `string_to_point` of
 * RFC 9381). Throws if the bytes are not a valid on-curve compressed point.
 */
export function decompressPoint(bytes: Uint8Array): AffinePoint {
  if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
    throw new Error('Expected a 33-byte SEC1 compressed P-256 point');
  }

  const point = decompressXWithParity(bytesToBigInt(bytes.slice(1)), bytes[0] === 0x03);

  if (point === null) {
    throw new Error('Compressed point does not lie on the P-256 curve');
  }

  return point;
}

/**
 * Try to interpret a 32-byte string as the x-coordinate of a point with even y.
 * Returns null (rather than throwing) when x >= p or no square root exists — this is
 * exactly the "INVALID, try the next counter" branch of RFC 9381 try-and-increment.
 */
export function tryDecompressEvenX(xBytes: Uint8Array): AffinePoint | null {
  return decompressXWithParity(bytesToBigInt(xBytes), false);
}

function decompressXWithParity(x: bigint, wantOdd: boolean): AffinePoint | null {
  if (x >= P256_P) {
    return null;
  }

  const rhs = mod(x * x * x + P256_A * x + P256_B, P256_P);
  const root = sqrtModP(rhs);

  if (root === null) {
    return null;
  }

  const y = ((root & 1n) === 1n) === wantOdd ? root : mod(-root, P256_P);
  const point = { x, y };
  return isOnCurve(point) ? point : null;
}

export function scalarToBytes(scalar: bigint): Uint8Array {
  return bigintToBytes(mod(scalar, P256_N), 32);
}

export function scalarFromBytes(bytes: Uint8Array): bigint {
  const value = bytesToBigInt(bytes);

  if (value <= 0n || value >= P256_N) {
    throw new Error('Invalid scalar encoding');
  }

  return value;
}
