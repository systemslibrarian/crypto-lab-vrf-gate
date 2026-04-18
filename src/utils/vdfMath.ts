export interface QuotientRemainder {
  quotient: bigint;
  remainder: bigint;
}

export function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) {
    throw new Error('Modulus must be greater than 1');
  }

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

export function repeatedSquaring(
  g: bigint,
  N: bigint,
  squarings: number,
  onProgress?: (pct: number, completed: number) => void,
): bigint {
  if (!Number.isInteger(squarings) || squarings < 0) {
    throw new Error('Squaring count must be a non-negative integer');
  }

  let value = mod(g, N);
  const progressInterval = Math.max(1, Math.floor(squarings / 100));

  for (let step = 0; step < squarings; step += 1) {
    value = mod(value * value, N);

    if (onProgress && (step + 1 === squarings || (step + 1) % progressInterval === 0)) {
      onProgress(Math.round(((step + 1) / squarings) * 100), step + 1);
    }
  }

  return value;
}

export function powerOfTwoDivmod(exponent: number, modulus: bigint): QuotientRemainder {
  if (!Number.isInteger(exponent) || exponent < 0) {
    throw new Error('Exponent must be a non-negative integer');
  }

  if (modulus <= 0n) {
    throw new Error('Modulus must be positive');
  }

  let quotient = 0n;
  let remainder = 1n;

  for (let step = 0; step < exponent; step += 1) {
    const doubled = remainder << 1n;
    const carry = doubled / modulus;
    remainder = doubled % modulus;
    quotient = (quotient << 1n) + carry;
  }

  return {
    quotient,
    remainder,
  };
}

export function powerOfTwoMod(exponent: number, modulus: bigint): bigint {
  return powerOfTwoDivmod(exponent, modulus).remainder;
}
