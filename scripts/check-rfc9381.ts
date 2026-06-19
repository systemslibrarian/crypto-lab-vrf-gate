import {
  encodeToCurveTAI,
  vrfProveScalar,
  vrfVerify,
} from '../src/ecvrf.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils/bytes.js';
import { compressPoint, P256_G, scalarMultiply } from '../src/utils/p256.js';

/**
 * RFC 9381 Appendix B.1, ECVRF-P256-SHA256-TAI, Example 10 (alpha = "sample").
 * If any domain octet, the SEC1 point encoding, the RFC 6979 nonce, or the s = k + c*x
 * response is wrong, these byte strings will not reproduce — so this is the proof that
 * the implementation is genuinely interoperable, not merely "RFC-shaped".
 */
const VECTOR = {
  sk: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
  pk: '0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6',
  alpha: '73616d706c65', // "sample"
  counter: 1,
  h: '0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4',
  k: '0d90591273453d2dc67312d39914e3a93e194ab47a58cd598886897076986f77',
  u: '02bb6a034f67643c6183c10f8b41dc4babf88bff154b674e377d90bde009c21672',
  v: '02893ebee7af9a0faa6da810da8a91f9d50e1dc071240c9706726820ff919e8394',
  pi: '035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f',
  beta: 'a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e',
} as const;

function assertHex(actual: Uint8Array, expected: string, label: string): void {
  const got = bytesToHex(actual);

  if (got !== expected) {
    throw new Error(`${label} mismatch\n  expected ${expected}\n  got      ${got}`);
  }

  console.log(`  ok  ${label}`);
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

async function main(): Promise<void> {
  const secretScalar = BigInt(`0x${VECTOR.sk}`);
  const alpha = hexToBytes(VECTOR.alpha);

  assert(bytesToHex(alpha) === bytesToHex(utf8ToBytes('sample')), 'alpha decoding sanity check');

  // Public key Y = x*B must match the RFC's compressed PK.
  const publicKeyBytes = compressPoint(scalarMultiply(secretScalar, P256_G)!);
  assertHex(publicKeyBytes, VECTOR.pk, 'PK = x*B');

  // try-and-increment encode_to_curve.
  const { point: hPoint, counter } = await encodeToCurveTAI(publicKeyBytes, alpha);
  assert(counter === VECTOR.counter, `try-and-increment counter mismatch: ${counter} != ${VECTOR.counter}`);
  assertHex(compressPoint(hPoint), VECTOR.h, 'H = encode_to_curve(PK, alpha)');

  const output = await vrfProveScalar(secretScalar, alpha);

  assertHex(output.trace.nonce, VECTOR.k, 'k (RFC 6979 nonce)');
  assertHex(output.trace.uPoint, VECTOR.u, 'U = k*B');
  assertHex(output.trace.vPoint, VECTOR.v, 'V = k*H');

  const pi = concatBytes(output.proof.gamma, output.proof.c, output.proof.s);
  assertHex(pi, VECTOR.pi, 'pi = Gamma || c || s');
  assertHex(output.beta, VECTOR.beta, 'beta = proof_to_hash(Gamma)');

  const verification = await vrfVerify(publicKeyBytes, alpha, output);
  assert(verification.valid, 'vrfVerify rejected the RFC proof');
  console.log('  ok  vrfVerify accepts the RFC proof');

  const tampered = { ...output, beta: output.beta.slice() };
  tampered.beta[0] ^= 0x01;
  const tamperedResult = await vrfVerify(publicKeyBytes, alpha, tampered);
  assert(!tamperedResult.valid, 'vrfVerify accepted a tampered beta');
  console.log('  ok  vrfVerify rejects a tampered beta');

  console.log('rfc-9381 known-answer test passed (ECVRF-P256-SHA256-TAI, Example 10)');
}

void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
