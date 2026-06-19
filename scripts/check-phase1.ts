import { encodeToCurveTAI, vrfKeyGen, vrfProve, vrfVerify } from '../src/ecvrf.js';
import { equalBytes, utf8ToBytes } from '../src/utils/bytes.js';
import { isOnCurve } from '../src/utils/p256.js';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

async function main(): Promise<void> {
  const alpha = utf8ToBytes('block-1847-leader-selection');
  const alphaTwo = utf8ToBytes('block-1848-leader-selection');
  const keyPair = await vrfKeyGen();
  const alternateKeyPair = await vrfKeyGen();

  const runOne = await vrfProve(keyPair, alpha);
  const runTwo = await vrfProve(keyPair, alpha);
  const runThree = await vrfProve(keyPair, alpha);
  const distinctAlpha = await vrfProve(keyPair, alphaTwo);

  assert(
    equalBytes(runOne.beta, runTwo.beta) && equalBytes(runTwo.beta, runThree.beta),
    'Same key and alpha did not produce the same beta',
  );
  assert(!equalBytes(runOne.beta, distinctAlpha.beta), 'Different alpha produced same beta');

  const valid = await vrfVerify(keyPair.publicKeyBytes, alpha, runOne);
  assert(valid.valid, 'Expected vrfVerify to accept a correct proof');

  const tampered = {
    ...runOne,
    beta: runOne.beta.slice(),
  };
  tampered.beta[0] ^= 0x01;
  const tamperedResult = await vrfVerify(keyPair.publicKeyBytes, alpha, tampered);
  assert(!tamperedResult.valid, 'Expected tampered beta to fail verification');

  const wrongKeyResult = await vrfVerify(alternateKeyPair.publicKeyBytes, alpha, runOne);
  assert(!wrongKeyResult.valid, 'Expected a different public key to fail verification');

  const { point: hashPoint } = await encodeToCurveTAI(keyPair.publicKeyBytes, alpha);
  assert(isOnCurve(hashPoint), 'encode_to_curve did not return an on-curve point');

  console.log('phase-1 checks passed');
}

void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
