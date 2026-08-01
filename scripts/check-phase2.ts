import { utf8ToBytes } from '../src/utils/bytes.js';
import { TOY_PARAMS, hashToGroup, hashToPrime, isProbablePrime, skipVdfDelay, vdfEval, vdfProve, vdfVerify } from '../src/vdf.js';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

async function main(): Promise<void> {
  const x = utf8ToBytes('beacon-seed');
  const g = await hashToGroup(x, TOY_PARAMS.N);
  let progressEvents = 0;

  const evaluation = await vdfEval(g, { ...TOY_PARAMS, T: 1 << 12, T_exp: 12 }, () => {
    progressEvents += 1;
  });
  const proofBundle = await vdfProve(g, evaluation.y, { ...TOY_PARAMS, T: 1 << 12, T_exp: 12 });
  const verified = await vdfVerify(g, evaluation.y, proofBundle.proof, { ...TOY_PARAMS, T: 1 << 12, T_exp: 12 });
  assert(verified, 'Expected VDF proof verification to pass');

  const tampered = await vdfVerify(g, evaluation.y ^ 1n, proofBundle.proof, { ...TOY_PARAMS, T: 1 << 12, T_exp: 12 });
  assert(!tampered, 'Expected modified VDF output to fail verification');

  const prime = await hashToPrime(g, evaluation.y, 1 << 12);
  assert(isProbablePrime(prime), 'hashToPrime did not return a prime');

  const secondEvaluation = await vdfEval(g, { ...TOY_PARAMS, T: 1 << 12, T_exp: 12 });
  assert(secondEvaluation.y === evaluation.y, 'Same VDF input did not produce the same output');
  assert(progressEvents > 0, 'Expected VDF evaluation progress callback to fire');

  // The page states the toy delay is ZERO and offers a button that skips it. That is only
  // honest if the shortcut lands on exactly the same y as the full chain, at every T the
  // slider offers — so check it here instead of asserting it in prose.
  for (const T_exp of [12, 14, 16, 18]) {
    const params = { ...TOY_PARAMS, T: 1 << T_exp, T_exp };
    const chain = await vdfEval(g, params);
    const shortcut = skipVdfDelay(g, params);
    assert(shortcut !== null, `Expected the lambda shortcut to apply at T = 2^${T_exp}`);
    assert(
      shortcut?.y === chain.y,
      `Shortcut output differed from the sequential chain at T = 2^${T_exp}`,
    );
  }

  // And it must decline rather than mislead when it does not apply.
  assert(
    skipVdfDelay(g, { ...TOY_PARAMS, N: TOY_PARAMS.N + 2n }) === null,
    'Expected the lambda shortcut to decline a modulus whose factors it does not know',
  );

  console.log('phase-2 checks passed');
}

void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
