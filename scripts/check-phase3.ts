import { applyVDF, commitPhase, initBeaconRound, revealPhase, verifyBeaconRound } from '../src/beacon.js';
import { equalBytes, utf8ToBytes } from '../src/utils/bytes.js';
import { TOY_PARAMS } from '../src/vdf.js';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function requireValue<T>(value: T | undefined, message: string): T {
  if (value === undefined) {
    throw new Error(message);
  }

  return value;
}

async function main(): Promise<void> {
  const params = { ...TOY_PARAMS, T: 1 << 10, T_exp: 10 };
  const honestRound = await initBeaconRound(4, utf8ToBytes('epoch-42'));
  await commitPhase(honestRound);
  await revealPhase(honestRound);
  await applyVDF(honestRound, params);
  const honestVerification = await verifyBeaconRound(honestRound, params);

  assert(honestRound.finalRandomness !== undefined, 'Expected honest beacon round to produce final randomness');
  assert(honestVerification.valid, `Expected honest beacon round to verify: ${honestVerification.failures.join('; ')}`);

  const attackRound = await initBeaconRound(4, utf8ToBytes('epoch-42'));
  await commitPhase(attackRound);
  const withheldValidatorId = attackRound.validators[3]?.id;

  if (!withheldValidatorId) {
    throw new Error('Expected a fourth validator for withholding test');
  }

  await revealPhase(attackRound, [withheldValidatorId]);
  await applyVDF(attackRound, params);
  const attackVerification = await verifyBeaconRound(attackRound, params);

  assert(attackVerification.valid, `Expected withheld beacon round to verify: ${attackVerification.failures.join('; ')}`);
  assert(attackRound.validators.some((validator) => validator.withheld), 'Expected one validator to be marked withheld');
  const honestMix = requireValue(honestRound.randaoMix, 'Expected honest round to produce a RANDAO mix');
  const withheldMix = requireValue(attackRound.randaoMix, 'Expected withheld round to produce a partial RANDAO mix');
  assert(!equalBytes(honestMix, withheldMix), 'Withholding should change the RANDAO mix');
  assert(attackRound.finalRandomness !== undefined, 'Expected withheld round to still produce final randomness');

  console.log('phase-3 checks passed');
}

void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
