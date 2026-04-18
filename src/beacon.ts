import { VRFKeyPair, VRFOutput, vrfKeyGen, vrfProve, vrfVerify } from './ecvrf.js';
import { bigintToBytes, concatBytes, equalBytes, xorBytes } from './utils/bytes.js';
import { hashToGroup, VDFParams, VDFResult, runVdf, vdfVerify } from './vdf.js';

export interface Validator {
  id: string;
  keyPair: VRFKeyPair;
  vrfOutput?: VRFOutput;
  committed: boolean;
  revealed: boolean;
  withheld: boolean;
}

export interface BeaconRound {
  epochSeed: Uint8Array;
  validators: Validator[];
  commitments: Map<string, Uint8Array>;
  randaoMix?: Uint8Array;
  vdfResult?: VDFResult;
  finalRandomness?: Uint8Array;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = concatBytes(...parts);
  const copy = new Uint8Array(total.length);
  copy.set(total);
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer);
  return new Uint8Array(digest);
}

function requireBytes(value: Uint8Array | undefined, label: string): Uint8Array {
  if (!value) {
    throw new Error(`${label} is missing`);
  }

  return value;
}

function collectRevealedBetas(round: BeaconRound): Uint8Array[] {
  const betas = round.validators
    .filter((validator) => validator.revealed && !validator.withheld && validator.vrfOutput)
    .map((validator) => requireBytes(validator.vrfOutput?.beta, `VRF beta for ${validator.id}`));

  if (betas.length === 0) {
    throw new Error('No revealed VRF outputs are available');
  }

  return betas;
}

export async function initBeaconRound(N: number, epochSeed: Uint8Array): Promise<BeaconRound> {
  const validators: Validator[] = [];

  for (let index = 0; index < N; index += 1) {
    validators.push({
      id: `V${index + 1}`,
      keyPair: await vrfKeyGen(),
      committed: false,
      revealed: false,
      withheld: false,
    });
  }

  return {
    epochSeed: epochSeed.slice(),
    validators,
    commitments: new Map(),
  };
}

export async function commitPhase(round: BeaconRound): Promise<BeaconRound> {
  for (const validator of round.validators) {
    const vrfOutput = await vrfProve(validator.keyPair, round.epochSeed);
    validator.vrfOutput = vrfOutput;
    validator.committed = true;
    validator.revealed = false;
    validator.withheld = false;
    round.commitments.set(validator.id, await sha256(vrfOutput.beta));
  }

  return round;
}

export async function revealPhase(
  round: BeaconRound,
  withheldValidators: string[] = [],
): Promise<BeaconRound> {
  const withheldSet = new Set(withheldValidators);

  for (const validator of round.validators) {
    if (!validator.committed || !validator.vrfOutput) {
      throw new Error(`Validator ${validator.id} has not committed a VRF output`);
    }

    validator.withheld = withheldSet.has(validator.id);
    validator.revealed = !validator.withheld;
  }

  round.randaoMix = computeRANDAO(round);
  return round;
}

export function computeRANDAO(round: BeaconRound): Uint8Array {
  return xorBytes(collectRevealedBetas(round));
}

export async function applyVDF(round: BeaconRound, params: VDFParams): Promise<BeaconRound> {
  const randaoMix = round.randaoMix ?? computeRANDAO(round);
  const g = await hashToGroup(randaoMix, params.N);
  const vdfResult = await runVdf(g, params);
  const finalRandomness = await sha256(bigintToBytes(vdfResult.output));

  round.randaoMix = randaoMix;
  round.vdfResult = vdfResult;
  round.finalRandomness = finalRandomness;
  return round;
}

export async function verifyBeaconRound(
  round: BeaconRound,
  params: VDFParams,
): Promise<{ valid: boolean; failures: string[] }> {
  const failures: string[] = [];

  for (const validator of round.validators) {
    if (!validator.committed || !validator.vrfOutput) {
      failures.push(`${validator.id} did not commit a VRF output`);
      continue;
    }

    const expectedCommitment = round.commitments.get(validator.id);

    if (!expectedCommitment) {
      failures.push(`${validator.id} is missing its commitment`);
      continue;
    }

    const actualCommitment = await sha256(validator.vrfOutput.beta);

    if (!equalBytes(expectedCommitment, actualCommitment)) {
      failures.push(`${validator.id} commitment does not match its VRF output`);
    }

    if (!validator.withheld) {
      const verification = await vrfVerify(validator.keyPair.publicKeyBytes, round.epochSeed, validator.vrfOutput);

      if (!verification.valid) {
        failures.push(`${validator.id} VRF proof failed verification`);
      }
    }
  }

  if (round.randaoMix) {
    const computed = computeRANDAO(round);

    if (!equalBytes(computed, round.randaoMix)) {
      failures.push('RANDAO mix does not match the revealed VRF outputs');
    }
  }

  if (round.vdfResult && round.randaoMix) {
    const expectedInput = await hashToGroup(round.randaoMix, params.N);

    if (expectedInput !== round.vdfResult.input) {
      failures.push('VDF input does not match hashToGroup(RANDAO)');
    }

    const verified = await vdfVerify(
      round.vdfResult.input,
      round.vdfResult.output,
      round.vdfResult.proof,
      params,
    );

    if (!verified) {
      failures.push('VDF proof failed verification');
    }

    if (round.finalRandomness) {
      const expectedFinal = await sha256(bigintToBytes(round.vdfResult.output));

      if (!equalBytes(expectedFinal, round.finalRandomness)) {
        failures.push('Final randomness does not match SHA-256(y)');
      }
    }
  }

  return {
    valid: failures.length === 0,
    failures,
  };
}
