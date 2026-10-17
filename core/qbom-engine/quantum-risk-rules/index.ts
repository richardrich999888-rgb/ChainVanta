import type { Assessment, Observation } from '../../../packages/domain-models/src/index.js';
export function buildQbom(observation?: Observation): Assessment['qbom'] {
  return {
    format: 'chainvanta-qbom/0.1',
    ruleVersion: 'quantum-exposure/1.0.0',
    status: observation?.signature ? 'classical-signature-observed' : 'unknown',
    migration: 'requires-further-discovery',
    reason: observation?.signature
      ? 'Verified secp256k1 ECDSA transaction signature: elliptic-curve signatures are exposed to a sufficiently capable quantum computer. This is a migration dependency, not a prediction of timing or current exploitability. ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) require chain and wallet compatibility analysis; transport PQC does not migrate transaction signatures.'
      : 'Account authorization and public-key exposure are unverified. No quantum vulnerability or quantum-safety conclusion is supported by this snapshot.',
  };
}
