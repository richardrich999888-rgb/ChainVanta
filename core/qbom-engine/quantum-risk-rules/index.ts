import type { Assessment, Observation } from '../../../packages/domain-models/src/index.js';
import { structureFacts } from '../../cryptographic-inventory/algorithm-classification/account-structure.js';

const MIGRATION_NOTE =
  'This is a migration dependency, not a prediction of timing or current exploitability. ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) require chain and wallet compatibility analysis; transport PQC does not migrate transaction signatures.';

/**
 * Quantum exposure record. `classical-signature-observed` requires direct evidence of a secp256k1
 * signer: a verified transaction, a recovered EIP-7702 authorization signature, or an EIP-7702
 * designator (installed only by a secp256k1-signed authorization). Inferred Safe-owner schemes do not change the status.
 */
export function buildQbom(observation?: Observation): Assessment['qbom'] {
  const delegate = observation ? structureFacts(observation).delegate : null;
  const authorization = observation?.discovery?.authorization ?? null;
  const status =
    observation?.signature || delegate || authorization
      ? 'classical-signature-observed'
      : 'unknown';
  return {
    format: 'chainvanta-qbom/0.1',
    ruleVersion: 'quantum-exposure/1.1.0',
    status,
    migration: 'requires-further-discovery',
    reason: observation?.signature
      ? `Verified secp256k1 ECDSA transaction signature: elliptic-curve signatures are exposed to a sufficiently capable quantum computer. ${MIGRATION_NOTE}`
      : authorization
        ? `Recovered the account's secp256k1 signature on an EIP-7702 authorization (transaction ${authorization.transactionHash}); the public key is recoverable from public chain data. ${MIGRATION_NOTE}`
        : delegate
          ? `EIP-7702 delegation designator present: the account's secp256k1 key signed the authorization and remains a valid signer, so delegation does not remove the elliptic-curve dependency. ${MIGRATION_NOTE}`
          : 'Account authorization and public-key exposure are unverified. No quantum vulnerability or quantum-safety conclusion is supported by this snapshot.',
  };
}
