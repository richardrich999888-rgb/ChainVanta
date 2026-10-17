import { evidenceHash } from '../../evidence-engine/evidence-hashing/index.js';
import type { Assessment, Observation } from '../../../packages/domain-models/src/index.js';

export function buildCbom(observation: Observation): Assessment['cbom'] {
  return {
    format: 'chainvanta-cbom/0.1',
    components: [
      ...(observation.signature
        ? [
            {
              algorithm: 'ECDSA-secp256k1',
              purpose: 'transaction signature',
              domain: 'transaction-signature' as const,
              confidence: 'observed' as const,
              basis: `Verified transaction ${observation.signature.hash}; recovered sender matches the observed account.`,
              evidenceRefs: [evidenceHash(observation)],
            },
          ]
        : []),
      {
        algorithm: 'unknown',
        purpose: 'account authorization',
        confidence: 'unknown',
        basis:
          observation.code === '0x'
            ? 'No code at the observed block. Address, nonce and balance do not prove a signing scheme or public-key exposure.'
            : 'Bytecode is present. Signer schemes, delegated code and upgrade paths require additional analysis.',
      },
    ],
  };
}
