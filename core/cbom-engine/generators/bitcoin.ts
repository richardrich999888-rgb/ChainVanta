import type {
  BitcoinAssessment,
  BitcoinObservation,
  ScriptType,
} from '../../../packages/domain-models/src/bitcoin.js';

type Component = BitcoinAssessment['cbom']['components'][number];

/**
 * Signature algorithm each script type requires by consensus. Script-hash types depend on the
 * hidden script, so they stay unknown unless a supplied spend revealed a standard multisig.
 */
const ALGORITHM: Record<ScriptType, string> = {
  p2pk: 'ECDSA-secp256k1',
  p2pkh: 'ECDSA-secp256k1',
  p2wpkh: 'ECDSA-secp256k1',
  'bare-multisig': 'ECDSA-secp256k1',
  // BIP-341 key path: BIP-340 Schnorr over secp256k1. Script paths are not visible.
  p2tr: 'Schnorr-secp256k1',
  p2sh: 'unknown',
  p2wsh: 'unknown',
  unknown: 'unknown',
};

/** Native CBOM for a Bitcoin target: one component per script type the target can receive. */
export function buildBitcoinCbom(
  observation: BitcoinObservation,
  hash: string,
): BitcoinAssessment['cbom'] {
  const revealed = observation.revealedSpend;
  const components: Component[] = observation.target.scriptTypes.map((scriptType) => {
    const multisig =
      (scriptType === 'p2sh' || scriptType === 'p2wsh') && revealed && revealed.threshold !== null;
    const algorithm = multisig ? 'ECDSA-secp256k1' : ALGORITHM[scriptType];
    const known = algorithm !== 'unknown';
    return {
      algorithm,
      purpose: `${scriptType} spending authorization`,
      domain: 'account-authorization' as const,
      confidence: known ? ('observed' as const) : ('unknown' as const),
      basis: multisig
        ? `Spend ${revealed.txid} revealed a ${revealed.threshold}-of-${revealed.publicKeys.length} CHECKMULTISIG script matching the ${scriptType} commitment.`
        : known
          ? `Consensus rules require a ${algorithm} signature to spend ${scriptType} outputs.`
          : 'The script is committed by hash; its signature scheme is hidden until it is spent.',
      ...(known ? { evidenceRefs: [hash] } : {}),
    };
  });
  return { format: 'chainvanta-cbom/0.1', components };
}
