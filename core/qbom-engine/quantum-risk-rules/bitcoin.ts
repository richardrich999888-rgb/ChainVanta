import type {
  BitcoinAssessment,
  BitcoinObservation,
} from '../../../packages/domain-models/src/bitcoin.js';

const MIGRATION_NOTE =
  'This is a migration dependency, not a prediction of timing or current exploitability. Bitcoin has no deployed post-quantum output type; migration requires a consensus change.';

/** Sums sats across groups matching `exposure`. */
const sum = (o: BitcoinObservation, exposure: string) =>
  o.groups.filter((g) => g.keyExposure === exposure).reduce((t, g) => t + BigInt(g.sats), 0n);

/**
 * Quantum exposure of unspent value. Value is exposed when its locking key is public: in the
 * output script itself (P2PK, bare multisig, P2TR output key), or revealed by a supplied confirmed
 * spend from the same address or key (reuse). Hash-locked value without such evidence is
 * reported as hash-protected, which says nothing about off-chain key disclosure.
 */
export function buildBitcoinQbom(o: BitcoinObservation): BitcoinAssessment['qbom'] {
  const inScript = sum(o, 'public-key-in-script');
  const hashLocked = sum(o, 'hash-locked');
  const unknown = sum(o, 'unknown');
  const exposed = inScript + (o.revealedSpend ? hashLocked : 0n);
  const protectedSats = o.revealedSpend ? 0n : hashLocked;
  const status =
    o.utxoCount === 0
      ? 'no-unspent-outputs'
      : exposed > 0n
        ? 'public-key-exposed'
        : unknown > 0n
          ? 'unknown'
          : 'hash-protected';
  const taprootAddress = o.target.kind === 'address' && o.target.scriptTypes[0] === 'p2tr';
  const reason =
    status === 'no-unspent-outputs'
      ? `No unspent outputs at block ${o.tipHash}.${taprootAddress ? ' The address itself encodes a public taproot output key, so any value sent to it is exposed.' : ''}`
      : status === 'public-key-exposed'
        ? `${exposed} sats are locked to secp256k1 keys that are public on-chain (${inScript} in output scripts, ${o.revealedSpend ? hashLocked : 0n} hash-locked but revealed by spend ${o.revealedSpend?.txid ?? 'n/a'}). Shor's algorithm on a sufficiently capable quantum computer could derive these keys. ${MIGRATION_NOTE}`
        : status === 'unknown'
          ? 'Non-standard output scripts prevent an exposure conclusion.'
          : `${hashLocked} sats are hash-locked; their keys are not in the output scripts. Prior spends, address reuse or off-chain disclosure were not established. ${MIGRATION_NOTE}`;
  return {
    format: 'chainvanta-qbom/0.1',
    ruleVersion: 'bitcoin-quantum-exposure/1.0.0',
    status,
    exposedSats: exposed.toString(),
    hashProtectedSats: protectedSats.toString(),
    reason,
    migration: 'requires-further-discovery',
  };
}
