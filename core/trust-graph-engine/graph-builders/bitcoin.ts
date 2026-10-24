import {
  bitcoinAssetId,
  type BitcoinAssessment,
  type BitcoinObservation,
} from '../../../packages/domain-models/src/bitcoin.js';

/** Evidence graph: the target, the scan tip, and keys a supplied spend revealed. */
export function buildBitcoinTrustGraph(
  o: BitcoinObservation,
  hash: string,
): BitcoinAssessment['trustGraph'] {
  const asset = bitcoinAssetId(o.network, o.target.value);
  const tip = `${o.chainId}:block:${o.tipHash}`;
  const spend = o.revealedSpend;
  const tx = spend ? `${o.chainId}:tx:${spend.txid}` : null;
  const keys = spend ? [...new Set(spend.publicKeys)].map((k) => `secp256k1:${k}`) : [];
  return {
    nodes: [
      { id: asset, kind: o.target.kind === 'address' ? 'bitcoin-address' : 'bitcoin-public-key' },
      { id: tip, kind: 'block' },
      { id: hash, kind: 'evidence' },
      ...(tx ? [{ id: tx, kind: 'transaction' }] : []),
      ...keys.map((id) => ({ id, kind: 'public-key' })),
    ],
    edges: [
      { from: asset, to: tip, relation: 'utxo-snapshot-at' },
      { from: hash, to: asset, relation: 'supports' },
      ...(tx ? [{ from: asset, to: tx, relation: 'key-revealed-by-spend' }] : []),
      ...keys.map((to) => ({ from: asset, to, relation: 'revealed-key' })),
    ],
  };
}
