import type { Assessment, Observation } from '../../../packages/domain-models/src/index.js';
export function buildTrustGraph(observation: Observation, hash: string): Assessment['trustGraph'] {
  const account = `eip155:${observation.chainId}:${observation.address}`;
  const block = `eip155:${observation.chainId}:${observation.blockHash}`;
  return {
    nodes: [
      { id: account, kind: 'account' },
      { id: block, kind: 'block' },
      { id: hash, kind: 'evidence' },
      ...(observation.signature
        ? [
            { id: observation.signature.hash, kind: 'transaction' },
            { id: 'algorithm:ECDSA-secp256k1', kind: 'algorithm' },
          ]
        : []),
      ...(observation.token
        ? [
            {
              id: `eip155:${observation.chainId}:${observation.token.owner}`,
              kind: 'reported-owner',
            },
          ]
        : []),
    ],
    edges: [
      { from: account, to: block, relation: 'observed-at' },
      { from: hash, to: account, relation: 'supports' },
      ...(observation.signature
        ? [
            { from: account, to: observation.signature.hash, relation: 'verified-sender' },
            {
              from: observation.signature.hash,
              to: 'algorithm:ECDSA-secp256k1',
              relation: 'verified-signature-uses',
            },
          ]
        : []),
      ...(observation.token
        ? [
            {
              from: account,
              to: `eip155:${observation.chainId}:${observation.token.owner}`,
              relation: 'owner-accessor-reports',
            },
          ]
        : []),
    ],
  };
}
