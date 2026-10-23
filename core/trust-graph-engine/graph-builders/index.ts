import type { Assessment, Observation } from '../../../packages/domain-models/src/index.js';
import { structureFacts } from '../../cryptographic-inventory/algorithm-classification/account-structure.js';

type Graph = Assessment['trustGraph'];

/** Structure relations; CPM tracks them as dependencies so upgrades and owner changes drift. */
export const STRUCTURE_RELATIONS = [
  'eip7702-delegates-to',
  'eip1167-delegates-to',
  'eip1967-implementation-slot-reports',
  'eip1967-admin-slot-reports',
  'eip1967-beacon-slot-reports',
  'beacon-implementation-reports',
  'safe-singleton-slot-reports',
  'safe-owner-accessor-reports',
  'safe-module-accessor-reports',
  'erc4337-entrypoint-accessor-reports',
] as const;
type StructureRelation = (typeof STRUCTURE_RELATIONS)[number];

/**
 * Structure edges. Relation names say how each edge was observed ("slot reports", "accessor
 * reports") so traversal never presents an accessor claim as a verified control relationship.
 */
function structureGraph(observation: Observation, account: string): Graph {
  const facts = structureFacts(observation);
  const id = (address: string) => `eip155:${observation.chainId}:${address}`;
  const links: [string | null | undefined, StructureRelation, string][] = [
    [facts.delegate, 'eip7702-delegates-to', 'delegate'],
    [facts.minimalProxy?.implementation, 'eip1167-delegates-to', 'implementation'],
    [facts.eip1967?.implementation, 'eip1967-implementation-slot-reports', 'implementation'],
    [facts.eip1967?.admin, 'eip1967-admin-slot-reports', 'proxy-admin'],
    [facts.eip1967?.beacon, 'eip1967-beacon-slot-reports', 'beacon'],
    [facts.eip1967?.beaconImplementation, 'beacon-implementation-reports', 'implementation'],
    [facts.safe?.singleton, 'safe-singleton-slot-reports', 'implementation'],
    [facts.erc4337?.entryPoint, 'erc4337-entrypoint-accessor-reports', 'entry-point'],
    ...(facts.safe?.owners ?? []).map(
      (o) =>
        [o, 'safe-owner-accessor-reports', 'reported-owner'] as [string, StructureRelation, string],
    ),
    ...(facts.safe?.modules ?? []).map(
      (m) => [m, 'safe-module-accessor-reports', 'module'] as [string, StructureRelation, string],
    ),
  ];
  const present = links.filter((l): l is [string, StructureRelation, string] => !!l[0]);
  const nodes = new Map<string, string>();
  for (const [address, , kind] of present)
    if (!nodes.has(id(address))) nodes.set(id(address), kind);
  // Accessor data is contract-controlled; duplicates must not violate the edge primary key.
  const edges = new Map<string, Graph['edges'][number]>();
  for (const [address, relation] of present)
    edges.set(`${relation}\n${id(address)}`, { from: account, to: id(address), relation });
  return {
    nodes: [...nodes].map(([nodeId, kind]) => ({ id: nodeId, kind })),
    edges: [...edges.values()],
  };
}

export function buildTrustGraph(observation: Observation, hash: string): Assessment['trustGraph'] {
  const account = `eip155:${observation.chainId}:${observation.address}`;
  const block = `eip155:${observation.chainId}:${observation.blockHash}`;
  const structure = structureGraph(observation, account);
  const base: Graph = {
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
  // Deduplicate: the same address can appear as owner and module, or already as reported-owner.
  const seen = new Set(base.nodes.map((n) => n.id));
  return {
    nodes: [...base.nodes, ...structure.nodes.filter((n) => !seen.has(n.id))],
    edges: [...base.edges, ...structure.edges],
  };
}
