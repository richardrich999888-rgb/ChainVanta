import type { AccountStructure, Observation } from '../../../packages/domain-models/src/index.js';

type OwnerKind = NonNullable<AccountStructure['safe']>['ownerCode'][number]['kind'];

/** Structure-derived authorization facts shared by the CBOM, QBOM, posture and graph engines. */
export interface StructureFacts {
  /** EIP-7702 delegate; when set, the account's own secp256k1 key remains a valid signer. */
  delegate: string | null;
  safe: AccountStructure['safe'];
  /** Safe owners by code kind at the observed block. */
  ownerCounts: Record<OwnerKind, number>;
  eip1967: AccountStructure['eip1967'];
  minimalProxy: AccountStructure['minimalProxy'];
  erc4337: AccountStructure['erc4337'];
}

const OWNER_KINDS: OwnerKind[] = ['no-code', 'eip-7702-delegated', 'contract', 'not-checked'];

/** Pure projection of `observation.structure`; absent structure yields empty facts. */
export function structureFacts(observation: Observation): StructureFacts {
  const s = observation.structure;
  const safe = s?.safe ?? null;
  return {
    delegate: s?.delegation?.delegate ?? null,
    safe,
    ownerCounts: Object.fromEntries(
      OWNER_KINDS.map((kind) => [kind, safe?.ownerCode.filter((o) => o.kind === kind).length ?? 0]),
    ) as Record<OwnerKind, number>,
    eip1967: s?.eip1967 ?? null,
    minimalProxy: s?.minimalProxy ?? null,
    erc4337: s?.erc4337 ?? null,
  };
}

/** Threshold policy label, e.g. "2-of-3". */
export const safePolicy = (safe: NonNullable<AccountStructure['safe']>) =>
  `${safe.threshold}-of-${safe.owners.length}`;
