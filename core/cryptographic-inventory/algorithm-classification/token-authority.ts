import {
  SUPPLY_OR_LOGIC_ROLES,
  type Observation,
  type TokenAuthority,
  type TokenRole,
} from '../../../packages/domain-models/src/index.js';

type AuthorityKind = TokenAuthority['authorities'][number]['kind'];

/** One authority address with every role it was reported to hold. */
export interface AuthorityHolder {
  address: string;
  kind: AuthorityKind;
  roles: TokenRole[];
}

/** Token-authority facts shared by the CBOM, posture and graph engines. */
export interface TokenAuthorityFacts {
  authority: TokenAuthority;
  holders: AuthorityHolder[];
  /**
   * Holders that can mint or replace logic and are controlled by a single secp256k1 key: no code
   * (a plain account) or an EIP-7702 delegated account, whose key stays a valid signer.
   */
  singleKeySupplyOrLogic: AuthorityHolder[];
  /** Roles whose holder list may be partial, or holders whose code was not classified. */
  incomplete: {
    roles: TokenRole[];
    unclassified: number;
    /** Not enumerable and no role history was collected. */
    nonEnumerable: boolean;
    /** Role history coverage, when collected. */
    history: { gaps: number; attested: boolean } | null;
  };
}

const SINGLE_KEY: readonly AuthorityKind[] = ['no-code', 'eip-7702-delegated'];

/** Pure projection of `observation.tokenAuthority`; null when the adapter did not run. */
export function tokenAuthorityFacts(observation: Observation): TokenAuthorityFacts | null {
  const authority = observation.tokenAuthority;
  if (!authority) return null;
  const kinds = new Map(authority.authorities.map((a) => [a.address, a.kind]));
  // Insertion order follows discovery order, so the projection is deterministic.
  const byAddress = new Map<string, AuthorityHolder>();
  for (const { role, holders } of authority.roles)
    for (const address of holders) {
      const holder = byAddress.get(address) ?? {
        address,
        kind: kinds.get(address) ?? 'not-checked',
        roles: [],
      };
      if (!holder.roles.includes(role)) holder.roles.push(role);
      byAddress.set(address, holder);
    }
  const holders = [...byAddress.values()];
  return {
    authority,
    holders,
    singleKeySupplyOrLogic: holders.filter(
      (h) => SINGLE_KEY.includes(h.kind) && h.roles.some((r) => SUPPLY_OR_LOGIC_ROLES.includes(r)),
    ),
    incomplete: {
      roles: [...new Set(authority.roles.filter((r) => !r.holdersComplete).map((r) => r.role))],
      unclassified: holders.filter((h) => h.kind === 'not-checked').length,
      nonEnumerable: authority.accessControl === 'non-enumerable' && !authority.roleHistory,
      history: authority.roleHistory
        ? {
            gaps: authority.roleHistory.gaps.length,
            attested: authority.roleHistory.historyAttested,
          }
        : null,
    },
  };
}
