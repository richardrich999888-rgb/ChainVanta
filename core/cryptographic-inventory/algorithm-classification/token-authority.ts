import {
  SUPPLY_OR_LOGIC_ROLES,
  type AuthorityControl,
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
  /** Contract holders that were profiled (adapter 1.2.0). */
  control?: AuthorityControl;
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
  /** Safes with threshold 1 holding supply or logic roles: any one owner can act alone. */
  singleSignerSafes: AuthorityHolder[];
  /** Timelocks with zero minimum delay holding supply or logic roles: no review window. */
  zeroDelayTimelocks: AuthorityHolder[];
  /** Roles whose holder list may be partial, or holders whose code was not classified. */
  incomplete: {
    roles: TokenRole[];
    unclassified: number;
    /** Contract holders of supply or logic roles left unprofiled by the budget (1.2.0). */
    unprofiled: number;
    /** Not enumerable and no role history was collected. */
    nonEnumerable: boolean;
    /** Role history coverage, when collected. */
    history: { gaps: number; attested: boolean } | null;
  };
}

const SINGLE_KEY: readonly AuthorityKind[] = ['no-code', 'eip-7702-delegated'];

/** Human-readable control description, e.g. "2-of-3 Safe" or "timelock (172800 s delay)". */
export function describeControl(control: AuthorityControl): string {
  if (control.type === 'safe') return `${control.threshold}-of-${control.owners.length} Safe`;
  if (control.type === 'timelock')
    return `${control.standard === 'compound-timelock' ? 'Compound' : 'OpenZeppelin'} timelock (${control.minDelaySeconds} s minimum delay)`;
  return 'contract without recognized Safe or timelock accessors';
}

/** Pure projection of `observation.tokenAuthority`; null when the adapter did not run. */
export function tokenAuthorityFacts(observation: Observation): TokenAuthorityFacts | null {
  const authority = observation.tokenAuthority;
  if (!authority) return null;
  const byAuthority = new Map(authority.authorities.map((a) => [a.address, a]));
  // Insertion order follows discovery order, so the projection is deterministic.
  const byAddress = new Map<string, AuthorityHolder>();
  for (const { role, holders } of authority.roles)
    for (const address of holders) {
      const known = byAuthority.get(address);
      const holder = byAddress.get(address) ?? {
        address,
        kind: known?.kind ?? 'not-checked',
        roles: [],
        ...(known?.control ? { control: known.control } : {}),
      };
      if (!holder.roles.includes(role)) holder.roles.push(role);
      byAddress.set(address, holder);
    }
  const holders = [...byAddress.values()];
  const powerful = (h: AuthorityHolder) => h.roles.some((r) => SUPPLY_OR_LOGIC_ROLES.includes(r));
  return {
    authority,
    holders,
    singleKeySupplyOrLogic: holders.filter((h) => SINGLE_KEY.includes(h.kind) && powerful(h)),
    singleSignerSafes: holders.filter(
      (h) => powerful(h) && h.control?.type === 'safe' && h.control.threshold === 1,
    ),
    zeroDelayTimelocks: holders.filter(
      (h) => powerful(h) && h.control?.type === 'timelock' && h.control.minDelaySeconds === '0',
    ),
    incomplete: {
      roles: [...new Set(authority.roles.filter((r) => !r.holdersComplete).map((r) => r.role))],
      unclassified: holders.filter((h) => h.kind === 'not-checked').length,
      // Proxy admins are skipped by design (their owner is followed); 1.0/1.1 never profiled.
      unprofiled:
        authority.adapter === 'token-authority/1.2.0'
          ? holders.filter(
              (h) =>
                h.kind === 'contract' &&
                powerful(h) &&
                !h.control &&
                !h.roles.includes('proxy-admin'),
            ).length
          : 0,
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
