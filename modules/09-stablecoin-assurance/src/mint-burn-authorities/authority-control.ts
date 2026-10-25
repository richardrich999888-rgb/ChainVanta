import { decodeFunctionResult, encodeFunctionData, parseAbi, type Hex } from 'viem';
import {
  STRUCTURE_LIMITS,
  SUPPLY_OR_LOGIC_ROLES,
  TOKEN_AUTHORITY_LIMITS,
  type AuthorityControl,
  type TokenAuthority,
} from '../../../../packages/domain-models/src/index.js';
import {
  decoded,
  type Recorder,
} from '../../../../core/evidence-engine/evidence-collection/read-recorder.js';

/**
 * Profiles how a contract authority holder is itself controlled, using standard accessors:
 *   Safe:                                getThreshold() then getOwners()
 *   OpenZeppelin TimelockController:     getMinDelay()
 *   Compound Timelock (GovernorBravo):   delay()
 * Probes run in that order and stop at the first consistent answer, so a holder costs at most
 * READS_PER_HOLDER reads. A Safe answer is accepted only when 1 <= threshold <= owners and owners
 * are distinct non-zero addresses; anything else is not a Safe. Accessors are contract-reported,
 * so a lookalike can return the same data: results are `inferred`.
 */

export const READS_PER_HOLDER = 3;
/** Read reservation the caller makes before spending its remaining budget elsewhere. */
export const CONTROL_READ_RESERVE = TOKEN_AUTHORITY_LIMITS.maxProfiledControls * READS_PER_HOLDER;

const abi = parseAbi([
  'function getThreshold() view returns (uint256)',
  'function getOwners() view returns (address[])',
  'function getMinDelay() view returns (uint256)',
  'function delay() view returns (uint256)',
]);
const ZERO = '0x0000000000000000000000000000000000000000';
type Authority = TokenAuthority['authorities'][number];
type Role = TokenAuthority['roles'][number];

const read = (r: Recorder, target: Hex, functionName: (typeof abi)[number]['name']) =>
  r.call(target, encodeFunctionData({ abi, functionName }));

/** Profiles one holder. Pure apart from the recorder; at most READS_PER_HOLDER reads. */
async function profile(r: Recorder, holder: Hex): Promise<AuthorityControl> {
  const threshold = decoded(await read(r, holder, 'getThreshold'), (data) =>
    decodeFunctionResult({ abi, functionName: 'getThreshold', data }),
  );
  if (threshold !== null && threshold >= 1n) {
    const owners = decoded(await read(r, holder, 'getOwners'), (data) =>
      decodeFunctionResult({ abi, functionName: 'getOwners', data }),
    );
    const list = owners?.map((o) => o.toLowerCase()) ?? [];
    const valid =
      list.length >= 1 &&
      list.length <= STRUCTURE_LIMITS.maxSafeOwners &&
      new Set(list).size === list.length &&
      !list.includes(ZERO) &&
      threshold <= BigInt(list.length);
    // A threshold answer without a consistent owner set is not treated as a Safe.
    return valid
      ? { type: 'safe', threshold: Number(threshold), owners: list }
      : { type: 'unrecognized' };
  }
  const minDelay = decoded(await read(r, holder, 'getMinDelay'), (data) =>
    decodeFunctionResult({ abi, functionName: 'getMinDelay', data }),
  );
  if (minDelay !== null)
    return {
      type: 'timelock',
      standard: 'openzeppelin-timelock-controller',
      minDelaySeconds: minDelay.toString(),
    };
  const delay = decoded(await read(r, holder, 'delay'), (data) =>
    decodeFunctionResult({ abi, functionName: 'delay', data }),
  );
  return delay !== null
    ? { type: 'timelock', standard: 'compound-timelock', minDelaySeconds: delay.toString() }
    : { type: 'unrecognized' };
}

/**
 * Selects contract holders of supply or logic roles (excluding proxy admins, whose owner is
 * already followed), in role-discovery order, and profiles up to maxProfiledControls of them.
 */
export async function profileControls(
  r: Recorder,
  roles: Role[],
  authorities: Authority[],
): Promise<Authority[]> {
  const proxyAdmins = new Set(
    roles.filter((x) => x.role === 'proxy-admin').flatMap((x) => x.holders),
  );
  const powerful = new Set(
    roles.filter((x) => SUPPLY_OR_LOGIC_ROLES.includes(x.role)).flatMap((x) => x.holders),
  );
  const selected = authorities
    .filter((a) => a.kind === 'contract' && powerful.has(a.address) && !proxyAdmins.has(a.address))
    .slice(0, TOKEN_AUTHORITY_LIMITS.maxProfiledControls)
    .map((a) => a.address);
  const controls = new Map(
    await Promise.all(
      selected.map(async (address) => [address, await profile(r, address as Hex)] as const),
    ),
  );
  return authorities.map((a) => {
    const control = controls.get(a.address);
    return control ? { ...a, control } : a;
  });
}
