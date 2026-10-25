import {
  decodeFunctionResult,
  encodeFunctionData,
  keccak256,
  parseAbi,
  toHex,
  type Hex,
} from 'viem';
import {
  TOKEN_AUTHORITY_LIMITS,
  TokenAuthority,
  type AccountStructure,
  type TokenRole,
} from '../../../../packages/domain-models/src/index.js';
import { IACCESS_CONTROL, IACCESS_CONTROL_ENUMERABLE, ROLE_IDS } from './access-control.js';
import { discoverRoleHistory, type HistoryReader } from './role-history.js';
import {
  decoded,
  recording,
  type ChainReader,
  type ProbeResult,
  type Recorder,
} from '../../../../core/evidence-engine/evidence-collection/read-recorder.js';
import {
  parseDelegation,
  slotAddress,
} from '../../../01-wallet-intelligence/src/discovery/account-structure.js';

/**
 * Discovers who holds privileged token powers, from standard accessors read at a pinned block:
 * Ownable/Ownable2Step, AccessControl (ERC-165 detected; enumerable roles listed),
 * AccessControlDefaultAdminRules, Circle FiatToken roles, pause state and proxy admins
 * (EIP-1967 from account structure, the legacy ZeppelinOS admin slot, and one hop to a ProxyAdmin
 * contract's owner). Each distinct holder's code is classified so single-key authorities stand out.
 *
 * Accessor answers come from contract code: a lookalike can return the same data, so holder
 * claims are `inferred`. The read budget is fixed by construction (see TOKEN_AUTHORITY_LIMITS).
 */

/** Legacy ZeppelinOS AdminUpgradeabilityProxy slot (used by e.g. USDC's FiatTokenProxy). */
export const ZEPPELINOS_ADMIN_SLOT = keccak256(toHex('org.zeppelinos.proxy.admin'));

const abi = parseAbi([
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function totalSupply() view returns (uint256)',
  'function paused() view returns (bool)',
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function defaultAdmin() view returns (address)',
  'function masterMinter() view returns (address)',
  'function pauser() view returns (address)',
  'function blacklister() view returns (address)',
  'function rescuer() view returns (address)',
  'function supportsInterface(bytes4 interfaceId) view returns (bool)',
  'function getRoleMemberCount(bytes32 role) view returns (uint256)',
  'function getRoleMember(bytes32 role, uint256 index) view returns (address)',
]);
const ZERO: Hex = '0x0000000000000000000000000000000000000000';
const MAX_SYMBOL_LENGTH = 32;
const UINT8_MAX = 255;

type Role = TokenAuthority['roles'][number];
const lower = (v: string) => v.toLowerCase() as Hex;

/** One address-returning accessor as a role; zero means explicitly renounced (no holder). */
function addressRole(
  result: ProbeResult,
  role: TokenRole,
  source: Role['source'],
  fn: string,
): Role | null {
  const value = decoded(result, (data) =>
    decodeFunctionResult({ abi, functionName: fn as 'owner', data }),
  );
  if (value === null) return null;
  const holder = lower(value);
  return { role, source, holders: holder === ZERO ? [] : [holder], holdersComplete: true };
}

async function enumerateRoles(r: Recorder, token: Hex, budget: () => number): Promise<Role[]> {
  const entries = Object.entries(ROLE_IDS) as [keyof typeof ROLE_IDS, Hex][];
  const counts = await Promise.all(
    entries.map(([, id]) =>
      r.call(token, encodeFunctionData({ abi, functionName: 'getRoleMemberCount', args: [id] })),
    ),
  );
  const roles: Role[] = [];
  for (const [i, [role, id]] of entries.entries()) {
    const count = decoded(counts[i]!, (data) =>
      decodeFunctionResult({ abi, functionName: 'getRoleMemberCount', data }),
    );
    if (count === null) continue;
    // Members are read in index order until the per-role cap or the shared budget runs out.
    const wanted = Math.min(
      Number(count > 1000n ? 1000n : count),
      TOKEN_AUTHORITY_LIMITS.maxHoldersPerRole,
    );
    const take = Math.max(0, Math.min(wanted, budget()));
    const members = await Promise.all(
      Array.from({ length: take }, (_, index) =>
        r.call(
          token,
          encodeFunctionData({ abi, functionName: 'getRoleMember', args: [id, BigInt(index)] }),
        ),
      ),
    );
    const decodedMembers = members.map((m) =>
      decoded(m, (data) => decodeFunctionResult({ abi, functionName: 'getRoleMember', data })),
    );
    const holders = decodedMembers
      .filter((h): h is Hex => h !== null && lower(h) !== ZERO)
      .map(lower);
    roles.push({
      role,
      source: 'access-control-enumerable',
      holders: [...new Set(holders)],
      // Complete only when every member index was read and each read decoded to an address.
      holdersComplete: BigInt(take) === count && decodedMembers.every((h) => h !== null),
    });
  }
  return roles;
}

/** Event-history access for non-enumerable AccessControl (see role-history.ts). */
export interface TokenHistoryOptions {
  reader: HistoryReader;
  /** Finalized snapshot block; logs are read over [0, snapshotBlock]. */
  snapshotBlock: bigint;
  /** Operator attests the provider serves full log history. */
  attested: boolean;
}

/**
 * Discovers token authorities. `structure` supplies already-read EIP-1967 proxy slots; `history`
 * enables role reconstruction from events when AccessControl cannot enumerate holders.
 */
export async function discoverTokenAuthority(
  reader: ChainReader,
  token: Hex,
  structure: AccountStructure | undefined,
  history?: TokenHistoryOptions,
): Promise<TokenAuthority> {
  const r = recording(reader, TOKEN_AUTHORITY_LIMITS);
  const remaining = () => TOKEN_AUTHORITY_LIMITS.maxReads - r.reads.length;
  const call = (
    functionName: Parameters<typeof encodeFunctionData<typeof abi>>[0]['functionName'],
  ) => r.call(token, encodeFunctionData({ abi, functionName } as never));
  const supports = (id: string) =>
    r.call(
      token,
      encodeFunctionData({ abi, functionName: 'supportsInterface', args: [id as Hex] }),
    );

  const [
    symbol,
    decimals,
    supply,
    paused,
    owner,
    pending,
    defaultAdmin,
    masterMinter,
    pauser,
    blacklister,
    rescuer,
    ac,
    ace,
    zosWord,
  ] = await Promise.all([
    call('symbol'),
    call('decimals'),
    call('totalSupply'),
    call('paused'),
    call('owner'),
    call('pendingOwner'),
    call('defaultAdmin'),
    call('masterMinter'),
    call('pauser'),
    call('blacklister'),
    call('rescuer'),
    supports(IACCESS_CONTROL),
    supports(IACCESS_CONTROL_ENUMERABLE),
    r.storage(token, ZEPPELINOS_ADMIN_SLOT),
  ]);
  const flag = (p: ProbeResult) =>
    decoded(p, (data) => decodeFunctionResult({ abi, functionName: 'supportsInterface', data }));
  const accessControl = flag(ace) ? 'enumerable' : flag(ac) ? 'non-enumerable' : 'absent';

  const roles: Role[] = [
    addressRole(owner, 'owner', 'ownable', 'owner'),
    addressRole(pending, 'pending-owner', 'ownable2step', 'pendingOwner'),
    addressRole(
      defaultAdmin,
      'default-admin',
      'access-control-default-admin-rules',
      'defaultAdmin',
    ),
    addressRole(masterMinter, 'master-minter', 'fiat-token', 'masterMinter'),
    addressRole(pauser, 'pauser', 'fiat-token', 'pauser'),
    addressRole(blacklister, 'blacklister', 'fiat-token', 'blacklister'),
    addressRole(rescuer, 'rescuer', 'fiat-token', 'rescuer'),
  ].filter((v): v is Role => v !== null);

  const admins: { address: Hex; source: Role['source'] }[] = [];
  if (structure?.eip1967?.admin)
    admins.push({ address: lower(structure.eip1967.admin), source: 'eip1967-admin-slot' });
  const zos = slotAddress(zosWord);
  if (zos !== 'empty' && zos !== 'malformed')
    admins.push({ address: zos, source: 'zeppelinos-admin-slot' });
  for (const { address, source } of admins)
    roles.push({ role: 'proxy-admin', source, holders: [address], holdersComplete: true });

  // Budget: 14 baseline reads + 5 role counts leave 13; holder classification (8) and one owner()
  // hop per proxy admin are reserved first, members get what is left.
  const reserve = TOKEN_AUTHORITY_LIMITS.maxClassifiedAuthorities + admins.length;
  if (accessControl === 'enumerable')
    roles.push(...(await enumerateRoles(r, token, () => remaining() - reserve)));
  // Separate, fixed budget (ROLE_HISTORY_LIMITS); holders found here join classification below.
  const roleHistory =
    accessControl === 'non-enumerable' && history
      ? await discoverRoleHistory(
          history.reader,
          reader,
          token,
          history.snapshotBlock,
          history.attested,
        )
      : null;
  if (roleHistory) roles.push(...roleHistory.roles);

  // ProxyAdmin contracts (OpenZeppelin 4/5) are themselves owned; their owner can upgrade.
  for (const { address } of admins) {
    const adminOwner = addressRole(
      await r.call(address, encodeFunctionData({ abi, functionName: 'owner' })),
      'upgrader',
      'proxy-admin-owner',
      'owner',
    );
    if (adminOwner?.holders.length) roles.push(adminOwner);
  }

  const distinct = [...new Set(roles.flatMap((role) => role.holders))];
  const checked = distinct.slice(
    0,
    Math.min(TOKEN_AUTHORITY_LIMITS.maxClassifiedAuthorities, remaining()),
  );
  const codes = await Promise.all(checked.map((address) => r.code(address as Hex)));
  const authorities = distinct.map((address, i) => {
    const code = codes[i];
    if (code === undefined) return { address, kind: 'not-checked' as const };
    if (code === '0x') return { address, kind: 'no-code' as const };
    return {
      address,
      kind: parseDelegation(code) ? ('eip-7702-delegated' as const) : ('contract' as const),
    };
  });

  const symbolValue = decoded(symbol, (data) =>
    decodeFunctionResult({ abi, functionName: 'symbol', data }),
  );
  const decimalsValue = decoded(decimals, (data) =>
    decodeFunctionResult({ abi, functionName: 'decimals', data }),
  );
  const supplyValue = decoded(supply, (data) =>
    decodeFunctionResult({ abi, functionName: 'totalSupply', data }),
  );
  const pausedValue = decoded(paused, (data) =>
    decodeFunctionResult({ abi, functionName: 'paused', data }),
  );
  const limitations = [
    'Holder claims are accessor responses from contract code; a lookalike can return the same data.',
    'Only standard roles are read (Ownable, AccessControl MINTER/BURNER/PAUSER/UPGRADER/DEFAULT_ADMIN, DefaultAdminRules, FiatToken). Custom roles, timelock delays and multisig thresholds of holders are not analyzed.',
    'FiatToken minters are configured by the master minter and are not enumerable from accessors.',
  ];
  if (accessControl === 'non-enumerable' && !roleHistory)
    limitations.push(
      'AccessControl is present but not enumerable; role holders require event history.',
    );
  if (roleHistory) {
    const h = roleHistory.history;
    limitations.push(
      'Role history assumes the contract emits RoleGranted/RoleRevoked for every role change, as OpenZeppelin AccessControl does; holders are confirmed with hasRole at the observed block.',
    );
    if (!h.historyAttested)
      limitations.push(
        'The provider is not attested to serve full log history (chain setting fullLogHistory); pruned history can omit grants, so role sets are not claimed complete.',
      );
    if (h.gaps.length)
      limitations.push(
        `${h.gaps.length} block range(s) were not covered within the log request budget.`,
      );
    if (h.unrecognizedRoleIds.length)
      limitations.push(
        `${h.unrecognizedRoleIds.length} non-standard role id(s) appear in events and were not analyzed.`,
      );
  }
  if (authorities.some((a) => a.kind === 'not-checked'))
    limitations.push('Some authority addresses were not classified because of the read budget.');
  return TokenAuthority.parse({
    adapter: 'token-authority/1.1.0',
    symbol: symbolValue !== null && symbolValue.length <= MAX_SYMBOL_LENGTH ? symbolValue : null,
    decimals: decimalsValue !== null && decimalsValue <= UINT8_MAX ? Number(decimalsValue) : null,
    totalSupply: supplyValue === null ? null : supplyValue.toString(),
    paused: pausedValue,
    accessControl,
    roles,
    authorities,
    reads: r.reads,
    ...(roleHistory ? { roleHistory: roleHistory.history } : {}),
    limitations,
  });
}
