import {
  encodeEventTopics,
  encodeFunctionData,
  encodeFunctionResult,
  keccak256,
  parseAbi,
  toFunctionSelector,
  toHex,
  type Hex,
} from 'viem';
import type { FakeChain } from './account-structure.js';

/**
 * Deterministic synthetic token state for token-authority tests. Calldata and return data are
 * produced by viem's ABI encoder; role ids are derived (keccak256 of the role name), not copied.
 */
export const tokenAbi = parseAbi([
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
type Name = (typeof tokenAbi)[number]['name'];

export const ROLE = {
  'default-admin': toHex(0n, { size: 32 }),
  minter: keccak256(toHex('MINTER_ROLE')),
  burner: keccak256(toHex('BURNER_ROLE')),
  pauser: keccak256(toHex('PAUSER_ROLE')),
  upgrader: keccak256(toHex('UPGRADER_ROLE')),
} as const;

/** ERC-165 id: XOR of the interface's function selectors. */
export function interfaceId(signatures: string[]): Hex {
  const xor = signatures.reduce((acc, s) => acc ^ BigInt(toFunctionSelector(s)), 0n);
  return toHex(xor, { size: 4 });
}
export const IACCESS_CONTROL = interfaceId([
  'hasRole(bytes32,address)',
  'getRoleAdmin(bytes32)',
  'grantRole(bytes32,address)',
  'revokeRole(bytes32,address)',
  'renounceRole(bytes32,address)',
]);
export const IACCESS_CONTROL_ENUMERABLE = interfaceId([
  'getRoleMember(bytes32,uint256)',
  'getRoleMemberCount(bytes32)',
]);

export const sel = (name: Name) =>
  toFunctionSelector(tokenAbi.find((f) => f.name === name)!).toLowerCase();
export const ret = (functionName: Name, result: unknown) =>
  encodeFunctionResult({ abi: tokenAbi, functionName, result } as never);
const data = (functionName: Name, args: unknown[]) =>
  encodeFunctionData({ abi: tokenAbi, functionName, args } as never).toLowerCase();

/** Call map entries for an AccessControlEnumerable token with the given role members. */
export function enumerableRoles(
  members: Partial<Record<keyof typeof ROLE, Hex[]>>,
  counts: Partial<Record<keyof typeof ROLE, bigint>> = {},
): Record<string, Hex> {
  const calls: Record<string, Hex> = {
    [data('supportsInterface', [IACCESS_CONTROL])]: ret('supportsInterface', true),
    [data('supportsInterface', [IACCESS_CONTROL_ENUMERABLE])]: ret('supportsInterface', true),
  };
  for (const [role, id] of Object.entries(ROLE) as [keyof typeof ROLE, Hex][]) {
    const list = members[role] ?? [];
    calls[data('getRoleMemberCount', [id])] = ret(
      'getRoleMemberCount',
      counts[role] ?? BigInt(list.length),
    );
    list.forEach((m, i) => {
      calls[data('getRoleMember', [id, BigInt(i)])] = ret('getRoleMember', m);
    });
  }
  return calls;
}

/** Non-enumerable AccessControl: IAccessControl only. */
export const accessControlOnly = (): Record<string, Hex> => ({
  [data('supportsInterface', [IACCESS_CONTROL])]: ret('supportsInterface', true),
  [data('supportsInterface', [IACCESS_CONTROL_ENUMERABLE])]: ret('supportsInterface', false),
});

/** ERC20 metadata entries. */
export const erc20 = (symbol = 'TKN', decimals = 6, supply = 1_000_000n): Record<string, Hex> => ({
  [sel('symbol')]: ret('symbol', symbol),
  [sel('decimals')]: ret('decimals', decimals),
  [sel('totalSupply')]: ret('totalSupply', supply),
});

export type { FakeChain };

// --- Role history fixtures. Event selectors are derived from the signature strings.
const historyAbi = parseAbi([
  'function hasRole(bytes32 role, address account) view returns (bool)',
  'event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)',
  'event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)',
]);
const SENDER = `0x${'ab'.repeat(20)}` as Hex;
/** A provider-shaped RoleGranted/RoleRevoked log built with viem's event encoder. */
export function roleLog(
  token: Hex,
  kind: 'granted' | 'revoked',
  role: Hex,
  account: Hex,
  block: bigint,
  logIndex = 0,
) {
  const topics = encodeEventTopics({
    abi: historyAbi,
    eventName: kind === 'granted' ? 'RoleGranted' : 'RoleRevoked',
    args: { role, account, sender: SENDER },
  } as never);
  return {
    address: token,
    topics,
    data: '0x',
    blockNumber: toHex(block),
    transactionHash: keccak256(toHex(`${block}:${logIndex}`)),
    logIndex: toHex(logIndex),
    removed: false,
  };
}

/** hasRole call-map entries: every listed (role, account) answers `holds`. */
export function hasRoleCalls(entries: [Hex, Hex, boolean][]): Record<string, Hex> {
  return Object.fromEntries(
    entries.map(([role, account, holds]) => [
      encodeFunctionData({
        abi: historyAbi,
        functionName: 'hasRole',
        args: [role, account],
      }).toLowerCase(),
      encodeFunctionResult({ abi: historyAbi, functionName: 'hasRole', result: holds }),
    ]),
  );
}

type RawLog = ReturnType<typeof roleLog>;
/**
 * In-memory log provider. `maxRange` models a block-range cap (wider requests are refused);
 * `unavailableBelow` models pruned history. Logs are filtered exactly like eth_getLogs.
 */
export function fakeLogs(
  logs: RawLog[],
  options: { maxRange?: bigint; unavailableBelow?: bigint } = {},
) {
  const requests: [bigint, bigint][] = [];
  return {
    requests,
    reader: {
      logs: async (address: Hex, topic0: readonly Hex[], fromBlock: bigint, toBlock: bigint) => {
        requests.push([fromBlock, toBlock]);
        if (options.unavailableBelow !== undefined && fromBlock < options.unavailableBelow)
          return { outcome: 'unavailable' as const };
        if (options.maxRange !== undefined && toBlock - fromBlock + 1n > options.maxRange)
          return { outcome: 'range-limited' as const };
        return {
          outcome: 'returned' as const,
          logs: logs.filter(
            (l) =>
              l.address.toLowerCase() === address.toLowerCase() &&
              topic0.includes(l.topics[0]!) &&
              BigInt(l.blockNumber) >= fromBlock &&
              BigInt(l.blockNumber) <= toBlock,
          ),
        };
      },
    },
  };
}
