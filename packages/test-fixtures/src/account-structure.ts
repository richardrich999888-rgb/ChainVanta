import { encodeFunctionResult, parseAbi, toFunctionSelector, toHex, type Hex } from 'viem';
import type { StructureReader } from '../../../modules/01-wallet-intelligence/src/discovery/account-structure.js';
import { fixtureTransport } from './fixtures.js';

/**
 * Deterministic synthetic chain state for account-structure tests. Addresses are test-only
 * constants. Return data is produced by viem's ABI encoder, not hand-written hex.
 */
export const abi = parseAbi([
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function VERSION() view returns (string)',
  'function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)',
  'function entryPoint() view returns (address)',
  'function implementation() view returns (address)',
]);
type FunctionName = (typeof abi)[number]['name'];

export const addr = (byte: string) => `0x${byte.repeat(20)}` as Hex;
export const word = (address: Hex) =>
  `0x${address.slice(2).toLowerCase().padStart(64, '0')}` as Hex;
export const SENTINEL = '0x0000000000000000000000000000000000000001' as Hex;
export const selector = (name: FunctionName) =>
  toFunctionSelector(abi.find((f) => f.name === name)!);
export const encode = (functionName: FunctionName, result: unknown) =>
  encodeFunctionResult({ abi, functionName, result } as never);
/** EIP-7702 designator for `delegate`. */
export const designator = (delegate: Hex) => `0xef0100${delegate.slice(2)}` as Hex;
export const minimalProxy = (implementation: Hex) =>
  `0x363d3d373d3d3d363d73${implementation.slice(2)}5af43d82803e903d91602b57fd5bf3` as Hex;

export interface FakeChain {
  code?: Record<string, Hex>;
  storage?: Record<string, Record<string, Hex>>;
  /** Return data by target and full calldata or 4-byte selector (full calldata wins). Missing entries revert. */
  calls?: Record<string, Record<string, Hex>>;
}

const key = (value: string) => value.toLowerCase();

function lookup(chain: FakeChain) {
  return {
    code: (target: string) => chain.code?.[key(target)] ?? ('0x' as Hex),
    storage: (target: string, slot: string) =>
      chain.storage?.[key(target)]?.[key(slot)] ?? toHex(0n, { size: 32 }),
    call: (target: string, data: string) =>
      chain.calls?.[key(target)]?.[key(data)] ??
      chain.calls?.[key(target)]?.[key(data.slice(0, 10))],
  };
}

/** Reader port over the fake chain; `delay` lets tests reorder completion deterministically. */
export function fakeReader(
  chain: FakeChain,
  delay: (n: number) => number = () => 0,
): StructureReader & { count: () => number } {
  const state = lookup(chain);
  let n = 0;
  const wait = () => new Promise((r) => setTimeout(r, delay(n++)));
  return {
    count: () => n,
    storage: async (t, s) => (await wait(), state.storage(t, s)),
    code: async (t) => (await wait(), state.code(t)),
    call: async (t, d) => {
      await wait();
      const data = state.call(t, d);
      return data ? { outcome: 'returned', data } : { outcome: 'reverted' };
    },
  };
}

/**
 * JSON-RPC transport over the fake chain. Unknown calls revert with `revertCode`, so tests can
 * model geth's code 3 and -32000 forms. Block and account basics come from the shared fixture.
 */
export function fakeChainTransport(
  chain: FakeChain,
  revert: { code: number; message: string } = { code: -32000, message: 'execution reverted' },
): typeof fetch {
  const state = lookup(chain);
  return async (url, init) => {
    const request = JSON.parse(String(init?.body));
    const reply = (result: unknown) => Response.json({ jsonrpc: '2.0', id: request.id, result });
    const [first, second] = request.params as [unknown, unknown];
    switch (request.method) {
      case 'eth_getCode':
        return reply(state.code(first as string));
      case 'eth_getStorageAt':
        return reply(state.storage(first as string, second as string));
      case 'eth_call': {
        const { to, data } = first as { to: string; data: string };
        const result = state.call(to, data);
        return result
          ? reply(result)
          : Response.json({ jsonrpc: '2.0', id: request.id, error: revert });
      }
      default:
        return fixtureTransport(url, init);
    }
  };
}
