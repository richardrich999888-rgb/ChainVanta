import { describe, expect, it } from 'vitest';
import { EvmConnector, RpcFailure } from '../../connectors/blockchains/ethereum/src/index.js';
import { EIP1967_SLOTS } from '../../modules/01-wallet-intelligence/src/discovery/account-structure.js';
import { ADDRESS, BLOCK_HASH, testConfig } from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  encode,
  fakeChainTransport,
  selector,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';

const CHAIN = testConfig.chains[0]!;
const RUNTIME = '0x6080604052' as const;
const OWNERS = [addr('44'), addr('55')];
const safe: FakeChain = {
  code: { [ADDRESS]: RUNTIME },
  calls: {
    [ADDRESS]: {
      [selector('getOwners')]: encode('getOwners', OWNERS),
      [selector('getThreshold')]: encode('getThreshold', 2n),
    },
  },
};

/** Records every JSON-RPC request the connector sends. */
function recorded(transport: typeof fetch) {
  const requests: { method: string; params: unknown[] }[] = [];
  const wrapped: typeof fetch = async (url, init) => {
    requests.push(JSON.parse(String(init?.body)));
    return transport(url, init);
  };
  return { requests, wrapped };
}

describe('EVM connector account-structure collection', () => {
  it.each([
    ['code 3 with revert data', { code: 3, message: 'execution reverted: nope' }],
    ['code -32000 without revert data', { code: -32000, message: 'execution reverted' }],
    [
      'Hardhat -32603 revert',
      { code: -32603, message: 'Error: Transaction reverted without a reason string' },
    ],
    [
      'Hardhat invalid opcode halt',
      { code: -32603, message: 'VM Exception while processing transaction: invalid opcode' },
    ],
    ['geth invalid opcode halt', { code: -32000, message: 'invalid opcode: INVALID' }],
    ['geth out-of-gas halt', { code: -32000, message: 'out of gas' }],
    ['revm halt', { code: -32000, message: 'EVM error InvalidFEOpcode' }],
    ['Nethermind execution error', { code: -32015, message: 'VM execution error.' }],
  ])('treats %s as an interface answer, not a failure', async (_, revert) => {
    const observation = await new EvmConnector(CHAIN, fakeChainTransport(safe, revert)).observe(
      ADDRESS,
    );
    expect(observation.structure?.safe).toMatchObject({ owners: OWNERS, threshold: 2 });
    expect(observation.structure?.safe?.modulesComplete).toBe(false);
  });

  it('fails the observation on non-revert provider errors instead of reporting absence', async () => {
    for (const error of [
      { code: -32005, message: 'rate limit exceeded' },
      { code: -32000, message: 'header not found' },
      { code: -32603, message: 'internal error' },
      { code: -32000, message: 'nonrevertible state unavailable' },
    ])
      await expect(
        new EvmConnector(CHAIN, fakeChainTransport(safe, error)).observe(ADDRESS),
      ).rejects.toBeInstanceOf(RpcFailure);
  });

  it('never surfaces upstream error text', async () => {
    const secret = 'https://user:token@provider.example/key';
    const error = await new EvmConnector(
      CHAIN,
      fakeChainTransport(safe, { code: -32005, message: secret }),
    )
      .observe(ADDRESS)
      .catch((e: Error) => e);
    expect(String((error as Error).message)).not.toContain('token');
  });

  it('pins every structure read to the snapshot block hash', async () => {
    const { requests, wrapped } = recorded(fakeChainTransport(safe));
    await new EvmConnector(CHAIN, wrapped).observe(ADDRESS);
    const structural = requests.filter(
      (r) =>
        r.method === 'eth_getStorageAt' ||
        r.method === 'eth_call' ||
        (r.method === 'eth_getCode' && r.params[0] !== ADDRESS),
    );
    expect(structural.length).toBeGreaterThan(0);
    for (const request of structural)
      expect(request.params.at(-1)).toEqual({ blockHash: BLOCK_HASH, requireCanonical: true });
  });

  it('normalizes minimal storage quantities to 32-byte words', async () => {
    const implementation = addr('11');
    const transport = fakeChainTransport({
      code: { [ADDRESS]: RUNTIME },
      storage: {
        [ADDRESS]: {
          [EIP1967_SLOTS.implementation]: `0x${implementation.slice(2)}` as `0x${string}`,
          [EIP1967_SLOTS.admin]: '0x0',
        },
      },
    });
    const observation = await new EvmConnector(CHAIN, transport).observe(ADDRESS);
    expect(observation.structure?.eip1967?.implementation).toBe(implementation);
    expect(observation.structure?.eip1967?.admin).toBeNull();
  });

  it('makes no structure reads for accounts without code', async () => {
    const { requests, wrapped } = recorded(fakeChainTransport({}));
    const observation = await new EvmConnector(CHAIN, wrapped).observe(ADDRESS);
    expect(observation.structure).toBeUndefined();
    expect(requests.map((r) => r.method)).not.toContain('eth_getStorageAt');
    expect(requests.map((r) => r.method)).not.toContain('eth_call');
  });
});
