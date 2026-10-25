import { describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import { EvmConnector, RpcFailure } from '../../connectors/blockchains/ethereum/src/index.js';
import { EIP1967_SLOTS } from '../../modules/01-wallet-intelligence/src/discovery/account-structure.js';
import { ZEPPELINOS_ADMIN_SLOT } from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/token-authority.js';
import { ROLE_HISTORY_LIMITS } from '../../packages/domain-models/src/index.js';
import { ADDRESS, testConfig } from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  fakeChainTransport,
  word,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import {
  ROLE,
  accessControlOnly,
  erc20,
  hasRoleCalls,
  ret,
  roleLog,
  sel,
} from '../../packages/test-fixtures/src/token-authority.js';

const TOKEN = ADDRESS as Hex;
const RUNTIME = '0x6080604052' as Hex;
/** The monitoring worker's per-job RPC cap (services/job-worker/cpm-worker.ts). */
const WORKER_RPC_CAP = 60;
type LogsHandler = (params: { fromBlock: string; toBlock: string }) => unknown;

/** Chain transport with an eth_getLogs handler; counts every JSON-RPC request. */
function withLogs(chain: FakeChain, handler: LogsHandler) {
  const base = fakeChainTransport(chain);
  let calls = 0;
  const transport: typeof fetch = async (url, init) => {
    calls++;
    const request = JSON.parse(String(init?.body));
    if (request.method !== 'eth_getLogs') return base(url, init);
    const outcome = handler(request.params[0]);
    if (outcome instanceof Response) return outcome;
    return Response.json({ jsonrpc: '2.0', id: request.id, ...(outcome as object) });
  };
  return { transport, calls: () => calls };
}
const nonEnumerable = (holds: [Hex, Hex, boolean][] = []): FakeChain => ({
  code: { [TOKEN]: RUNTIME },
  calls: { [TOKEN]: { ...erc20(), ...accessControlOnly(), ...hasRoleCalls(holds) } },
});
const observe = (transport: typeof fetch, fullLogHistory = true) =>
  new EvmConnector({ ...testConfig.chains[0]!, fullLogHistory }, transport).observe(ADDRESS, {
    adapter: 'token-authority',
  });

describe('EVM connector role history', () => {
  it('reads logs over [0, snapshot] and honors the operator attestation', async () => {
    const log = roleLog(TOKEN, 'granted', ROLE.minter, addr('22'), 5n);
    const chain = nonEnumerable([[ROLE.minter, addr('22'), true]]);
    const { transport } = withLogs(chain, () => ({ result: [log] }));
    const attested = (await observe(transport)).tokenAuthority!;
    expect(attested.roleHistory).toMatchObject({ toBlock: '256', complete: true });
    expect(
      attested.roles.find((r) => r.source === 'access-control-events' && r.role === 'minter'),
    ).toMatchObject({ holders: [addr('22')], holdersComplete: true });
    const unattested = (await observe(withLogs(chain, () => ({ result: [log] })).transport, false))
      .tokenAuthority!;
    expect(unattested.roleHistory?.complete).toBe(false);
  });

  it.each([
    ['EIP-1474 limit code', { error: { code: -32005, message: 'limit exceeded' } }],
    [
      'result-count wording',
      { error: { code: -32000, message: 'query returned more than 10000 results' } },
    ],
    ['response-size wording', { error: { code: -32602, message: 'Log response size exceeded.' } }],
  ])('splits the range on a %s', async (_, refusal) => {
    const { transport } = withLogs(nonEnumerable(), ({ fromBlock, toBlock }) =>
      BigInt(toBlock) - BigInt(fromBlock) > 200n ? refusal : { result: [] },
    );
    const history = (await observe(transport)).tokenAuthority!.roleHistory!;
    expect(history.requests[0]!.outcome).toBe('range-limited');
    expect(history.gaps).toEqual([]);
  });

  it('splits on an oversized response body instead of failing', async () => {
    let first = true;
    const { transport } = withLogs(nonEnumerable(), () => {
      if (!first) return { result: [] };
      first = false;
      return new Response(`{"jsonrpc":"2.0","id":1,"result":["${'0'.repeat(1_100_000)}"]}`);
    });
    const history = (await observe(transport)).tokenAuthority!.roleHistory!;
    expect(history.requests.map((r) => r.outcome)).toEqual([
      'range-limited',
      'returned',
      'returned',
    ]);
  });

  it('records pruned history as a gap without splitting', async () => {
    const { transport } = withLogs(nonEnumerable(), () => ({
      error: { code: -32000, message: 'history has been pruned' },
    }));
    const history = (await observe(transport)).tokenAuthority!.roleHistory!;
    expect(history.requests).toHaveLength(1);
    expect(history.gaps).toEqual([{ fromBlock: '0', toBlock: '256' }]);
  });

  it.each([
    [
      'an unclassified provider error',
      () => ({ error: { code: -32000, message: 'internal error' } }),
    ],
    ['a non-array result', () => ({ result: { logs: [] } })],
    [
      'a log for another address',
      () => ({ result: [roleLog(addr('99'), 'granted', ROLE.minter, addr('22'), 5n)] }),
    ],
  ])('fails the observation on %s', async (_, handler) => {
    await expect(
      observe(withLogs(nonEnumerable(), handler as LogsHandler).transport),
    ).rejects.toBeInstanceOf(RpcFailure);
  });

  it(`stays within the worker's ${WORKER_RPC_CAP}-call cap in the worst case`, async () => {
    // Proxied token, every single-holder accessor answering a distinct address, a ZeppelinOS and
    // an EIP-1967 admin with an owner, a provider that refuses all but tiny ranges, and more
    // grant-last candidates than the verification budget.
    const proxyAdmin = addr('70');
    const implementation = addr('71');
    const candidates = Array.from({ length: 12 }, (_, i) => addr((0x30 + i).toString(16)));
    const chain: FakeChain = {
      code: { [TOKEN]: RUNTIME, [proxyAdmin]: RUNTIME, [implementation]: RUNTIME },
      storage: {
        [TOKEN]: {
          [EIP1967_SLOTS.implementation]: word(implementation),
          [EIP1967_SLOTS.admin]: word(proxyAdmin),
          [ZEPPELINOS_ADMIN_SLOT]: word(addr('72')),
        },
      },
      calls: {
        [TOKEN]: {
          ...erc20(),
          ...accessControlOnly(),
          [sel('owner')]: ret('owner', addr('a1')),
          [sel('pendingOwner')]: ret('pendingOwner', addr('a2')),
          [sel('defaultAdmin')]: ret('defaultAdmin', addr('a3')),
          [sel('masterMinter')]: ret('masterMinter', addr('a4')),
          [sel('pauser')]: ret('pauser', addr('a5')),
          [sel('blacklister')]: ret('blacklister', addr('a6')),
          [sel('rescuer')]: ret('rescuer', addr('a7')),
          ...hasRoleCalls(candidates.map((c) => [ROLE.minter, c, true])),
        },
        [proxyAdmin]: { [sel('owner')]: ret('owner', addr('a8')) },
      },
    };
    const logs = candidates.map((c, i) =>
      roleLog(TOKEN, 'granted', ROLE.minter, c, 250n + BigInt(i % 6), i),
    );
    const { transport, calls } = withLogs(chain, ({ fromBlock, toBlock }) =>
      BigInt(toBlock) - BigInt(fromBlock) > 8n
        ? { error: { code: -32005, message: 'limit exceeded' } }
        : {
            result: logs.filter(
              (l) =>
                BigInt(l.blockNumber) >= BigInt(fromBlock) &&
                BigInt(l.blockNumber) <= BigInt(toBlock),
            ),
          },
    );
    const authority = (await observe(transport)).tokenAuthority!;
    expect(authority.roleHistory!.requests).toHaveLength(ROLE_HISTORY_LIMITS.maxLogRequests);
    expect(authority.roleHistory!.reads).toHaveLength(ROLE_HISTORY_LIMITS.maxVerifications);
    expect(calls()).toBeLessThanOrEqual(WORKER_RPC_CAP);
  });
});
