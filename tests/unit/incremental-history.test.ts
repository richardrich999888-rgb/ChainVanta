import { describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import {
  InconsistentHistory,
  discoverRoleHistory,
  type HistorySeed,
} from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/role-history.js';
import { EvmConnector } from '../../connectors/blockchains/ethereum/src/index.js';
import { ROLE_HISTORY_LIMITS, type RoleHistory } from '../../packages/domain-models/src/index.js';
import { ADDRESS, testConfig } from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  fakeChainTransport,
  fakeReader,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import {
  ROLE,
  accessControlOnly,
  erc20,
  fakeLogs,
  hasRoleCalls,
  roleLog,
} from '../../packages/test-fixtures/src/token-authority.js';

const TOKEN = ADDRESS as Hex;
const EVIDENCE = `sha256:${'a'.repeat(64)}`;
const BLOCK_HASH = `0x${'cd'.repeat(32)}`;
const grant = (account: Hex, block: bigint, role: Hex = ROLE.minter) =>
  roleLog(TOKEN, 'granted', role, account, block);
const chain = (holds: [Hex, Hex, boolean][]): FakeChain => ({
  calls: { [TOKEN]: { ...accessControlOnly(), ...hasRoleCalls(holds) } },
});
const seedOf = (history: RoleHistory): HistorySeed => ({
  history,
  evidenceHash: EVIDENCE,
  blockHash: BLOCK_HASH,
});
const run = (
  logs: ReturnType<typeof grant>[],
  holds: [Hex, Hex, boolean][],
  head: bigint,
  seed?: HistorySeed,
  options: Parameters<typeof fakeLogs>[1] = {},
  attested = true,
) => {
  const provider = fakeLogs(logs, options);
  return discoverRoleHistory(
    provider.reader,
    fakeReader(chain(holds)),
    TOKEN,
    head,
    attested,
    seed,
  ).then((result) => ({ ...result, requests: provider.requests }));
};
const minter = (r: Awaited<ReturnType<typeof run>>) => r.roles.find((x) => x.role === 'minter')!;

describe('incremental role history', () => {
  it('reads only blocks after the seed and re-verifies every holder at the new block', async () => {
    const first = await run([grant(addr('11'), 10n)], [[ROLE.minter, addr('11'), true]], 100n);
    const logs = [grant(addr('11'), 10n), grant(addr('22'), 150n)];
    const second = await run(
      logs,
      [
        [ROLE.minter, addr('11'), true],
        [ROLE.minter, addr('22'), true],
      ],
      200n,
      seedOf(first.history),
    );
    expect(second.requests).toEqual([[101n, 200n]]);
    expect(second.history.events.map((e) => e.blockNumber)).toEqual(['10', '150']);
    expect(minter(second)).toMatchObject({
      holders: [addr('22'), addr('11')],
      holdersComplete: true,
    });
    expect(second.history.reads).toHaveLength(2);
    expect(second.history.basedOn).toEqual({
      evidenceHash: EVIDENCE,
      toBlock: '100',
      blockHash: BLOCK_HASH,
    });
  });

  it('drops a carried holder whose role was revoked on chain since the seed', async () => {
    const first = await run([grant(addr('11'), 10n)], [[ROLE.minter, addr('11'), true]], 100n);
    const revoke = roleLog(TOKEN, 'revoked', ROLE.minter, addr('11'), 120n);
    const second = await run(
      [revoke],
      [[ROLE.minter, addr('11'), false]],
      200n,
      seedOf(first.history),
    );
    expect(minter(second).holders).toEqual([]);
    expect(second.history.reads).toHaveLength(0);
  });

  it('converges to complete coverage over successive monitoring runs on a capped provider', async () => {
    const logs = [grant(addr('11'), 3n), grant(addr('22'), 4000n)];
    const holds: [Hex, Hex, boolean][] = [
      [ROLE.minter, addr('11'), true],
      [ROLE.minter, addr('22'), true],
    ];
    const cap = { maxRange: 600n };
    let seed: HistorySeed | undefined;
    const gapsPerRun: number[] = [];
    let last: Awaited<ReturnType<typeof run>> | undefined;
    for (const head of [4100n, 4110n, 4120n, 4130n, 4140n]) {
      last = await run(logs, holds, head, seed, cap);
      expect(last.requests.length).toBeLessThanOrEqual(ROLE_HISTORY_LIMITS.maxLogRequests);
      gapsPerRun.push(last.history.gaps.length);
      seed = seedOf(last.history);
      if (last.history.complete) break;
    }
    expect(gapsPerRun[0]).toBeGreaterThan(0);
    expect(last!.history.complete).toBe(true);
    expect(minter(last!)).toMatchObject({
      holders: [addr('22'), addr('11')],
      holdersComplete: true,
    });
  });

  it('only re-reads gaps when the head has not moved', async () => {
    const first = await run([], [], 100n, undefined, { unavailableBelow: 1n });
    const second = await run([], [], 100n, seedOf(first.history));
    expect(second.requests).toEqual([[0n, 100n]]);
    expect(second.history.complete).toBe(true);
  });

  it.each([
    ['a different attestation regime', { attested: false }],
    ['a seed ahead of the snapshot (provider regression)', { head: 50n }],
  ])('ignores the seed for %s and rescans from block 0', async (_, change) => {
    const first = await run([grant(addr('11'), 10n)], [[ROLE.minter, addr('11'), true]], 100n);
    const head = 'head' in change ? change.head : 200n;
    const second = await run(
      [grant(addr('11'), 10n)],
      [[ROLE.minter, addr('11'), true]],
      head,
      seedOf(first.history),
      {},
      'attested' in change ? change.attested : true,
    );
    expect(second.requests[0]).toEqual([0n, head]);
    expect(second.history.basedOn).toBeUndefined();
  });

  it.each([
    [
      'an event beyond its range',
      (h: RoleHistory) => ({ ...h, events: [{ ...h.events[0]!, blockNumber: '500' }] }),
    ],
    [
      'an event inside its own gap',
      (h: RoleHistory) => ({ ...h, gaps: [{ fromBlock: '5', toBlock: '20' }] }),
    ],
    [
      'a gap beyond its range',
      (h: RoleHistory) => ({ ...h, gaps: [{ fromBlock: '90', toBlock: '300' }] }),
    ],
  ])('fails closed on a seed with %s', async (_, corrupt) => {
    const first = await run([grant(addr('11'), 10n)], [[ROLE.minter, addr('11'), true]], 100n);
    await expect(run([], [], 200n, seedOf(corrupt(first.history)))).rejects.toBeInstanceOf(
      InconsistentHistory,
    );
  });
});

describe('connector collection context', () => {
  const CHAIN = { ...testConfig.chains[0]!, fullLogHistory: true };
  const token: FakeChain = {
    code: { [TOKEN]: '0x6080604052' },
    calls: {
      [TOKEN]: {
        ...erc20(),
        ...accessControlOnly(),
        ...hasRoleCalls([[ROLE.minter, addr('11'), true]]),
      },
    },
  };
  /** Transport answering eth_getLogs from `logs` and recording requested ranges. */
  const transport = (ranges: string[]) => {
    const base = fakeChainTransport(token);
    const fn: typeof fetch = async (url, init) => {
      const request = JSON.parse(String(init?.body));
      if (request.method !== 'eth_getLogs') return base(url, init);
      const { fromBlock, toBlock } = request.params[0];
      ranges.push(`${BigInt(fromBlock)}-${BigInt(toBlock)}`);
      const log = grant(addr('11'), 5n);
      const inRange = BigInt(fromBlock) <= 5n && 5n <= BigInt(toBlock);
      return Response.json({ jsonrpc: '2.0', id: request.id, result: inRange ? [log] : [] });
    };
    return fn;
  };
  const observe = (ranges: string[], context?: Parameters<EvmConnector['observe']>[2]) =>
    new EvmConnector(CHAIN, transport(ranges)).observe(
      ADDRESS,
      { adapter: 'token-authority' },
      context,
    );

  it('carries history from a previous observation of the same token', async () => {
    const firstRanges: string[] = [];
    const first = await observe(firstRanges);
    const previous = {
      observation: {
        ...first,
        blockNumber: '0x80',
        tokenAuthority: {
          ...first.tokenAuthority!,
          roleHistory: { ...first.tokenAuthority!.roleHistory!, toBlock: '128' },
        },
      },
      evidenceHash: EVIDENCE,
    };
    const ranges: string[] = [];
    const second = await observe(ranges, { previous });
    expect(firstRanges).toEqual(['0-256']);
    expect(ranges).toEqual(['129-256']);
    expect(second.tokenAuthority!.roleHistory!.basedOn?.evidenceHash).toBe(EVIDENCE);
    expect(
      second.tokenAuthority!.roles.find(
        (r) => r.source === 'access-control-events' && r.role === 'minter',
      )?.holders,
    ).toEqual([addr('11')]);
  });

  it('fails closed when carried history does not end at its snapshot block', async () => {
    const first = await observe([]);
    const observation = { ...first, blockNumber: '0x80' }; // History still ends at 256.
    await expect(
      observe([], { previous: { observation, evidenceHash: EVIDENCE } }),
    ).rejects.toThrow('Carried role history does not end at its snapshot block');
  });

  it('ignores a previous observation of another address or chain', async () => {
    const first = await observe([]);
    for (const observation of [
      { ...first, address: addr('99') },
      { ...first, chainId: first.chainId + 1 },
    ]) {
      const ranges: string[] = [];
      const o = await observe(ranges, { previous: { observation, evidenceHash: EVIDENCE } });
      expect(ranges).toEqual(['0-256']);
      expect(o.tokenAuthority!.roleHistory!.basedOn).toBeUndefined();
    }
  });
});
