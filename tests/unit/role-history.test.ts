import { describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import {
  InconsistentHistory,
  discoverRoleHistory,
} from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/role-history.js';
import { discoverTokenAuthority } from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/token-authority.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { ROLE_HISTORY_LIMITS } from '../../packages/domain-models/src/index.js';
import { ADDRESS, TENANT_A, observation } from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  fakeReader,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import {
  ROLE,
  accessControlOnly,
  fakeLogs,
  hasRoleCalls,
  roleLog,
} from '../../packages/test-fixtures/src/token-authority.js';

const TOKEN = ADDRESS as Hex;
const HEAD = 1_000n;
const OTHER_ROLE = `0x${'12'.repeat(32)}` as Hex;
const grant = (role: Hex, account: Hex, block: bigint, index = 0) =>
  roleLog(TOKEN, 'granted', role, account, block, index);
const revoke = (role: Hex, account: Hex, block: bigint, index = 0) =>
  roleLog(TOKEN, 'revoked', role, account, block, index);
const chain = (holds: [Hex, Hex, boolean][]): FakeChain => ({
  calls: { [TOKEN]: { ...accessControlOnly(), ...hasRoleCalls(holds) } },
});
const run = (
  logs: ReturnType<typeof grant>[],
  holds: [Hex, Hex, boolean][],
  options: Parameters<typeof fakeLogs>[1] = {},
  attested = true,
) => {
  const provider = fakeLogs(logs, options);
  return {
    provider,
    result: discoverRoleHistory(provider.reader, fakeReader(chain(holds)), TOKEN, HEAD, attested),
  };
};
const role = (r: Awaited<ReturnType<typeof run>['result']>, name: string) =>
  r.roles.find((x) => x.role === name)!;

describe('role history reconstruction', () => {
  it('replays grants and revokes, then confirms holders with hasRole', async () => {
    const { result } = run(
      [
        grant(ROLE['default-admin'], addr('11'), 1n),
        grant(ROLE.minter, addr('22'), 5n),
        grant(ROLE.minter, addr('33'), 6n),
        revoke(ROLE.minter, addr('33'), 9n),
      ],
      [
        [ROLE['default-admin'], addr('11'), true],
        [ROLE.minter, addr('22'), true],
      ],
    );
    const r = await result;
    expect(role(r, 'default-admin')).toMatchObject({
      holders: [addr('11')],
      holdersComplete: true,
    });
    // A revoked-last account is not asked and not reported.
    expect(role(r, 'minter')).toEqual({
      role: 'minter',
      source: 'access-control-events',
      holders: [addr('22')],
      holdersComplete: true,
    });
    expect(role(r, 'burner')).toMatchObject({ holders: [], holdersComplete: true });
    expect(r.history).toMatchObject({ complete: true, gaps: [], fromBlock: '0', toBlock: '1000' });
    expect(r.history.requests).toEqual([
      { fromBlock: '0', toBlock: '1000', outcome: 'returned', logCount: 4 },
    ]);
    expect(r.history.reads).toHaveLength(2);
  });

  it('never invents a holder from logs alone: state wins over events', async () => {
    const r = await run([grant(ROLE.minter, addr('22'), 5n)], [[ROLE.minter, addr('22'), false]])
      .result;
    expect(role(r, 'minter')).toMatchObject({ holders: [], holdersComplete: true });
  });

  it('bisects refused ranges newest-first and covers the whole history within budget', async () => {
    const { result, provider } = run(
      [grant(ROLE.minter, addr('22'), 10n), grant(ROLE.pauser, addr('44'), 900n)],
      [
        [ROLE.minter, addr('22'), true],
        [ROLE.pauser, addr('44'), true],
      ],
      { maxRange: 501n },
    );
    const r = await result;
    expect(provider.requests.map(([a, b]) => `${a}-${b}`)).toEqual(['0-1000', '501-1000', '0-500']);
    expect(r.history.complete).toBe(true);
    expect(role(r, 'minter').holders).toEqual([addr('22')]);
  });

  it('reports gaps when the request budget runs out; covered holders still verify', async () => {
    const { result } = run(
      [grant(ROLE.minter, addr('22'), 10n), grant(ROLE.minter, addr('55'), 990n)],
      [
        [ROLE.minter, addr('22'), true],
        [ROLE.minter, addr('55'), true],
      ],
      { maxRange: 20n },
    );
    const r = await result;
    expect(r.history.requests).toHaveLength(ROLE_HISTORY_LIMITS.maxLogRequests);
    expect(r.history.gaps.length).toBeGreaterThan(0);
    expect(r.history.complete).toBe(false);
    // Newest-first: the recent grant is covered, the oldest range is a gap.
    expect(role(r, 'minter')).toMatchObject({ holders: [addr('55')], holdersComplete: false });
    expect(r.history.gaps[0]!.fromBlock).toBe('0');
  });

  it('does not split pruned history and records it as a gap', async () => {
    const { result, provider } = run([], [], { unavailableBelow: 1n });
    const r = await result;
    expect(provider.requests).toHaveLength(1);
    expect(r.history.gaps).toEqual([{ fromBlock: '0', toBlock: '1000' }]);
    expect(role(r, 'minter').holdersComplete).toBe(false);
  });

  it('never claims completeness without an attested full log history', async () => {
    const r = await run([], [], {}, false).result;
    expect(r.history).toMatchObject({ gaps: [], historyAttested: false, complete: false });
    expect(r.roles.every((x) => !x.holdersComplete)).toBe(true);
  });

  it('caps verifications, asking supply and logic roles first', async () => {
    const pausers = Array.from({ length: 8 }, (_, i) =>
      grant(ROLE.pauser, addr((0x30 + i).toString(16)), 500n + BigInt(i)),
    );
    const r = await run(
      [...pausers, grant(ROLE.minter, addr('22'), 1n)],
      [[ROLE.minter, addr('22'), true]],
    ).result;
    expect(r.history.reads).toHaveLength(ROLE_HISTORY_LIMITS.maxVerifications);
    expect(role(r, 'minter')).toMatchObject({ holders: [addr('22')], holdersComplete: true });
    expect(role(r, 'pauser').holdersComplete).toBe(false);
  });

  it('records custom role ids without analyzing them', async () => {
    const r = await run([grant(OTHER_ROLE, addr('22'), 3n)], []).result;
    expect(r.history.unrecognizedRoleIds).toEqual([OTHER_ROLE]);
    expect(r.history.events[0]!.role).toBeNull();
    expect(r.history.reads).toHaveLength(0);
  });

  it('splits a response with more events than the evidence cap', async () => {
    const many = Array.from({ length: ROLE_HISTORY_LIMITS.maxEvents + 1 }, (_, i) =>
      grant(OTHER_ROLE, addr('22'), BigInt(i), 0),
    );
    const r = await run(many, []).result;
    expect(r.history.requests[0]!.outcome).toBe('range-limited');
    expect(r.history.events.length).toBeLessThanOrEqual(ROLE_HISTORY_LIMITS.maxEvents);
  });

  it('orders events by chain position regardless of response order', async () => {
    const logs = [revoke(ROLE.minter, addr('22'), 7n, 1), grant(ROLE.minter, addr('22'), 7n, 0)];
    const r = await run(logs, [[ROLE.minter, addr('22'), true]]).result;
    expect(r.history.events.map((e) => e.kind)).toEqual(['granted', 'revoked']);
    // Revoked last within the same block: not a candidate.
    expect(r.history.reads).toHaveLength(0);
  });

  it.each([
    ['another address', { address: addr('99') }],
    ['a block outside the range', { blockNumber: '0x5000' }],
    ['a removed log', { removed: true }],
    ['a non-address account topic', { topicsAt2: `0x${'ff'.repeat(32)}` }],
    ['missing topics', { topicsLength: 3 }],
  ])('fails closed on a log with %s', async (_, change) => {
    const base = grant(ROLE.minter, addr('22'), 5n);
    const topics = [...base.topics];
    if ('topicsAt2' in change) topics[2] = change.topicsAt2 as Hex;
    const log = {
      ...base,
      ...('address' in change ? { address: change.address } : {}),
      ...('blockNumber' in change ? { blockNumber: change.blockNumber } : {}),
      ...('removed' in change ? { removed: change.removed } : {}),
      topics: 'topicsLength' in change ? topics.slice(0, change.topicsLength) : topics,
    };
    const reader = { logs: async () => ({ outcome: 'returned' as const, logs: [log] }) };
    await expect(
      discoverRoleHistory(reader, fakeReader({}), TOKEN, HEAD, true),
    ).rejects.toBeInstanceOf(InconsistentHistory);
  });

  it('is deterministic', async () => {
    const logs = [grant(ROLE.minter, addr('22'), 5n), grant(ROLE.burner, addr('33'), 6n)];
    const holds: [Hex, Hex, boolean][] = [
      [ROLE.minter, addr('22'), true],
      [ROLE.burner, addr('33'), true],
    ];
    expect(await run(logs, holds, { maxRange: 300n }).result).toEqual(
      await run(logs, holds, { maxRange: 300n }).result,
    );
  });
});

describe('token authority with role history', () => {
  const tokenChain = (holds: [Hex, Hex, boolean][]): FakeChain => ({
    calls: { [TOKEN]: { ...accessControlOnly(), ...hasRoleCalls(holds) } },
  });
  const assessed = async (attested: boolean) => {
    const provider = fakeLogs([
      grant(ROLE.minter, addr('22'), 5n),
      grant(ROLE['default-admin'], addr('11'), 1n),
    ]);
    const tokenAuthority = await discoverTokenAuthority(
      fakeReader(
        tokenChain([
          [ROLE.minter, addr('22'), true],
          [ROLE['default-admin'], addr('11'), true],
        ]),
      ),
      TOKEN,
      undefined,
      { reader: provider.reader, snapshotBlock: HEAD, attested },
    );
    return {
      tokenAuthority,
      a: assessWallet(TENANT_A, { ...observation, code: '0x6000', tokenAuthority }),
    };
  };

  it('feeds event-derived holders into classification, findings and the graph', async () => {
    const { tokenAuthority, a } = await assessed(true);
    expect(tokenAuthority.adapter).toBe('token-authority/1.1.0');
    expect(tokenAuthority.authorities).toEqual([
      { address: addr('11'), kind: 'no-code' },
      { address: addr('22'), kind: 'no-code' },
    ]);
    const ids = a.posture.findings.map((f) => f.ruleId);
    expect(ids).toContain('CV-TOKEN-003');
    // Complete, attested history: the authority set is not reported incomplete.
    expect(ids).not.toContain('CV-TOKEN-004');
    expect(a.trustGraph.edges).toContainEqual({
      from: `eip155:1:${ADDRESS}`,
      to: `eip155:1:${addr('22')}`,
      relation: 'token-minter-accessor-reports',
    });
  });

  it('reports an incomplete authority set when history is not attested', async () => {
    const { a } = await assessed(false);
    const incomplete = a.posture.findings.find((f) => f.ruleId === 'CV-TOKEN-004');
    expect(incomplete?.rationale).toMatch(/not attested/);
  });

  it('does not read history for enumerable or absent AccessControl', async () => {
    const provider = fakeLogs([]);
    await discoverTokenAuthority(fakeReader({}), TOKEN, undefined, {
      reader: provider.reader,
      snapshotBlock: HEAD,
      attested: true,
    });
    expect(provider.requests).toHaveLength(0);
  });

  it('keeps 1.0.0 documents valid', async () => {
    const { tokenAuthority } = await assessed(true);
    const legacy = { ...tokenAuthority, adapter: 'token-authority/1.0.0' as const };
    delete (legacy as { roleHistory?: unknown }).roleHistory;
    expect(() =>
      assessWallet(TENANT_A, { ...observation, code: '0x6000', tokenAuthority: legacy }),
    ).not.toThrow();
  });
});
