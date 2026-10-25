import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { CpmRepository } from '../../services/inventory-service/src/cpm-repository.js';
import { CpmWorker } from '../../services/job-worker/cpm-worker.js';
import {
  ADDRESS,
  TENANT_A,
  observation,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { addr, fakeChainTransport } from '../../packages/test-fixtures/src/account-structure.js';
import {
  ROLE,
  accessControlOnly,
  erc20,
  hasRoleCalls,
  roleLog,
} from '../../packages/test-fixtures/src/token-authority.js';
import { canonicalAssetId, type Assessment } from '../../packages/domain-models/src/index.js';

const TOKEN = ADDRESS as Hex;
/** Provider block-range cap; small enough that one run cannot cover the history. */
const MAX_RANGE = 40n;
/** Per-chain RPC rate limit high enough for several ticks inside one test minute. */
const TEST_RPC_PER_MINUTE = 10_000;
const blockHash = (n: bigint) => `0x${n.toString(16).padStart(64, '0')}`;

/**
 * A chain whose finalized head advances between ticks. Blocks are canonical by number, so the
 * worker's isCanonical check of the previous snapshot passes. eth_getLogs enforces MAX_RANGE.
 */
function movingChain() {
  let head = 0x100n;
  const logs = [
    roleLog(TOKEN, 'granted', ROLE.minter, addr('11'), 3n),
    roleLog(TOKEN, 'granted', ROLE.minter, addr('22'), 0xf0n),
  ];
  const base = fakeChainTransport({
    code: { [TOKEN]: '0x6080604052' },
    calls: {
      [TOKEN]: {
        ...erc20(),
        ...accessControlOnly(),
        ...hasRoleCalls([
          [ROLE.minter, addr('11'), true],
          [ROLE.minter, addr('22'), true],
        ]),
      },
    },
  });
  const transport: typeof fetch = async (url, init) => {
    const request = JSON.parse(String(init?.body));
    const reply = (result: unknown) => Response.json({ jsonrpc: '2.0', id: request.id, result });
    if (request.method === 'eth_getBlockByNumber') {
      const n = request.params[0] === 'finalized' ? head : BigInt(request.params[0]);
      return reply({ number: `0x${n.toString(16)}`, hash: blockHash(n), timestamp: '0x65000000' });
    }
    if (request.method === 'eth_getLogs') {
      const from = BigInt(request.params[0].fromBlock);
      const to = BigInt(request.params[0].toBlock);
      if (to - from + 1n > MAX_RANGE)
        return Response.json({
          jsonrpc: '2.0',
          id: request.id,
          error: { code: -32005, message: 'limit exceeded' },
        });
      return reply(
        logs.filter((l) => BigInt(l.blockNumber) >= from && BigInt(l.blockNumber) <= to),
      );
    }
    return base(url, init);
  };
  return { transport, advance: (blocks: bigint) => (head += blocks) };
}

describe('incremental role history through the monitoring worker', () => {
  let db: Awaited<ReturnType<typeof testDatabase>>, cpm: CpmRepository, base: PostgresRepository;
  beforeEach(async () => {
    db = await testDatabase();
    base = new PostgresRepository(db.pool);
    cpm = new CpmRepository(base);
  });
  afterEach(async () => {
    await db?.close();
  });

  it('carries verified history between ticks and converges to complete coverage', async () => {
    const chain = movingChain();
    const chains = [{ ...testConfig.chains[0]!, fullLogHistory: true }];
    const worker = new CpmWorker(
      cpm,
      chains,
      'worker-history',
      chain.transport,
      60_000,
      2,
      TEST_RPC_PER_MINUTE,
    );
    // Register the asset with a plain snapshot at the chain's canonical block 0x100.
    const registered = assessWallet(TENANT_A, { ...observation, blockHash: blockHash(0x100n) });
    await base.save(registered);
    await cpm.assess(TENANT_A, registered.id);
    const schedule = await worker.jobs.create(
      TENANT_A,
      { input: { address: ADDRESS, chainId: 1, adapter: 'token-authority' }, intervalSeconds: 60 },
      'analyst',
    );
    const asset = canonicalAssetId(1, ADDRESS);
    const runs: Assessment[] = [];
    for (let tick = 0; tick < 12; tick++) {
      expect(await worker.tick(TENANT_A)).toBe(true);
      const latest = (await cpm.latestValidAssessment(TENANT_A, asset))!;
      runs.push(latest);
      const h = latest.observation.tokenAuthority!.roleHistory!;
      if (h.complete) break;
      chain.advance(10n);
      await worker.jobs.update(TENANT_A, schedule.id, { intervalSeconds: 60 }, 'analyst');
    }
    const histories = runs.map((r) => r.observation.tokenAuthority!.roleHistory!);
    expect(histories[0]!.basedOn).toBeUndefined();
    expect(histories[0]!.complete).toBe(false);
    // Each later run is chained to the run before it.
    for (let i = 1; i < runs.length; i++)
      expect(histories[i]!.basedOn).toMatchObject({
        evidenceHash: runs[i - 1]!.evidenceHash,
        toBlock: histories[i - 1]!.toBlock,
      });
    const last = runs.at(-1)!.observation.tokenAuthority!;
    expect(last.roleHistory!.complete).toBe(true);
    expect(
      last.roles.find((r) => r.source === 'access-control-events' && r.role === 'minter'),
    ).toMatchObject({ holders: [addr('22'), addr('11')], holdersComplete: true });
    expect(runs.length).toBeGreaterThan(1);
  });
});
