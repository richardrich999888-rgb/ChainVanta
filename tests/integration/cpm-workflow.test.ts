import { beforeEach, afterEach, describe, it, expect } from 'vitest';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { CpmRepository } from '../../services/inventory-service/src/cpm-repository.js';
import { CpmWorker } from '../../services/job-worker/cpm-worker.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { signedTransactionFixture } from '../../packages/test-fixtures/src/transaction.js';
import {
  TENANT_A,
  ADDRESS,
  observation,
  testConfig,
  fixtureTransport,
  BLOCK_HASH,
} from '../../packages/test-fixtures/src/fixtures.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { effectiveStatus } from '../../core/policy-engine/exceptions/index.js';
import type { Assessment } from '../../packages/domain-models/src/index.js';
describe('CPM end-to-end evidence workflow', () => {
  let db: Awaited<ReturnType<typeof testDatabase>>, base: PostgresRepository, cpm: CpmRepository;
  beforeEach(async () => {
    db = await testDatabase();
    base = new PostgresRepository(db.pool);
    cpm = new CpmRepository(base);
  });
  afterEach(async () => {
    await db?.close();
  });
  const seed = async (a: Assessment) => {
    await base.save(a);
    return cpm.assess(TENANT_A, a.id);
  };
  it('collects a verified signature, resolves only a defined missing-evidence finding, and reopens on regression', async () => {
    const tx = await signedTransactionFixture();
    const a = assessWallet(TENANT_A, { ...observation, address: tx.address });
    const snapshot = await seed(a);
    for (const status of ['acknowledged', 'in_remediation', 'pending_verification'] as const)
      await cpm.transition(
        TENANT_A,
        snapshot.id,
        'CV-CPM-EVIDENCE',
        { status, reason: 'Track supplied signature evidence verification' },
        'admin',
      );
    const transport: typeof fetch = async (url, init) => {
      const call = JSON.parse(String(init?.body));
      let result;
      if (call.method === 'eth_getTransactionByHash') result = tx.raw;
      if (call.method === 'eth_getTransactionReceipt') result = tx.receipt;
      if (call.method === 'eth_getBlockByNumber')
        result =
          call.params[0] === '0x100'
            ? { number: '0x100', hash: BLOCK_HASH, timestamp: '0x65000000' }
            : { number: '0x101', hash: `0x${'cd'.repeat(32)}`, timestamp: '0x65000001' };
      return result
        ? Response.json({ jsonrpc: '2.0', id: 1, result })
        : fixtureTransport(url, init);
    };
    const worker = new CpmWorker(cpm, testConfig.chains, 'worker-fixture', transport);
    await worker.jobs.create(
      TENANT_A,
      { input: { address: tx.address, chainId: 1, transactionHash: tx.hash }, intervalSeconds: 60 },
      'analyst',
    );
    expect(await worker.tick(TENANT_A)).toBe(true);
    const state = (await cpm.posture(TENANT_A, snapshot.assetId))!;
    expect(state.snapshot.quantumExposure).toBe('exposed');
    expect(state.snapshot.publicKeyExposure).toBe('recoverable-from-verified-signature');
    expect(state.lifecycle.find((f) => f.rule_id === 'CV-CPM-EVIDENCE')?.status).toBe('resolved');
    expect(state.lifecycle.find((f) => f.rule_id === 'CV-QUANTUM-001')?.status).toBe('open');
    const drift = await cpm.list(TENANT_A, 'drift', 100, 0);
    expect(drift.some((d) => d.type === 'ALGORITHM_OBSERVED')).toBe(true);
    await cpm.assess(TENANT_A, state.snapshot.assessmentId);
    expect(await cpm.list(TENANT_A, 'drift', 100, 0)).toEqual(drift);
    await cpm.invalidate(
      TENANT_A,
      (await base.get(TENANT_A, state.snapshot.assessmentId))!,
      'Fixture canonicality changed',
    );
    expect(
      (await cpm.posture(TENANT_A, snapshot.assetId))!.lifecycle.find(
        (f) => f.rule_id === 'CV-CPM-EVIDENCE',
      )?.status,
    ).toBe('open');
    await expect(cpm.assess(TENANT_A, state.snapshot.assessmentId)).rejects.toThrow('Invalidated');
    const b = assessWallet(TENANT_A, {
      ...observation,
      address: tx.address,
      blockNumber: '0x102',
      blockHash: `0x${'45'.repeat(32)}`,
      observedAt: new Date().toISOString(),
    });
    await seed(b);
    const regressed = (await cpm.posture(TENANT_A, snapshot.assetId))!;
    expect(regressed.lifecycle.find((f) => f.rule_id === 'CV-CPM-EVIDENCE')?.status).toBe('open');
    expect(regressed.lifecycle.find((f) => f.rule_id === 'CV-QUANTUM-001')?.status).not.toBe(
      'resolved',
    );
  });
  it('keeps outstanding findings when policy rules are disabled and reproduces retained versions', async () => {
    const a = assessWallet(TENANT_A, observation),
      original = await seed(a);
    const policy = { ...defaultPolicy, version: '2.0.0', enabled: false };
    await cpm.policies.publish(TENANT_A, policy, 'admin');
    const changed = await cpm.assess(TENANT_A, a.id, { id: policy.id, version: policy.version });
    expect(changed.findings).toHaveLength(0);
    const state = (await cpm.posture(TENANT_A, original.assetId))!;
    expect(
      state.currentFindings.some(
        (f) => f.ruleId === 'CV-WALLET-001' && f.effectiveStatus === 'open',
      ),
    ).toBe(true);
    expect(await cpm.history(TENANT_A, original.assetId, 100, 0)).toHaveLength(2);
    expect(evaluateCpm((await base.get(TENANT_A, a.id))!, defaultPolicy)).toEqual(original);
    await base.findingEvent(
      TENANT_A,
      a.id,
      'CV-WALLET-001',
      { status: 'acknowledged', reason: 'Legacy endpoint shares the CPM state machine' },
      'admin',
    );
    expect(
      (await cpm.posture(TENANT_A, original.assetId))!.lifecycle.find(
        (e) => e.rule_id === 'CV-WALLET-001',
      )?.status,
    ).toBe('acknowledged');
  });
  it('fails collection without removing earlier posture or findings', async () => {
    const original = await seed(assessWallet(TENANT_A, observation));
    const worker = new CpmWorker(cpm, testConfig.chains, 'worker-failure', async () => {
      throw new Error('secret upstream failure');
    });
    await worker.jobs.create(
      TENANT_A,
      { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 },
      'analyst',
    );
    await worker.tick(TENANT_A);
    expect(await cpm.history(TENANT_A, original.assetId, 100, 0)).toHaveLength(1);
    const state = (await cpm.posture(TENANT_A, original.assetId))!;
    expect(state.monitoring[0]?.last_failure).toBe('collection_failed');
    expect(state.currentStatus).toBe('collection_failed');
    expect(state.currentQuantumExposure).toBe('unknown');
    expect(state.lifecycle.some((e) => e.status === 'resolved')).toBe(false);
    expect(JSON.stringify(await cpm.list(TENANT_A, 'notifications', 100, 0))).not.toContain(
      'secret',
    );
  });
  it('records timeouts and fences a transport that ignores abort', async () => {
    const original = await seed(assessWallet(TENANT_A, observation));
    const worker = new CpmWorker(
      cpm,
      testConfig.chains,
      'worker-timeout',
      async () => new Promise(() => {}),
      20,
    );
    await worker.jobs.create(
      TENANT_A,
      { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 },
      'analyst',
    );
    await worker.tick(TENANT_A);
    expect((await cpm.posture(TENANT_A, original.assetId))!.monitoring[0]?.last_failure).toBe(
      'assessment_timeout',
    );
    expect(await base.list(TENANT_A)).toHaveLength(1);
  });
  it('invalidates reorganized finalized evidence and schedules recollection without deleting history', async () => {
    const original = await seed(assessWallet(TENANT_A, observation));
    const worker = new CpmWorker(cpm, testConfig.chains, 'worker-reorg', async (url, init) => {
      const call = JSON.parse(String(init?.body));
      return call.method === 'eth_getBlockByNumber'
        ? Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { number: '0x100', hash: `0x${'ef'.repeat(32)}`, timestamp: '0x65000000' },
          })
        : fixtureTransport(url, init);
    });
    await worker.jobs.create(
      TENANT_A,
      { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 },
      'analyst',
    );
    await worker.tick(TENANT_A);
    const state = (await cpm.posture(TENANT_A, original.assetId))!;
    expect(state.snapshot.validity).toBe('invalidated');
    expect(state.monitoring[0]?.last_failure).toBe('canonicality_changed');
    expect(await base.list(TENANT_A)).toHaveLength(1);
    expect(await cpm.latestValidAssessment(TENANT_A, original.assetId)).toBeNull();
  });
  it('expires exceptions and keeps administrative closure distinct from verified resolution', async () => {
    const original = await seed(assessWallet(TENANT_A, observation));
    await base.scoped(TENANT_A, (c) =>
      cpm.event(
        c,
        TENANT_A,
        original,
        'CV-WALLET-001',
        'excepted',
        'Historical exception with recorded actor',
        'admin',
        '2020-01-01T00:00:00.000Z',
      ),
    );
    const old = (await cpm.posture(TENANT_A, original.assetId))!.lifecycle.find(
      (e) => e.rule_id === 'CV-WALLET-001',
    )!;
    expect(effectiveStatus(old)).toBe('open');
    const next = await seed(
      assessWallet(TENANT_A, {
        ...observation,
        blockNumber: '0x101',
        observedAt: new Date().toISOString(),
      }),
    );
    expect(
      (await cpm.posture(TENANT_A, original.assetId))!.lifecycle.find(
        (e) => e.rule_id === 'CV-WALLET-001',
      )?.status,
    ).toBe('open');
    await cpm.transition(
      TENANT_A,
      next.id,
      'CV-WALLET-001',
      { status: 'administratively_closed', reason: 'Accepted administrative disposition only' },
      'admin',
    );
    expect(
      (await cpm.posture(TENANT_A, original.assetId))!.lifecycle.find(
        (e) => e.rule_id === 'CV-WALLET-001',
      )?.status,
    ).toBe('administratively_closed');
    await expect(
      base.findingEvent(
        TENANT_A,
        next.assessmentId,
        'CV-WALLET-001',
        { status: 'resolved', reason: 'Cannot label technical resolution' },
        'admin',
      ),
    ).rejects.toThrow('verification');
  });
  it('verifies a later scoped owner accessor change and refuses unsupported quantum migration', async () => {
    const token = {
      adapter: 'ownable-erc20/1.0.0' as const,
      owner: ADDRESS,
      totalSupply: '10',
      decimals: 6,
      calls: Array.from({ length: 3 }, () => ({ data: '0x', result: '0x' })),
      limitation: 'Accessor evidence only',
    };
    const a = assessWallet(TENANT_A, { ...observation, code: '0x6000', token });
    await seed(a);
    const expected = `0x${'42'.repeat(20)}`;
    const request = {
      assessmentId: a.id,
      goal: 'authorization-change' as const,
      scope: 'Verify the defined owner() accessor value only',
      criteria: [{ kind: 'owner_equals' as const, expected }],
    };
    const plan = await cpm.migration(TENANT_A, request, 'analyst');
    expect(plan.status).toBe('READY_FOR_PLANNING');
    const b = assessWallet(TENANT_A, {
      ...observation,
      blockNumber: '0x101',
      code: '0x6000',
      token: { ...token, owner: expected },
    });
    await seed(b);
    const verified = await cpm.migration(
      TENANT_A,
      { ...request, assessmentId: b.id },
      'analyst',
      plan.id,
    );
    expect(verified.status).toBe('VERIFIED_FOR_DEFINED_SCOPE');
    expect(
      await cpm.migration(TENANT_A, { ...request, assessmentId: b.id }, 'analyst', plan.id),
    ).toEqual(verified);
    const missing = assessWallet(TENANT_A, { ...observation, blockNumber: '0x102' });
    await seed(missing);
    expect(
      (await cpm.migration(TENANT_A, { ...request, assessmentId: missing.id }, 'analyst', plan.id))
        .status,
    ).toBe('NEEDS_ADDITIONAL_EVIDENCE');
    expect(
      (
        await cpm.migration(
          TENANT_A,
          {
            ...request,
            assessmentId: missing.id,
            goal: 'cryptographic-migration',
            criteria: [{ kind: 'signature_algorithm', expected: 'ML-DSA' }],
          },
          'analyst',
        )
      ).status,
    ).toBe('TECHNICALLY_BLOCKED');
    await cpm.invalidate(TENANT_A, b, 'Fixture canonicality changed');
    expect((await cpm.getMigration(TENANT_A, verified.id))!.document).toMatchObject({
      status: 'VERIFIED_FOR_DEFINED_SCOPE',
      validity: 'invalidated',
      effectiveStatus: 'PENDING_VERIFICATION',
    });
  });
});
