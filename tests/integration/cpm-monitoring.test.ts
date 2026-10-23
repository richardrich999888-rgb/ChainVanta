import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { CpmPolicyStore } from '../../services/inventory-service/src/cpm-policy-store.js';
import { MonitoringStore } from '../../services/inventory-service/src/monitoring-store.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import {
  TENANT_A,
  TENANT_B,
  ADDRESS,
  observation,
} from '../../packages/test-fixtures/src/fixtures.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
describe('Durable monitoring and immutable policy registry', () => {
  let db: Awaited<ReturnType<typeof testDatabase>>,
    base: PostgresRepository,
    policies: CpmPolicyStore,
    jobs: MonitoringStore;
  beforeAll(async () => {
    db = await testDatabase();
    base = new PostgresRepository(db.pool);
    policies = new CpmPolicyStore(base);
    jobs = new MonitoringStore(policies, 1, 2);
    await base.save(assessWallet(TENANT_A, observation));
  });
  afterAll(async () => {
    await db?.close();
  });
  it('retains policy versions and rejects mutation and cross-tenant assignment', async () => {
    await policies.publish(TENANT_A, defaultPolicy, 'admin');
    await expect(
      policies.publish(TENANT_A, { ...defaultPolicy, enabled: false }, 'admin'),
    ).rejects.toThrow('immutable');
    await policies.publish(TENANT_A, { ...defaultPolicy, version: '1.1.0' }, 'admin');
    expect(await policies.list(TENANT_A, 25, 0)).toHaveLength(2);
    await expect(
      policies.assign(
        TENANT_B,
        {
          assetId: `eip155:1:${ADDRESS}`,
          policy: { id: defaultPolicy.id, version: '1.0.0' },
          operationalImportance: 'critical',
        },
        'admin',
      ),
    ).rejects.toThrow('not found');
  });
  it('claims exactly one lease across competing workers and enforces RPC budgets', async () => {
    const s = await jobs.create(
      TENANT_A,
      { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 },
      'analyst',
    );
    expect(
      (
        await jobs.create(
          TENANT_A,
          { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 },
          'analyst',
        )
      ).id,
    ).toBe(s.id);
    await expect(
      jobs.create(
        TENANT_A,
        { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 120 },
        'analyst',
      ),
    ).rejects.toThrow('already exists');
    expect(await jobs.enqueueDue(TENANT_A)).toBe(1);
    expect(await jobs.enqueueDue(TENANT_A)).toBe(0);
    const claimed = await Promise.all([
      jobs.claim(TENANT_A, 'worker-a'),
      new MonitoringStore(policies, 1, 2).claim(TENANT_A, 'worker-b'),
    ]);
    expect(claimed.filter(Boolean)).toHaveLength(1);
    const job = claimed.find(Boolean)!;
    expect(await jobs.consumeRpc(job)).toBe(true);
    expect(await jobs.consumeRpc(job)).toBe(true);
    expect(await jobs.consumeRpc(job)).toBe(false);
    expect(await jobs.get(TENANT_B, job.id)).toBeNull();
    await jobs.update(TENANT_A, s.id, { enabled: false }, 'admin');
    await expect(
      jobs.complete(job, assessWallet(TENANT_A, observation), async () => {}),
    ).rejects.toThrow('lease');
    expect(await base.list(TENANT_A)).toHaveLength(1);
  });
  it('recovers expired leases after restart, fences old tokens, and preserves findings on failure', async () => {
    await jobs.create(
      TENANT_A,
      { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 },
      'analyst',
    );
    await jobs.enqueueDue(TENANT_A);
    const old = (await jobs.claim(TENANT_A, 'crashed'))!;
    await base.scoped(TENANT_A, (c) =>
      c.query("UPDATE assessment_jobs SET lease_until=now()-interval '1 second' WHERE id=$1", [
        old.id,
      ]),
    );
    expect(await jobs.claim(TENANT_A, 'restart')).toBeNull();
    await base.scoped(TENANT_A, (c) =>
      c.query('UPDATE assessment_jobs SET available_at=now() WHERE id=$1', [old.id]),
    );
    const next = (await jobs.claim(TENANT_A, 'restart'))!;
    expect(next.id).toBe(old.id);
    expect(next.lease_token).not.toBe(old.lease_token);
    await expect(
      jobs.complete(old, assessWallet(TENANT_A, observation), async () => {}),
    ).rejects.toThrow('lease');
    await expect(
      jobs.complete(next, assessWallet(TENANT_A, observation), async () => {
        throw new Error('CPM transaction failure');
      }),
    ).rejects.toThrow('CPM transaction failure');
    expect(await jobs.fail(next, 'collection_failed')).toBe(true);
    expect((await jobs.get(TENANT_A, next.id)).status).toBe('retry');
    expect(await base.list(TENANT_A)).toHaveLength(1);
    const schedules = await jobs.list(TENANT_A, 25, 0);
    expect(schedules.some((s) => s.last_failure === 'collection_failed')).toBe(true);
  });
  it('exhausts bounded retries and leaves a durable terminal failure', async () => {
    const retry = (
      await base.scoped(TENANT_A, (c) =>
        c.query("SELECT id FROM assessment_jobs WHERE tenant_id=$1 AND status='retry' LIMIT 1", [
          TENANT_A,
        ]),
      )
    ).rows[0];
    await base.scoped(TENANT_A, (c) =>
      c.query('UPDATE assessment_jobs SET attempts=4,available_at=now() WHERE id=$1', [retry.id]),
    );
    const last = (await jobs.claim(TENANT_A, 'last-attempt'))!;
    expect(last.attempts).toBe(5);
    await jobs.fail(last, 'collection_failed');
    expect((await jobs.get(TENANT_A, last.id)).status).toBe('failed');
    expect(await jobs.claim(TENANT_A, 'after-exhaustion')).toBeNull();
  });
  it('forces tenant RLS on every new table even without tenant predicates', async () => {
    await base.scoped(TENANT_B, async (c) => {
      for (const name of [
        'monitoring_schedules',
        'assessment_jobs',
        'worker_leases',
        'rpc_budgets',
        'posture_snapshots',
        'snapshot_invalidations',
        'cryptographic_drift_events',
        'migration_assessments',
        'notification_events',
      ])
        expect((await c.query(`SELECT * FROM ${name}`)).rows).toHaveLength(0);
    });
    await expect(
      base.scoped(TENANT_B, (c) =>
        c.query('INSERT INTO worker_leases(tenant_id,worker_id) VALUES($1,$2)', [
          TENANT_A,
          'forged',
        ]),
      ),
    ).rejects.toThrow();
  });
});
