import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import type { INestApplication } from '@nestjs/common';
import { createApp } from '../../services/api-gateway/src/app.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import {
  ADDRESS,
  TENANT_A,
  TENANT_B,
  KEY_A,
  KEY_B,
  fixtureTransport,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { ChainVantaClient } from '../../sdks/typescript/src/index.js';
describe('Authenticated CPM API and SDK', () => {
  let db: Awaited<ReturnType<typeof testDatabase>>,
    app: INestApplication,
    base: string,
    assessmentId: string,
    snapshotId: string;
  const admin = 'admin-cpm-fixture-key-at-least-32-characters',
    viewer = 'viewer-cpm-fixture-key-at-least-32-characters',
    adminB = 'admin-b-cpm-fixture-key-at-least-32-characters';
  const req = (path: string, key = KEY_A, method = 'GET', body?: unknown) =>
    fetch(`${base}/v1${path}`, {
      method,
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  beforeAll(async () => {
    db = await testDatabase();
    app = await createApp(
      {
        ...testConfig,
        tenantKeys: [
          ...testConfig.tenantKeys,
          { tenantId: TENANT_A, key: admin, role: 'admin' },
          { tenantId: TENANT_A, key: viewer, role: 'viewer' },
          { tenantId: TENANT_B, key: adminB, role: 'admin' },
        ],
      },
      new PostgresRepository(db.pool),
      fixtureTransport,
    );
    await app.listen(0, '127.0.0.1');
    base = await app.getUrl();
    assessmentId = (
      await (await req('/assessments', KEY_A, 'POST', { address: ADDRESS, chainId: 1 })).json()
    ).id;
  });
  afterAll(async () => {
    await app?.close();
    await db?.close();
  });
  it('authenticates all reads and derives tenants from credentials', async () => {
    for (const path of ['policies', 'monitoring', 'drift', 'remediation', 'notifications']) {
      expect((await fetch(`${base}/v1/cpm/${path}`)).status).toBe(401);
      expect((await req(`/cpm/${path}`, viewer)).status).toBe(200);
    }
    const client = new ChainVantaClient(base, KEY_A),
      state = await client.posture(`eip155:1:${ADDRESS}`);
    snapshotId = state.snapshot.id;
    expect(state.snapshot.quantumExposure).toBe('unknown');
    expect((await req(`/cpm/posture/eip155:1:${ADDRESS}`, KEY_B)).status).toBe(404);
    expect((await req('/cpm/assess', KEY_B, 'POST', { assessmentId })).status).toBe(404);
    expect(
      (await req('/cpm/assess', KEY_A, 'POST', { assessmentId, tenantId: TENANT_B })).status,
    ).toBe(400);
  });
  it('restricts policy writes and management to tenant administrators', async () => {
    expect((await req('/cpm/policies', KEY_A, 'POST', defaultPolicy)).status).toBe(403);
    expect(
      (await req('/cpm/policies', admin, 'POST', { ...defaultPolicy, version: '1.1.0' })).status,
    ).toBe(201);
    expect(
      (await req('/cpm/policies', admin, 'POST', { ...defaultPolicy, enabled: false })).status,
    ).toBe(409);
    expect(
      (await req('/cpm/policies/web3-baseline', KEY_A, 'PATCH', { active: false })).status,
    ).toBe(403);
    expect(
      (await req('/cpm/policies/web3-baseline', admin, 'PATCH', { active: false })).status,
    ).toBe(200);
    expect((await req('/cpm/assess', KEY_A, 'POST', { assessmentId })).status).toBe(409);
    expect(
      (await req('/cpm/policies/web3-baseline', admin, 'PATCH', { active: true })).status,
    ).toBe(200);
  });
  it('validates monitoring input, enforces roles, and isolates cross-tenant writes', async () => {
    const input = { input: { address: ADDRESS, chainId: 1 }, intervalSeconds: 60 };
    expect((await req('/cpm/monitoring', viewer, 'POST', input)).status).toBe(403);
    expect(
      (await req('/cpm/monitoring', KEY_A, 'POST', { ...input, intervalSeconds: 1 })).status,
    ).toBe(400);
    expect(
      (
        await req('/cpm/monitoring', KEY_A, 'POST', {
          ...input,
          input: { ...input.input, rpcUrl: 'https://evil.example' },
        })
      ).status,
    ).toBe(400);
    const schedule = await (await req('/cpm/monitoring', KEY_A, 'POST', input)).json();
    expect(schedule.id).toBeTruthy();
    expect(
      (await req(`/cpm/monitoring/${schedule.id}`, adminB, 'PATCH', { enabled: false })).status,
    ).toBe(404);
    expect((await req(`/cpm/monitoring/${schedule.id}`, KEY_A, 'DELETE')).status).toBe(403);
    expect((await req(`/cpm/monitoring/${schedule.id}`, admin, 'DELETE')).status).toBe(200);
    expect(await (await req('/cpm/monitoring', KEY_B)).json()).toEqual([]);
    expect((await req('/cpm/monitoring?limit=1000')).status).toBe(400);
  });
  it('does not permit an administrator to label technical resolution', async () => {
    const path = `/cpm/findings/${encodeURIComponent(snapshotId)}/CV-WALLET-001`;
    expect(
      (
        await req(path, admin, 'PATCH', {
          status: 'resolved',
          reason: 'Pretend technical resolution is complete',
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await req(path, admin, 'PATCH', {
          status: 'pending_verification',
          reason: 'Skip all required lifecycle transitions',
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await req(path, admin, 'PATCH', {
          status: 'acknowledged',
          reason: 'Reviewed supported evidence coverage',
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await req(`/assessments/${assessmentId}/findings/CV-WALLET-001`, admin, 'PATCH', {
          status: 'resolved',
          reason: 'Legacy endpoint must not bypass verification',
        })
      ).status,
    ).toBe(409);
  });
  it('exposes typed migration readiness and retains immutable history', async () => {
    const client = new ChainVantaClient(base, KEY_A);
    const result = await client.assessMigration({
      assessmentId,
      goal: 'cryptographic-migration',
      scope: 'Evaluate observed EVM signature migration readiness',
      criteria: [{ kind: 'signature_algorithm', expected: 'ML-DSA' }],
    });
    expect(result.status).toBe('TECHNICALLY_BLOCKED');
    expect(await client.migration(result.id)).toEqual(result);
    expect((await req(`/cpm/migrations/${result.id}`, KEY_B)).status).toBe(404);
    expect(await client.postureHistory(`eip155:1:${ADDRESS}`)).toHaveLength(1);
  });
});
