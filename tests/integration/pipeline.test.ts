import { signedTransactionFixture } from '../../packages/test-fixtures/src/transaction.js';
import { encodeFunctionResult, parseAbi } from 'viem';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { INestApplication } from '@nestjs/common';
import { createApp } from '../../services/api-gateway/src/app.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import {
  ADDRESS,
  KEY_A,
  KEY_B,
  TENANT_A,
  TENANT_B,
  fixtureTransport,
  observation,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';

describe('Authenticated RPC → PostgreSQL → inventory pipeline', () => {
  let database: Awaited<ReturnType<typeof testDatabase>>;
  let repository: PostgresRepository;
  let app: INestApplication;
  let base: string;
  let assessmentId: string;
  let activeTransport: typeof fetch = fixtureTransport;
  const request = (path: string, key = KEY_A, init: RequestInit = {}) =>
    fetch(`${base}${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${key}`,
        'content-type': 'application/json',
        ...init.headers,
      },
    });
  beforeAll(async () => {
    database = await testDatabase();
    repository = new PostgresRepository(database.pool);
    app = await createApp(
      {
        ...testConfig,
        tenantKeys: [
          ...testConfig.tenantKeys,
          { tenantId: TENANT_A, key: 'viewer-only-test-key-with-32-characters', role: 'viewer' },
          { tenantId: TENANT_A, key: 'admin-only-test-key-with-32-characters', role: 'admin' },
        ],
      },
      repository,
      (...args) => activeTransport(...args),
    );
    await app.listen(0, '127.0.0.1');
    base = await app.getUrl();
  });
  afterAll(async () => {
    await app?.close();
    await database?.close();
  });

  it('rejects unauthenticated requests', async () => {
    expect((await fetch(`${base}/v1/assessments`)).status).toBe(401);
  });
  it('stores a full assessment and retrieves verified evidence', async () => {
    const response = await request('/v1/assessments', KEY_A, {
      method: 'POST',
      body: JSON.stringify({ address: ADDRESS, chainId: 1 }),
    });
    expect(response.status).toBe(201);
    const value = await response.json();
    assessmentId = value.id;
    expect(value.tenantId).toBe(TENANT_A);
    expect(value.evidenceHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    const retrieved = await (await request(`/v1/assessments/${assessmentId}`)).json();
    expect(retrieved).toEqual(value);
    expect(
      (await new PostgresRepository(database.pool).list(TENANT_A)).map((item) => item.id),
    ).toContain(assessmentId);
  });
  it('prevents cross-tenant reads even with a forged tenant header', async () => {
    const response = await request(`/v1/assessments/${assessmentId}`, KEY_B, {
      headers: { 'x-tenant-id': TENANT_A },
    });
    expect(response.status).toBe(404);
    expect(await (await request('/v1/assessments', KEY_B)).json()).toEqual([]);
  });
  it('rejects tenant injection, invalid bodies, unknown chains and malformed IDs', async () => {
    for (const body of [
      { address: ADDRESS, chainId: 1, tenantId: TENANT_B },
      { address: ADDRESS, chainId: 999 },
      { address: '0x', chainId: 1 },
    ])
      expect(
        (await request('/v1/assessments', KEY_A, { method: 'POST', body: JSON.stringify(body) }))
          .status,
      ).toBe(400);
    expect((await request('/v1/assessments/not-an-id')).status).toBe(400);
  });
  it('enforces database row isolation without a tenant WHERE clause', async () => {
    const client = await database.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [TENANT_B]);
      expect((await client.query('SELECT * FROM assessments')).rows).toHaveLength(0);
      expect((await client.query('SELECT * FROM evidence')).rows).toHaveLength(0);
      for (const table of [
        'assets',
        'scan_requests',
        'graph_edges',
        'finding_events',
        'audit_events',
      ])
        expect((await client.query(`SELECT * FROM ${table}`)).rows).toHaveLength(0);
      await expect(
        client.query('INSERT INTO evidence (tenant_id, hash, observation) VALUES ($1, $2, $3)', [
          TENANT_A,
          `sha256:${'a'.repeat(64)}`,
          '{}',
        ]),
      ).rejects.toThrow();
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
  });
  it('rolls back evidence if assessment insertion fails', async () => {
    const value = assessWallet(TENANT_A, {
      ...observation,
      observedAt: '2026-10-17T01:00:00.000Z',
    });
    value.id = assessmentId;
    await expect(repository.save(value)).rejects.toThrow();
    const client = await database.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [TENANT_A]);
      expect(
        (await client.query('SELECT * FROM evidence WHERE hash = $1', [value.evidenceHash])).rows,
      ).toHaveLength(0);
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
  });
  it('prevents mutation and reports database readiness', async () => {
    await expect(
      database.admin("RESET ROLE; UPDATE evidence SET observation = '{}'::jsonb"),
    ).rejects.toThrow();
    expect((await fetch(`${base}/health/ready`)).status).toBe(200);
  });
  it('replays idempotent requests and rejects reused keys with different input', async () => {
    const init = {
      method: 'POST',
      headers: { 'idempotency-key': 'deterministic-request-001' },
      body: JSON.stringify({ address: ADDRESS, chainId: 1 }),
    };
    const first = await (await request('/v1/assessments', KEY_A, init)).json();
    const second = await (await request('/v1/assessments', KEY_A, init)).json();
    expect(second).toEqual(first);
    expect(
      (
        await request('/v1/assessments', KEY_A, {
          ...init,
          body: JSON.stringify({ address: '0x' + '02'.repeat(20), chainId: 1 }),
        })
      ).status,
    ).toBe(409);
    expect(
      (await repository.history(TENANT_A, `eip155:1:${ADDRESS}`)).filter((v) => v.id === first.id),
    ).toHaveLength(1);
  });
  it('enforces viewer/analyst/admin roles and records finding lifecycle with actor identity', async () => {
    const viewer = 'viewer-only-test-key-with-32-characters',
      admin = 'admin-only-test-key-with-32-characters';
    expect((await request('/v1/assessments', viewer)).status).toBe(200);
    expect(
      (
        await request('/v1/assessments', viewer, {
          method: 'POST',
          body: JSON.stringify({ address: ADDRESS, chainId: 1 }),
        })
      ).status,
    ).toBe(403);
    const path = `/v1/assessments/${assessmentId}/findings/CV-WALLET-001`;
    const init = {
      method: 'PATCH',
      body: JSON.stringify({ status: 'acknowledged', reason: 'Reviewed by test administrator' }),
    };
    expect((await request(path, KEY_A, init)).status).toBe(403);
    expect((await request(path, admin, init)).status).toBe(200);
    const events = await (await request('/v1/findings/events')).json();
    expect(events[0].status).toBe('acknowledged');
    expect(events[0].actor).toMatch(/^api-key:/);
    expect(await (await request('/v1/findings/events', KEY_B)).json()).toEqual([]);
    expect((await request('/v1/audit', KEY_A)).status).toBe(403);
    expect(
      (await (await request('/v1/audit', admin)).json()).some(
        (e: { action: string }) => e.action === 'finding.status',
      ),
    ).toBe(true);
    expect(
      (
        await request(path, admin, {
          method: 'PATCH',
          body: JSON.stringify({ status: 'excepted', reason: 'No expiry is unsafe' }),
        })
      ).status,
    ).toBe(400);
  });
  it('returns evidence-backed graph and reports, isolated by tenant', async () => {
    const graph = await (await request(`/v1/graph?source=eip155:1:${ADDRESS}`)).json();
    expect(graph.length).toBeGreaterThan(0);
    expect(graph[0].evidence_hash).toMatch(/^sha256:/);
    expect(await (await request(`/v1/graph?source=eip155:1:${ADDRESS}`, KEY_B)).json()).toEqual([]);
    const report = await (await request('/v1/reports')).json();
    expect(report.assetCount).toBe(1);
    expect(report.unknownQuantumAssessments).toBe(report.assessmentCount);
    expect(report.demonstration).toBe(true);
  });
  it('persists verified signature CBOM/QBOM findings through the API and rejects tampered transactions', async () => {
    const tx = await signedTransactionFixture();
    let tamper = false;
    activeTransport = async (url, init) => {
      const call = JSON.parse(String(init?.body));
      if (call.method === 'eth_getTransactionByHash')
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: tamper ? { ...tx.raw, value: '0x1' } : tx.raw,
        });
      if (call.method === 'eth_getTransactionReceipt')
        return Response.json({ jsonrpc: '2.0', id: 1, result: tx.receipt });
      return fixtureTransport(url, init);
    };
    try {
      const input = { address: tx.address, chainId: 1, transactionHash: tx.hash };
      const response = await request('/v1/assessments', KEY_A, {
        method: 'POST',
        body: JSON.stringify(input),
      });
      expect(response.status).toBe(201);
      const result = await response.json();
      expect(result.cbom.components[0].algorithm).toBe('ECDSA-secp256k1');
      expect(result.qbom.status).toBe('classical-signature-observed');
      const stored = await (await request(`/v1/assessments/${result.id}`)).json();
      expect(stored).toEqual(result);
      const before = (await repository.list(TENANT_A)).length;
      tamper = true;
      expect(
        (await request('/v1/assessments', KEY_A, { method: 'POST', body: JSON.stringify(input) }))
          .status,
      ).toBe(502);
      expect((await repository.list(TENANT_A)).length).toBe(before);
    } finally {
      activeTransport = fixtureTransport;
    }
  });
  it('collects an opt-in token adapter without inventing mint permissions', async () => {
    const abi = parseAbi([
      'function owner() view returns (address)',
      'function totalSupply() view returns (uint256)',
      'function decimals() view returns (uint8)',
    ]);
    const results = [
      encodeFunctionResult({ abi, functionName: 'owner', result: ADDRESS }),
      encodeFunctionResult({ abi, functionName: 'totalSupply', result: 123456789n }),
      encodeFunctionResult({ abi, functionName: 'decimals', result: 6 }),
    ];
    let index = 0;
    activeTransport = async (url, init) => {
      const call = JSON.parse(String(init?.body));
      if (call.method === 'eth_getCode')
        return Response.json({ jsonrpc: '2.0', id: 1, result: '0x6000' });
      if (call.method === 'eth_call')
        return Response.json({ jsonrpc: '2.0', id: 1, result: results[index++] });
      return fixtureTransport(url, init);
    };
    try {
      const response = await request('/v1/assessments', KEY_A, {
        method: 'POST',
        body: JSON.stringify({ address: ADDRESS, chainId: 1, adapter: 'ownable-erc20' }),
      });
      expect(response.status).toBe(201);
      const record = await response.json();
      expect(record.observation.token.totalSupply).toBe('123456789');
      expect(record.observation.token.limitation).toContain('mint/burn');
      expect(record.qbom.status).toBe('unknown');
    } finally {
      activeTransport = fixtureTransport;
    }
  });
});
