import { signedTransactionFixture } from '../../packages/test-fixtures/src/transaction.js';
import {
  SENTINEL,
  addr,
  encode,
  fakeChainTransport,
  selector,
} from '../../packages/test-fixtures/src/account-structure.js';
import { encodeFunctionResult, parseAbi, toFunctionSelector } from 'viem';
import { enumerableRoles, erc20 } from '../../packages/test-fixtures/src/token-authority.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { INestApplication } from '@nestjs/common';
import { createApp } from '../../services/api-gateway/src/app.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import {
  ADDRESS,
  BLOCK_HASH,
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
  it('exports a validated CycloneDX CBOM, isolated by tenant', async () => {
    const response = await request(`/v1/assessments/${assessmentId}/cbom`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/vnd.cyclonedx+json');
    expect(await response.json()).toMatchObject({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      serialNumber: `urn:uuid:${assessmentId}`,
      compositions: [{ aggregate: 'incomplete' }],
    });
    expect((await request(`/v1/assessments/${assessmentId}/cbom`, KEY_B)).status).toBe(404);
    expect((await request('/v1/assessments/not-a-uuid/cbom')).status).toBe(400);
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
  it('persists Safe structure evidence and graph edges, isolated by tenant', async () => {
    const owners = [addr('44'), addr('55')];
    const module = addr('77');
    activeTransport = fakeChainTransport({
      code: { [ADDRESS]: '0x6080604052' },
      calls: {
        [ADDRESS]: {
          [selector('getOwners')]: encode('getOwners', owners),
          [selector('getThreshold')]: encode('getThreshold', 2n),
          // Duplicate modules from a hostile contract must not break edge persistence.
          [selector('getModulesPaginated')]: encode('getModulesPaginated', [
            [module, module],
            SENTINEL,
          ]),
        },
      },
    });
    try {
      const response = await request('/v1/assessments', KEY_A, {
        method: 'POST',
        body: JSON.stringify({ address: ADDRESS, chainId: 1 }),
      });
      expect(response.status).toBe(201);
      const record = await response.json();
      expect(record.observation.structure.safe).toMatchObject({ owners, threshold: 2 });
      expect(record.posture.findings.map((f: { ruleId: string }) => f.ruleId)).toContain(
        'CV-SAFE-002',
      );
      const stored = await (await request(`/v1/assessments/${record.id}`)).json();
      expect(stored.observation.structure).toEqual(record.observation.structure);
      const graph = await (await request(`/v1/graph?source=eip155:1:${ADDRESS}`)).json();
      const relations = graph
        .filter((e: { assessment_id: string }) => e.assessment_id === record.id)
        .map((e: { relation: string }) => e.relation);
      expect(relations.filter((r: string) => r === 'safe-owner-accessor-reports')).toHaveLength(2);
      expect(relations.filter((r: string) => r === 'safe-module-accessor-reports')).toHaveLength(1);
      expect(await (await request(`/v1/graph?source=eip155:1:${ADDRESS}`, KEY_B)).json()).toEqual(
        [],
      );
    } finally {
      activeTransport = fixtureTransport;
    }
  });
  it('rejects transaction discovery on chains without archive state', async () => {
    const response = await request('/v1/assessments', KEY_A, {
      method: 'POST',
      body: JSON.stringify({ address: ADDRESS, chainId: 1, discoverTransaction: true }),
    });
    expect(response.status).toBe(400);
    expect((await response.json()).error.message).toContain('archive');
    const both = await request('/v1/assessments', KEY_A, {
      method: 'POST',
      body: JSON.stringify({
        address: ADDRESS,
        chainId: 1,
        discoverTransaction: true,
        transactionHash: `0x${'ab'.repeat(32)}`,
      }),
    });
    expect(both.status).toBe(400);
  });
  it('discovers and verifies the latest sent transaction on an archive chain', async () => {
    const tx = await signedTransactionFixture();
    const txBlock = BigInt(tx.raw.blockNumber);
    const archiveApp = await createApp(
      { ...testConfig, chains: [{ ...testConfig.chains[0]!, archive: true }] },
      repository,
      async (url, init) => {
        const call = JSON.parse(String(init?.body));
        const reply = (result: unknown) => Response.json({ jsonrpc: '2.0', id: 1, result });
        const [first, second] = call.params;
        if (call.method === 'eth_getTransactionCount')
          // Snapshot reads are hash-pinned objects; historical bisection reads use block numbers.
          return reply(
            typeof second === 'string' ? (BigInt(second) >= txBlock ? '0x1' : '0x0') : '0x1',
          );
        if (call.method === 'eth_getBlockByNumber' && second === true)
          return reply({
            number: first,
            hash: BLOCK_HASH,
            timestamp: '0x65000000',
            transactions: BigInt(first) === txBlock ? [tx.raw] : [],
          });
        if (call.method === 'eth_getTransactionByHash') return reply(tx.raw);
        if (call.method === 'eth_getTransactionReceipt') return reply(tx.receipt);
        return fixtureTransport(url, init);
      },
    );
    await archiveApp.listen(0, '127.0.0.1');
    try {
      const response = await fetch(`${await archiveApp.getUrl()}/v1/assessments`, {
        method: 'POST',
        headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
        body: JSON.stringify({ address: tx.address, chainId: 1, discoverTransaction: true }),
      });
      expect(response.status).toBe(201);
      const result = await response.json();
      expect(result.observation.discovery).toMatchObject({
        method: 'nonce-bisection/1.0.0',
        accountNonce: '1',
        outcome: 'found',
        blockNumber: tx.raw.blockNumber,
        transactionHash: tx.hash,
      });
      expect(result.observation.discovery.probes.length).toBeLessThanOrEqual(9);
      expect(result.observation.signature.hash).toBe(tx.hash);
      expect(result.qbom.status).toBe('classical-signature-observed');
    } finally {
      await archiveApp.close();
    }
  });
  it('collects an opt-in token adapter without inventing mint permissions', async () => {
    const abi = parseAbi([
      'function owner() view returns (address)',
      'function totalSupply() view returns (uint256)',
      'function decimals() view returns (uint8)',
    ]);
    // A plain ownable ERC20: answers its own selectors, reverts others, has empty proxy slots.
    const results: Record<string, string> = Object.fromEntries(
      (
        [
          ['owner', ADDRESS],
          ['totalSupply', 123456789n],
          ['decimals', 6],
        ] as const
      ).map(([functionName, result]) => [
        toFunctionSelector(abi.find((f) => f.name === functionName)!),
        encodeFunctionResult({ abi, functionName, result } as never),
      ]),
    );
    activeTransport = async (url, init) => {
      const call = JSON.parse(String(init?.body));
      if (call.method === 'eth_getCode')
        return Response.json({ jsonrpc: '2.0', id: 1, result: '0x6000' });
      if (call.method === 'eth_getStorageAt')
        return Response.json({ jsonrpc: '2.0', id: 1, result: `0x${'0'.repeat(64)}` });
      if (call.method === 'eth_call') {
        const result = results[String(call.params[0].data).slice(0, 10)];
        return Response.json(
          result
            ? { jsonrpc: '2.0', id: 1, result }
            : { jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'execution reverted' } },
        );
      }
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
      // Structure probes ran, found nothing, and did not invent a proxy, Safe or smart account.
      expect(record.observation.structure).toMatchObject({
        delegation: null,
        minimalProxy: null,
        eip1967: null,
        safe: null,
        erc4337: null,
      });
    } finally {
      activeTransport = fixtureTransport;
    }
  });
  it('persists token authority evidence and reports single-key minters', async () => {
    const minter = addr('11');
    activeTransport = fakeChainTransport({
      code: { [ADDRESS]: '0x6000' },
      calls: { [ADDRESS]: { ...erc20(), ...enumerableRoles({ minter: [minter] }) } },
    });
    try {
      const response = await request('/v1/assessments', KEY_A, {
        method: 'POST',
        body: JSON.stringify({ address: ADDRESS, chainId: 1, adapter: 'token-authority' }),
      });
      expect(response.status).toBe(201);
      const created = await response.json();
      const stored = await (await request(`/v1/assessments/${created.id}`, KEY_A)).json();
      expect(stored.evidenceHash).toBe(created.evidenceHash);
      expect(stored.observation.tokenAuthority.authorities).toEqual([
        { address: minter, kind: 'no-code' },
      ]);
      expect(stored.posture.findings.map((f: { ruleId: string }) => f.ruleId)).toContain(
        'CV-TOKEN-003',
      );
    } finally {
      activeTransport = fixtureTransport;
    }
  });
});
