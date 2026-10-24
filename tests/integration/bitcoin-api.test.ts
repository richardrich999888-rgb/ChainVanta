import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { INestApplication } from '@nestjs/common';
import { createApp } from '../../services/api-gateway/src/app.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import { validateCycloneDxCbom } from '../../core/cbom-engine/schema-validation/cyclonedx.js';
import { bitcoinAssetId } from '../../packages/domain-models/src/bitcoin.js';
import {
  KEY_A,
  KEY_B,
  TENANT_A,
  TENANT_B,
  fixtureTransport,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';
import {
  DUMMY_SIGNATURE,
  TX_BLOCK,
  fakeBitcoinNode,
  p2pkScript,
  p2wpkhAddress,
  p2wpkhScript,
  spendingTransaction,
  testKey,
} from '../../packages/test-fixtures/src/bitcoin.js';

const KEY = testKey(1);
const ADDRESS = p2wpkhAddress('regtest', KEY);
const SPEND = '0a'.repeat(32);
const VIEWER = 'viewer-bitcoin-fixture-key-at-least-32-chars';
const node = {
  network: 'regtest' as const,
  name: 'Regtest (fixture)',
  rpcUrl: 'http://127.0.0.1:18443',
  demonstration: true,
};

describe('Bitcoin assessment API', () => {
  let db: Awaited<ReturnType<typeof testDatabase>>;
  let app: INestApplication;
  let base: string;
  let id: string;
  let transport: typeof fetch = fakeBitcoinNode({
    unspents: [
      { txid: '0b'.repeat(32), vout: 0, scriptPubKey: p2wpkhScript(KEY), amount: 0.5, height: 150 },
    ],
    transactions: { [SPEND]: spendingTransaction(SPEND, { witness: [DUMMY_SIGNATURE, KEY] }) },
  });
  const request = (path: string, key = KEY_A, init: RequestInit = {}) =>
    fetch(`${base}/v1${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${key}`,
        'content-type': 'application/json',
        ...init.headers,
      },
    });
  const post = (body: unknown, key = KEY_A, headers: Record<string, string> = {}) =>
    request('/bitcoin/assessments', key, { method: 'POST', body: JSON.stringify(body), headers });

  beforeAll(async () => {
    db = await testDatabase();
    app = await createApp(
      {
        ...testConfig,
        tenantKeys: [...testConfig.tenantKeys, { tenantId: TENANT_A, key: VIEWER, role: 'viewer' }],
        bitcoinNodes: [node],
      },
      new PostgresRepository(db.pool),
      fixtureTransport,
      undefined,
      (url, init) => transport(url, init),
    );
    await app.listen(0, '127.0.0.1');
    base = await app.getUrl();
  });
  afterAll(async () => {
    await app?.close();
    await db?.close();
  });

  it('assesses an address, persists it, and proves key reuse from a supplied spend', async () => {
    const response = await post({
      network: 'regtest',
      address: ADDRESS,
      spendTransaction: { txid: SPEND, blockHash: TX_BLOCK },
    });
    expect(response.status).toBe(201);
    const a = await response.json();
    id = a.id;
    expect(a).toMatchObject({
      kind: 'bitcoin',
      assetKind: 'bitcoin-address',
      qbom: { status: 'public-key-exposed', exposedSats: '50000000' },
      observation: { utxoCount: 1, revealedSpend: { txid: SPEND, publicKeys: [KEY] } },
    });
    expect(a.posture.findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(['CV-BTC-002']);
    expect(await (await request(`/bitcoin/assessments/${id}`)).json()).toEqual(a);
    expect(
      (await (await request('/bitcoin/assessments')).json()).map((x: { id: string }) => x.id),
    ).toContain(id);
  });

  it('keeps Bitcoin documents out of EVM endpoints', async () => {
    const evm = await request('/assessments');
    expect(evm.status).toBe(200);
    expect((await evm.json()).some((x: { id: string }) => x.id === id)).toBe(false);
    expect((await request(`/assessments/${id}`)).status).toBe(404);
    expect((await request('/reports')).status).toBe(200);
  });

  it('records a CAIP-10 bip122 asset and graph edges under tenant scope', async () => {
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [TENANT_A]);
      const asset = (
        await client.query('SELECT namespace, chain_id FROM assets WHERE asset_id=$1', [
          bitcoinAssetId('regtest', ADDRESS),
        ])
      ).rows[0];
      expect(asset).toEqual({ namespace: 'bip122', chain_id: null });
      const edges = (
        await client.query('SELECT relation FROM graph_edges WHERE assessment_id=$1', [id])
      ).rows;
      expect(edges.map((e) => e.relation)).toContain('revealed-key');
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [TENANT_B]);
      expect(
        (
          await client.query('SELECT 1 FROM assets WHERE asset_id=$1', [
            bitcoinAssetId('regtest', ADDRESS),
          ])
        ).rowCount,
      ).toBe(0);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });

  it('exports a validated CycloneDX CBOM and isolates tenants', async () => {
    const response = await request(`/bitcoin/assessments/${id}/cbom`);
    expect(response.headers.get('content-type')).toContain('application/vnd.cyclonedx+json');
    expect(validateCycloneDxCbom(await response.json()).serialNumber).toBe(`urn:uuid:${id}`);
    expect((await request(`/bitcoin/assessments/${id}`, KEY_B)).status).toBe(404);
    expect((await request(`/bitcoin/assessments/${id}/cbom`, KEY_B)).status).toBe(404);
    expect(await (await request('/bitcoin/assessments', KEY_B)).json()).toEqual([]);
  });

  it('replays idempotent requests and rejects a reused key with different input', async () => {
    const headers = { 'idempotency-key': 'bitcoin-replay-key-1' };
    const first = await (await post({ network: 'regtest', publicKey: KEY }, KEY_A, headers)).json();
    const again = await (await post({ network: 'regtest', publicKey: KEY }, KEY_A, headers)).json();
    expect(again.id).toBe(first.id);
    expect((await post({ network: 'regtest', address: ADDRESS }, KEY_A, headers)).status).toBe(409);
  });

  it.each([
    [
      'an address for another network',
      { network: 'regtest', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4' },
    ],
    [
      'an unconfigured network',
      { network: 'mainnet', address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' },
    ],
    ['both address and public key', { network: 'regtest', address: ADDRESS, publicKey: KEY }],
    ['an unknown field', { network: 'regtest', address: ADDRESS, rpcUrl: 'http://127.0.0.1' }],
  ])('rejects %s with 400', async (_, body) => {
    expect((await post(body)).status).toBe(400);
  });

  it('requires the analyst role to scan', async () => {
    expect((await post({ network: 'regtest', address: ADDRESS }, VIEWER)).status).toBe(403);
    expect((await request('/bitcoin/assessments', VIEWER)).status).toBe(200);
  });

  it('returns 429 while a scan is running on the node, then accepts the next scan', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const inner = fakeBitcoinNode({ unspents: [] });
    transport = async (url, init) => {
      if (JSON.parse(String(init?.body)).method === 'scantxoutset') await gate;
      return inner(url, init);
    };
    const slow = post({ network: 'regtest', publicKey: testKey(5) });
    await new Promise((r) => setTimeout(r, 50));
    expect((await post({ network: 'regtest', publicKey: testKey(6) })).status).toBe(429);
    release();
    expect((await slow).status).toBe(201);
    expect((await post({ network: 'regtest', publicKey: testKey(6) })).status).toBe(201);
  });

  it('returns 502 and persists nothing when the node returns inconsistent data', async () => {
    transport = fakeBitcoinNode({
      unspents: [
        {
          txid: '0c'.repeat(32),
          vout: 0,
          scriptPubKey: p2pkScript(testKey(9)),
          amount: 1,
          height: 10,
        },
      ],
    });
    const before = (await (await request('/bitcoin/assessments')).json()).length;
    const response = await post({ network: 'regtest', address: ADDRESS });
    expect(response.status).toBe(502);
    expect(JSON.stringify(await response.json())).not.toContain('127.0.0.1');
    expect((await (await request('/bitcoin/assessments')).json()).length).toBe(before);
  });
});

describe('Bitcoin endpoints without configured nodes', () => {
  it('reports no networks and refuses scans', async () => {
    const db = await testDatabase();
    const app = await createApp(testConfig, new PostgresRepository(db.pool), fixtureTransport);
    await app.listen(0, '127.0.0.1');
    try {
      const base = await app.getUrl();
      const headers = { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' };
      expect(await (await fetch(`${base}/v1/bitcoin/networks`, { headers })).json()).toEqual([]);
      const scan = await fetch(`${base}/v1/bitcoin/assessments`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ network: 'regtest', address: ADDRESS }),
      });
      expect(scan.status).toBe(404);
    } finally {
      await app.close();
      await db.close();
    }
  });
});
