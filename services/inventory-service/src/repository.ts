import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import type { Pool, PoolClient } from 'pg';
import { Assessment, canonicalAssetId } from '../../../packages/domain-models/src/index.js';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';
import { BitcoinAssessment, bitcoinAssetId } from '../../../packages/domain-models/src/bitcoin.js';

type StoredRow = {
  document: { evidenceHash: string; observation: unknown };
  record_hash: string;
  observation: unknown;
};
/** Any assessment document plus the asset it describes, ready for persistence. */
type StoredRecord = {
  tenantId: string;
  id: string;
  evidenceHash: string;
  observation: unknown;
  document: unknown;
  trustGraph: { edges: { from: string; to: string; relation: string }[] };
  asset: {
    id: string;
    namespace: 'eip155' | 'bip122';
    chainId: number | null;
    address: string;
    firstSeen: string;
  };
};

export interface Repository {
  save(assessment: Assessment): Promise<void>;
  list(tenantId: string): Promise<Assessment[]>;
  get(tenantId: string, id: string): Promise<Assessment | null>;
  ping(): Promise<void>;
  replay?(tenantId: string, key: string, requestHash: string): Promise<Assessment | null>;
  saveOnce?(
    assessment: Assessment,
    key: string,
    requestHash: string,
    actor: string,
  ): Promise<Assessment>;
  history?(tenantId: string, assetId: string): Promise<Assessment[]>;
  graph?(tenantId: string, source: string): Promise<unknown[]>;
  audit?(tenantId: string): Promise<unknown[]>;
  findingEvent?(
    tenantId: string,
    id: string,
    ruleId: string,
    input: { status: string; reason: string; expiresAt?: string },
    actor: string,
  ): Promise<void>;
  findingEvents?(tenantId: string): Promise<unknown[]>;
}

export class PostgresRepository implements Repository {
  constructor(private readonly pool: Pool) {}

  async scoped<T>(tenantId: string, action: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await action(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Shared persistence for any assessment document: evidence, document, asset, graph and audit,
   * in the caller's tenant-scoped transaction. Integrity is checked before anything is written.
   */
  private async insertRecord(client: PoolClient, record: StoredRecord, actor: string) {
    if (evidenceHash(record.observation) !== record.evidenceHash)
      throw new Error('Evidence integrity failure');
    await client.query(
      'INSERT INTO evidence (tenant_id, hash, observation) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
      [record.tenantId, record.evidenceHash, JSON.stringify(record.observation)],
    );
    await client.query(
      'INSERT INTO assessments (tenant_id,id,evidence_hash,record_hash,document) VALUES ($1,$2,$3,$4,$5)',
      [
        record.tenantId,
        record.id,
        record.evidenceHash,
        evidenceHash(record.document),
        JSON.stringify(record.document),
      ],
    );
    await client.query(
      'INSERT INTO assets (tenant_id,asset_id,namespace,chain_id,address,first_seen) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
      [
        record.tenantId,
        record.asset.id,
        record.asset.namespace,
        record.asset.chainId,
        record.asset.address,
        record.asset.firstSeen,
      ],
    );
    for (const edge of record.trustGraph.edges)
      await client.query(
        'INSERT INTO graph_edges (tenant_id,assessment_id,source,target,relation,evidence_hash) VALUES ($1,$2,$3,$4,$5,$6)',
        [record.tenantId, record.id, edge.from, edge.to, edge.relation, record.evidenceHash],
      );
    await client.query(
      'INSERT INTO audit_events (tenant_id,id,actor,action,resource,details) VALUES ($1,$2,$3,$4,$5,$6)',
      [
        record.tenantId,
        randomUUID(),
        actor,
        'assessment.created',
        record.id,
        JSON.stringify({ evidenceHash: record.evidenceHash }),
      ],
    );
  }
  async insert(client: PoolClient, assessment: Assessment, actor: string) {
    Assessment.parse(assessment);
    const o = assessment.observation;
    await this.insertRecord(
      client,
      {
        ...assessment,
        document: assessment,
        asset: {
          id: canonicalAssetId(o.chainId, o.address),
          namespace: 'eip155',
          chainId: o.chainId,
          address: o.address,
          firstSeen: o.observedAt,
        },
      },
      actor,
    );
  }
  private async insertBitcoin(client: PoolClient, assessment: BitcoinAssessment, actor: string) {
    BitcoinAssessment.parse(assessment);
    const o = assessment.observation;
    await this.insertRecord(
      client,
      {
        ...assessment,
        document: assessment,
        asset: {
          id: bitcoinAssetId(o.network, o.target.value),
          namespace: 'bip122',
          chainId: null,
          address: o.target.value,
          firstSeen: o.observedAt,
        },
      },
      actor,
    );
  }
  async save(assessment: Assessment): Promise<void> {
    await this.scoped(assessment.tenantId, (client) => this.insert(client, assessment, 'internal'));
  }
  private async lookup<T>(
    client: PoolClient,
    tenantId: string,
    key: string,
    requestHash: string,
    parse: (value: unknown) => T,
  ): Promise<T | null> {
    const result = await client.query(
      'SELECT r.request_hash,a.document,a.record_hash,e.observation FROM scan_requests r JOIN assessments a ON a.tenant_id=r.tenant_id AND a.id=r.assessment_id JOIN evidence e ON e.tenant_id=a.tenant_id AND e.hash=a.evidence_hash WHERE r.tenant_id=$1 AND r.key=$2',
      [tenantId, key],
    );
    const row = result.rows[0];
    if (!row) return null;
    if (row.request_hash !== requestHash)
      throw new HttpException('Idempotency key already used with different input', 409);
    return this.verifiedAs(row, parse);
  }
  replay(tenantId: string, key: string, requestHash: string) {
    return this.scoped(tenantId, (client) =>
      this.lookup(client, tenantId, key, requestHash, (v) => Assessment.parse(v)),
    );
  }
  saveOnce(assessment: Assessment, key: string, requestHash: string, actor: string) {
    return this.scoped(assessment.tenantId, async (client) => {
      // Cross-process serialization; transaction lock disappears on rollback/crash.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
        `${assessment.tenantId}:${key}`,
      ]);
      const prior = await this.lookup(client, assessment.tenantId, key, requestHash, (v) =>
        Assessment.parse(v),
      );
      if (prior) return prior;
      await this.insert(client, assessment, actor);
      await client.query(
        'INSERT INTO scan_requests (tenant_id,key,request_hash,assessment_id) VALUES ($1,$2,$3,$4)',
        [assessment.tenantId, key, requestHash, assessment.id],
      );
      return assessment;
    });
  }
  history(tenantId: string, assetId: string) {
    return this.scoped(tenantId, async (client) => {
      const result = await client.query(
        "SELECT a.document,a.record_hash,e.observation FROM assessments a JOIN evidence e ON e.tenant_id=a.tenant_id AND e.hash=a.evidence_hash WHERE a.tenant_id=$1 AND a.document->>'kind' IS NULL AND 'eip155:' || (a.document->'observation'->>'chainId') || ':' || (a.document->'observation'->>'address')=$2 ORDER BY a.created_at DESC,a.id LIMIT 100",
        [tenantId, assetId],
      );
      return result.rows.map((row) => this.verified(row));
    });
  }
  graph(tenantId: string, source: string) {
    return this.scoped(
      tenantId,
      async (client) =>
        (
          await client.query(
            `WITH RECURSIVE walk AS (
      SELECT source,target,relation,evidence_hash,assessment_id,1 AS depth,ARRAY[source,target] AS path FROM graph_edges WHERE tenant_id=$1 AND source=$2
      UNION ALL SELECT e.source,e.target,e.relation,e.evidence_hash,e.assessment_id,w.depth+1,w.path || e.target FROM graph_edges e JOIN walk w ON e.source=w.target AND e.assessment_id=w.assessment_id WHERE e.tenant_id=$1 AND w.depth<3 AND NOT e.target=ANY(w.path)
    ) SELECT DISTINCT source,target,relation,evidence_hash,assessment_id,depth FROM walk LIMIT 200`,
            [tenantId, source],
          )
        ).rows,
    );
  }
  audit(tenantId: string) {
    return this.scoped(
      tenantId,
      async (client) =>
        (
          await client.query(
            'SELECT id,actor,action,resource,details,created_at FROM audit_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100',
            [tenantId],
          )
        ).rows,
    );
  }
  findingEvents(tenantId: string) {
    return this.scoped(
      tenantId,
      async (client) =>
        (
          await client.query(
            'SELECT * FROM finding_events WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT 500',
            [tenantId],
          )
        ).rows,
    );
  }
  async findingEvent(
    tenantId: string,
    id: string,
    ruleId: string,
    input: { status: string; reason: string; expiresAt?: string },
    actor: string,
  ) {
    if (input.status === 'resolved')
      throw new HttpException(
        'Technical resolution requires a subsequent CPM verification; use administrative closure for administrative decisions',
        409,
      );
    const snapshot = await this.scoped(
      tenantId,
      async (client) =>
        (
          await client.query(
            "SELECT id FROM posture_snapshots WHERE tenant_id=$1 AND assessment_id=$2 AND document->'evaluations' @> $3::jsonb ORDER BY created_at DESC LIMIT 1",
            [tenantId, id, JSON.stringify([{ ruleId }])],
          )
        ).rows[0],
    );
    if (snapshot) {
      const { CpmRepository } = await import('./cpm-repository.js');
      const { FindingTransition } = await import('../../../packages/domain-models/src/cpm.js');
      await new CpmRepository(this).transition(
        tenantId,
        snapshot.id,
        ruleId,
        FindingTransition.parse(input),
        actor,
        'finding.status',
      );
      return;
    }
    await this.scoped(tenantId, async (client) => {
      const result = await client.query(
        'SELECT document FROM assessments WHERE tenant_id=$1 AND id=$2',
        [tenantId, id],
      );
      if (
        !result.rows[0]?.document.posture.findings.some(
          (f: { ruleId: string }) => f.ruleId === ruleId,
        )
      )
        throw new HttpException('Finding not found', 404);
      if (
        input.status === 'excepted' &&
        (!input.expiresAt || Date.parse(input.expiresAt) <= Date.now())
      )
        throw new HttpException('Exception expiry must be in the future', 400);
      await client.query(
        'INSERT INTO finding_events (tenant_id,id,assessment_id,rule_id,status,reason,expires_at,actor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [
          tenantId,
          randomUUID(),
          id,
          ruleId,
          input.status,
          input.reason,
          input.expiresAt ?? null,
          actor,
        ],
      );
      await client.query(
        'INSERT INTO audit_events (tenant_id,id,actor,action,resource,details) VALUES ($1,$2,$3,$4,$5,$6)',
        [tenantId, randomUUID(), actor, 'finding.status', `${id}:${ruleId}`, JSON.stringify(input)],
      );
    });
  }

  private verified(row: StoredRow): Assessment {
    return this.verifiedAs(row, (v) => Assessment.parse(v));
  }
  /** Recomputes every stored hash before parsing; any mismatch is an integrity failure. */
  private verifiedAs<T>(row: StoredRow, parse: (value: unknown) => T): T {
    const value = row.document;
    if (
      evidenceHash(value) !== row.record_hash ||
      evidenceHash(row.observation) !== value.evidenceHash ||
      evidenceHash(value.observation) !== value.evidenceHash
    )
      throw new Error('Stored evidence integrity failure');
    return parse(value);
  }

  async list(tenantId: string): Promise<Assessment[]> {
    return this.scoped(tenantId, async (client) => {
      const result = await client.query(
        "SELECT a.document, a.record_hash, e.observation FROM assessments a JOIN evidence e ON e.tenant_id = a.tenant_id AND e.hash = a.evidence_hash WHERE a.tenant_id = $1 AND a.document->>'kind' IS NULL ORDER BY a.created_at DESC, a.id LIMIT 50",
        [tenantId],
      );
      return result.rows.map((row) => this.verified(row));
    });
  }

  async get(tenantId: string, id: string): Promise<Assessment | null> {
    return this.scoped(tenantId, async (client) => {
      const result = await client.query(
        "SELECT a.document, a.record_hash, e.observation FROM assessments a JOIN evidence e ON e.tenant_id = a.tenant_id AND e.hash = a.evidence_hash WHERE a.tenant_id = $1 AND a.id = $2 AND a.document->>'kind' IS NULL",
        [tenantId, id],
      );
      return result.rows[0] ? this.verified(result.rows[0]) : null;
    });
  }

  replayBitcoin(tenantId: string, key: string, requestHash: string) {
    return this.scoped(tenantId, (client) =>
      this.lookup(client, tenantId, key, requestHash, (v) => BitcoinAssessment.parse(v)),
    );
  }
  saveBitcoinOnce(assessment: BitcoinAssessment, key: string, requestHash: string, actor: string) {
    return this.scoped(assessment.tenantId, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
        `${assessment.tenantId}:${key}`,
      ]);
      const prior = await this.lookup(client, assessment.tenantId, key, requestHash, (v) =>
        BitcoinAssessment.parse(v),
      );
      if (prior) return prior;
      await this.insertBitcoin(client, assessment, actor);
      await client.query(
        'INSERT INTO scan_requests (tenant_id,key,request_hash,assessment_id) VALUES ($1,$2,$3,$4)',
        [assessment.tenantId, key, requestHash, assessment.id],
      );
      return assessment;
    });
  }
  listBitcoin(tenantId: string): Promise<BitcoinAssessment[]> {
    return this.scoped(tenantId, async (client) =>
      (
        await client.query(
          "SELECT a.document, a.record_hash, e.observation FROM assessments a JOIN evidence e ON e.tenant_id = a.tenant_id AND e.hash = a.evidence_hash WHERE a.tenant_id = $1 AND a.document->>'kind' = 'bitcoin' ORDER BY a.created_at DESC, a.id LIMIT 50",
          [tenantId],
        )
      ).rows.map((row) => this.verifiedAs(row, (v) => BitcoinAssessment.parse(v))),
    );
  }
  getBitcoin(tenantId: string, id: string): Promise<BitcoinAssessment | null> {
    return this.scoped(tenantId, async (client) => {
      const row = (
        await client.query(
          "SELECT a.document, a.record_hash, e.observation FROM assessments a JOIN evidence e ON e.tenant_id = a.tenant_id AND e.hash = a.evidence_hash WHERE a.tenant_id = $1 AND a.id = $2 AND a.document->>'kind' = 'bitcoin'",
          [tenantId, id],
        )
      ).rows[0];
      return row ? this.verifiedAs(row, (v) => BitcoinAssessment.parse(v)) : null;
    });
  }

  async ping(): Promise<void> {
    const role = (
      await this.pool.query('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user')
    ).rows[0];
    if (!role || role.rolsuper || role.rolbypassrls)
      throw new Error('Runtime database role must enforce tenant RLS');
    await this.pool
      .query("SELECT version FROM schema_migrations WHERE version = '011_bitcoin'")
      .then((result) => {
        if (!result.rowCount) throw new Error('Migration required');
      });
  }
}
