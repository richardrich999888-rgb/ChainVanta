import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import type { Pool, PoolClient } from 'pg';
import { Assessment, canonicalAssetId } from '../../../packages/domain-models/src/index.js';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';

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

  private async scoped<T>(
    tenantId: string,
    action: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
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

  private async insert(client: PoolClient, assessment: Assessment, actor: string) {
    Assessment.parse(assessment);
    if (evidenceHash(assessment.observation) !== assessment.evidenceHash)
      throw new Error('Evidence integrity failure');
    await client.query(
      'INSERT INTO evidence (tenant_id, hash, observation) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
      [assessment.tenantId, assessment.evidenceHash, JSON.stringify(assessment.observation)],
    );
    await client.query(
      'INSERT INTO assessments (tenant_id,id,evidence_hash,record_hash,document) VALUES ($1,$2,$3,$4,$5)',
      [
        assessment.tenantId,
        assessment.id,
        assessment.evidenceHash,
        evidenceHash(assessment),
        JSON.stringify(assessment),
      ],
    );
    const o = assessment.observation;
    await client.query(
      'INSERT INTO assets (tenant_id,asset_id,chain_id,address,first_seen) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
      [
        assessment.tenantId,
        canonicalAssetId(o.chainId, o.address),
        o.chainId,
        o.address,
        o.observedAt,
      ],
    );
    for (const edge of assessment.trustGraph.edges)
      await client.query(
        'INSERT INTO graph_edges (tenant_id,assessment_id,source,target,relation,evidence_hash) VALUES ($1,$2,$3,$4,$5,$6)',
        [
          assessment.tenantId,
          assessment.id,
          edge.from,
          edge.to,
          edge.relation,
          assessment.evidenceHash,
        ],
      );
    await client.query(
      'INSERT INTO audit_events (tenant_id,id,actor,action,resource,details) VALUES ($1,$2,$3,$4,$5,$6)',
      [
        assessment.tenantId,
        randomUUID(),
        actor,
        'assessment.created',
        assessment.id,
        JSON.stringify({ evidenceHash: assessment.evidenceHash }),
      ],
    );
  }
  async save(assessment: Assessment): Promise<void> {
    await this.scoped(assessment.tenantId, (client) => this.insert(client, assessment, 'internal'));
  }
  private async lookup(client: PoolClient, tenantId: string, key: string, requestHash: string) {
    const result = await client.query(
      'SELECT r.request_hash,a.document,a.record_hash,e.observation FROM scan_requests r JOIN assessments a ON a.tenant_id=r.tenant_id AND a.id=r.assessment_id JOIN evidence e ON e.tenant_id=a.tenant_id AND e.hash=a.evidence_hash WHERE r.tenant_id=$1 AND r.key=$2',
      [tenantId, key],
    );
    const row = result.rows[0];
    if (!row) return null;
    if (row.request_hash !== requestHash)
      throw new HttpException('Idempotency key already used with different input', 409);
    return this.verified(row);
  }
  replay(tenantId: string, key: string, requestHash: string) {
    return this.scoped(tenantId, (client) => this.lookup(client, tenantId, key, requestHash));
  }
  saveOnce(assessment: Assessment, key: string, requestHash: string, actor: string) {
    return this.scoped(assessment.tenantId, async (client) => {
      // Cross-process serialization; transaction lock disappears on rollback/crash.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
        `${assessment.tenantId}:${key}`,
      ]);
      const prior = await this.lookup(client, assessment.tenantId, key, requestHash);
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
        "SELECT a.document,a.record_hash,e.observation FROM assessments a JOIN evidence e ON e.tenant_id=a.tenant_id AND e.hash=a.evidence_hash WHERE a.tenant_id=$1 AND 'eip155:' || (a.document->'observation'->>'chainId') || ':' || (a.document->'observation'->>'address')=$2 ORDER BY a.created_at DESC,a.id LIMIT 100",
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

  private verified(row: {
    document: Assessment;
    record_hash: string;
    observation: unknown;
  }): Assessment {
    const value = row.document;
    if (
      evidenceHash(value) !== row.record_hash ||
      evidenceHash(row.observation) !== value.evidenceHash ||
      evidenceHash(value.observation) !== value.evidenceHash
    )
      throw new Error('Stored evidence integrity failure');
    return Assessment.parse(value);
  }

  async list(tenantId: string): Promise<Assessment[]> {
    return this.scoped(tenantId, async (client) => {
      const result = await client.query(
        'SELECT a.document, a.record_hash, e.observation FROM assessments a JOIN evidence e ON e.tenant_id = a.tenant_id AND e.hash = a.evidence_hash WHERE a.tenant_id = $1 ORDER BY a.created_at DESC, a.id LIMIT 50',
        [tenantId],
      );
      return result.rows.map((row) => this.verified(row));
    });
  }

  async get(tenantId: string, id: string): Promise<Assessment | null> {
    return this.scoped(tenantId, async (client) => {
      const result = await client.query(
        'SELECT a.document, a.record_hash, e.observation FROM assessments a JOIN evidence e ON e.tenant_id = a.tenant_id AND e.hash = a.evidence_hash WHERE a.tenant_id = $1 AND a.id = $2',
        [tenantId, id],
      );
      return result.rows[0] ? this.verified(result.rows[0]) : null;
    });
  }

  async ping(): Promise<void> {
    await this.pool
      .query("SELECT version FROM schema_migrations WHERE version = '002_inventory'")
      .then((result) => {
        if (!result.rowCount) throw new Error('Migration required');
      });
  }
}
