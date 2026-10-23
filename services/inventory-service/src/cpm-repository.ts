import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { z } from 'zod';
import type { Assessment } from '../../../packages/domain-models/src/index.js';
import { canonicalAssetId, Finding } from '../../../packages/domain-models/src/index.js';
import {
  PostureSnapshot,
  type PolicyRef,
  type FindingTransition,
  type MigrationRequest,
  MigrationResult,
} from '../../../packages/domain-models/src/cpm.js';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';
import { evaluateCpm } from '../../../core/cpm-engine/posture-evaluation/snapshot.js';
import { comparePosture } from '../../../core/cpm-engine/drift-detection/index.js';
import {
  effectiveStatus,
  allowedTransition,
} from '../../../core/policy-engine/exceptions/index.js';
import { recommend } from '../../../core/risk-engine/remediation.js';
import { assessMigration } from '../../../core/migration-engine/assess.js';
import { CpmPolicyStore, audit, notify } from './cpm-policy-store.js';
import type { PostgresRepository } from './repository.js';
type Event = {
  status: string;
  expires_at?: Date | null;
  rule_id: string;
  snapshot_id: string;
  assessment_id: string;
  verification_snapshot_id: string | null;
};
export class CpmRepository {
  readonly policies: CpmPolicyStore;
  constructor(readonly base: PostgresRepository) {
    this.policies = new CpmPolicyStore(base);
  }
  async lock(c: PoolClient, tenant: string, asset: string) {
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${tenant}:monitoring`]);
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
      `${tenant}:posture:${asset}`,
    ]);
  }
  async knownInvalid(c: PoolClient, a: Assessment) {
    return !!(
      await c.query(
        `SELECT 1 FROM snapshot_invalidations i JOIN posture_snapshots p ON p.tenant_id=i.tenant_id AND p.id=i.snapshot_id JOIN assessments a ON a.tenant_id=p.tenant_id AND a.id=p.assessment_id
      WHERE p.tenant_id=$1 AND (a.document->'observation'->>'chainId')::bigint=$2 AND (a.document->'observation'->>'blockHash'=$3 OR ($4::text IS NOT NULL AND a.document->'observation'->'signature'->>'blockHash'=$4)) LIMIT 1`,
        [
          a.tenantId,
          a.observation.chainId,
          a.observation.blockHash,
          a.observation.signature?.blockHash ?? null,
        ],
      )
    ).rowCount;
  }
  verify(row: { document: unknown; content_hash: string }) {
    if (evidenceHash(row.document) !== row.content_hash)
      throw new Error('Posture integrity failure');
    return PostureSnapshot.parse(row.document);
  }
  async assess(tenant: string, id: string, ref?: z.infer<typeof PolicyRef>, actor = 'internal') {
    const assessment = await this.base.get(tenant, id);
    if (!assessment) throw new HttpException('Assessment not found', 404);
    return this.base.scoped(tenant, (c) => this.persist(c, assessment, ref, actor));
  }
  async persist(c: PoolClient, a: Assessment, ref?: z.infer<typeof PolicyRef>, actor = 'internal') {
    const tenant = a.tenantId,
      asset = canonicalAssetId(a.observation.chainId, a.observation.address);
    await this.lock(c, tenant, asset);
    if (await this.knownInvalid(c, a))
      throw new HttpException(
        'Invalidated evidence requires collection from canonical chain state',
        409,
      );
    const policy = await this.policies.load(c, tenant, ref, asset);
    const snapshot = evaluateCpm(a, policy);
    const replay = (
      await c.query(
        'SELECT document,content_hash FROM posture_snapshots WHERE tenant_id=$1 AND id=$2',
        [tenant, snapshot.id],
      )
    ).rows[0];
    if (replay) return this.verify(replay);
    const previousRow = (
      await c.query(
        `SELECT p.document,p.content_hash,a.document AS assessment FROM posture_snapshots p JOIN assessments a ON a.tenant_id=p.tenant_id AND a.id=p.assessment_id
      WHERE p.tenant_id=$1 AND p.asset_id=$2 AND p.policy_id=$3 AND NOT EXISTS(SELECT 1 FROM snapshot_invalidations i WHERE i.tenant_id=p.tenant_id AND i.snapshot_id=p.id)
      ORDER BY p.observed_at DESC,p.created_at DESC,p.id DESC LIMIT 1`,
        [tenant, asset, policy.id],
      )
    ).rows[0];
    const previous = previousRow ? this.verify(previousRow) : null;
    await c.query(
      'INSERT INTO posture_snapshots(tenant_id,id,asset_id,assessment_id,policy_id,policy_version,document,content_hash,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [
        tenant,
        snapshot.id,
        asset,
        a.id,
        policy.id,
        policy.version,
        JSON.stringify(snapshot),
        evidenceHash(snapshot),
        a.observation.observedAt,
      ],
    );
    // Historical reevaluation remains stored but cannot overwrite the effective latest state.
    const forward =
      !previousRow ||
      (BigInt(a.observation.blockNumber) >=
        BigInt(previousRow.assessment.observation.blockNumber) &&
        a.observation.observedAt >= previousRow.assessment.observation.observedAt);
    if (forward) {
      if (previous)
        for (const drift of comparePosture(previous, snapshot)) {
          await c.query(
            'INSERT INTO cryptographic_drift_events(tenant_id,id,previous_snapshot_id,current_snapshot_id,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
            [tenant, drift.id, previous!.id, snapshot.id, JSON.stringify(drift)],
          );
          await notify(c, tenant, drift.id, 'cryptographic_drift', asset, drift);
        }
      const later =
        !!previousRow &&
        BigInt(a.observation.blockNumber) > BigInt(previousRow.assessment.observation.blockNumber);
      await this.syncFindings(c, tenant, snapshot, previous, later);
    }
    const importance =
      (
        await c.query(
          'SELECT operational_importance FROM policy_assignments WHERE tenant_id=$1 AND asset_id=$2',
          [tenant, asset],
        )
      ).rows[0]?.operational_importance ?? 'normal';
    for (const recommendation of recommend(snapshot, policy, importance))
      await c.query(
        'INSERT INTO remediation_recommendations(tenant_id,snapshot_id,rule_id,document) VALUES($1,$2,$3,$4)',
        [tenant, snapshot.id, recommendation.ruleId, JSON.stringify(recommendation)],
      );
    await audit(c, tenant, actor, 'cpm.assessed', snapshot.id, {
      assessmentId: a.id,
      policyHash: snapshot.policyHash,
    });
    return snapshot;
  }
  async latestEvents(
    c: PoolClient,
    tenant: string,
    asset: string,
    policy: string,
  ): Promise<Event[]> {
    return (
      await c.query(
        'SELECT DISTINCT ON(rule_id) * FROM finding_events WHERE tenant_id=$1 AND asset_id=$2 AND policy_id=$3 ORDER BY rule_id,event_seq DESC',
        [tenant, asset, policy],
      )
    ).rows;
  }
  async event(
    c: PoolClient,
    tenant: string,
    snapshot: PostureSnapshot,
    rule: string,
    status: string,
    reason: string,
    actor: string,
    expires?: string,
    verification?: string,
  ) {
    await c.query(
      'INSERT INTO finding_events(tenant_id,id,assessment_id,rule_id,status,reason,actor,expires_at,asset_id,policy_id,snapshot_id,verification_snapshot_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
      [
        tenant,
        randomUUID(),
        snapshot.assessmentId,
        rule,
        status,
        reason,
        actor,
        expires ?? null,
        snapshot.assetId,
        snapshot.policyId,
        snapshot.id,
        verification ?? null,
      ],
    );
  }
  async syncFindings(
    c: PoolClient,
    tenant: string,
    snapshot: PostureSnapshot,
    previous: PostureSnapshot | null,
    later: boolean,
  ) {
    const events = await this.latestEvents(c, tenant, snapshot.assetId, snapshot.policyId);
    for (const result of snapshot.evaluations) {
      const last = events.find((e) => e.rule_id === result.ruleId),
        state = last ? effectiveStatus(last) : null;
      const actionable = result.result === 'violation' || result.result === 'unknown';
      if (
        actionable &&
        (!last || state === 'resolved' || (last.status === 'excepted' && state === 'open'))
      ) {
        await this.event(
          c,
          tenant,
          snapshot,
          result.ruleId,
          'open',
          !last
            ? 'First supported policy observation'
            : state === 'resolved'
              ? 'Condition observed again; technical resolution reopened'
              : 'Exception expired; condition remains actionable',
          'system:cpm',
        );
      } else if (
        last &&
        state === 'pending_verification' &&
        result.result === 'satisfied' &&
        later
      ) {
        const prior = previous?.evaluations.find((e) => e.ruleId === result.ruleId);
        if (prior?.ruleHash === result.ruleHash && prior.result === 'violation')
          await this.event(
            c,
            tenant,
            snapshot,
            result.ruleId,
            'resolved',
            'A later finalized assessment satisfies the same evidence requirement. Resolution is limited to this rule.',
            'system:verification',
            undefined,
            snapshot.id,
          );
      }
    }
  }
  transition(
    tenant: string,
    id: string,
    rule: string,
    input: z.infer<typeof FindingTransition>,
    actor: string,
    auditAction = 'finding.transition',
  ) {
    return this.base.scoped(tenant, async (c) => {
      const row = (
        await c.query(
          'SELECT document,content_hash FROM posture_snapshots WHERE tenant_id=$1 AND id=$2',
          [tenant, id],
        )
      ).rows[0];
      if (!row) throw new HttpException('Posture not found', 404);
      const snapshot = this.verify(row);
      await this.lock(c, tenant, snapshot.assetId);
      const last = (await this.latestEvents(c, tenant, snapshot.assetId, snapshot.policyId)).find(
        (e) => e.rule_id === rule,
      );
      if (!last || !snapshot.evaluations.some((e) => e.ruleId === rule))
        throw new HttpException('Finding not found', 404);
      if (!allowedTransition(effectiveStatus(last), input.status))
        throw new HttpException('Invalid finding transition', 409);
      if (
        input.status === 'excepted' &&
        (!input.expiresAt || Date.parse(input.expiresAt) <= Date.now())
      )
        throw new HttpException('Exception expiry must be in the future', 400);
      await this.event(
        c,
        tenant,
        snapshot,
        rule,
        input.status,
        input.reason,
        actor,
        input.expiresAt,
      );
      await audit(c, tenant, actor, auditAction, `${snapshot.assetId}:${rule}`, input);
      return { status: input.status };
    });
  }
  history(tenant: string, asset: string, limit: number, offset: number) {
    return this.base.scoped(tenant, async (c) =>
      (
        await c.query(
          `SELECT p.document,p.content_hash,i.reason AS invalidation_reason FROM posture_snapshots p
      JOIN assessments a ON a.tenant_id=p.tenant_id AND a.id=p.assessment_id LEFT JOIN snapshot_invalidations i ON i.tenant_id=p.tenant_id AND i.snapshot_id=p.id
      WHERE p.tenant_id=$1 AND p.asset_id=$2 ORDER BY p.observed_at DESC,p.created_at DESC,p.id DESC LIMIT $3 OFFSET $4`,
          [tenant, asset, limit, offset],
        )
      ).rows.map((row) => ({
        ...this.verify(row),
        validity: row.invalidation_reason ? 'invalidated' : 'provider-finalized',
        invalidationReason: row.invalidation_reason ?? null,
      })),
    );
  }
  async posture(tenant: string, asset: string) {
    const records = await this.history(tenant, asset, 1, 0);
    if (!records[0]) return null;
    const snapshot = records[0];
    const lifecycle = await this.base.scoped(tenant, async (c) =>
      (
        await c.query(
          'SELECT DISTINCT ON(policy_id,rule_id) * FROM finding_events WHERE tenant_id=$1 AND asset_id=$2 ORDER BY policy_id,rule_id,event_seq DESC',
          [tenant, asset],
        )
      ).rows.map((e) => ({ ...e, effectiveStatus: effectiveStatus(e) })),
    );
    const currentFindings = await this.base.scoped(tenant, async (c) => {
      const rows = (
        await c.query(
          `SELECT DISTINCT ON(p.policy_id,f.value->>'ruleId') f.value AS finding,p.assessment_id,p.id,p.policy_id,i.reason FROM posture_snapshots p
        CROSS JOIN LATERAL jsonb_array_elements(p.document->'findings') f(value)
        LEFT JOIN snapshot_invalidations i ON i.tenant_id=p.tenant_id AND i.snapshot_id=p.id
        WHERE p.tenant_id=$1 AND p.asset_id=$2 ORDER BY p.policy_id,f.value->>'ruleId',p.observed_at DESC,p.created_at DESC,p.id DESC`,
          [tenant, asset],
        )
      ).rows;
      return rows.map((row) => ({
        ...Finding.parse(row.finding),
        policyId: row.policy_id as string,
        lastObservedAssessmentId: row.assessment_id as string,
        lastObservedSnapshotId: row.id as string,
        evidenceValidity: row.reason ? ('invalidated' as const) : ('provider-finalized' as const),
        effectiveStatus:
          lifecycle.find((e) => e.rule_id === row.finding.ruleId && e.policy_id === row.policy_id)
            ?.effectiveStatus ?? 'open',
      }));
    });
    const health = await this.base.scoped(
      tenant,
      async (c) =>
        (
          await c.query(
            'SELECT last_success_at,last_failure_at,last_failure,next_run_at,enabled FROM monitoring_schedules WHERE tenant_id=$1 AND asset_id=$2 ORDER BY created_at DESC LIMIT 10',
            [tenant, asset],
          )
        ).rows,
    );
    const currentStatus =
      snapshot.validity === 'invalidated'
        ? 'stale'
        : health.some(
              (s) =>
                s.last_failure_at &&
                new Date(s.last_failure_at) > new Date(snapshot.assessedAt) &&
                (!s.last_success_at || new Date(s.last_failure_at) > new Date(s.last_success_at)),
            )
          ? 'collection_failed'
          : 'observed';
    return {
      snapshot,
      lifecycle,
      currentFindings,
      currentStatus,
      currentQuantumExposure: currentStatus === 'observed' ? snapshot.quantumExposure : 'unknown',
      monitoring: health,
    };
  }
  list(
    tenant: string,
    kind: 'drift' | 'remediation' | 'notifications',
    limit: number,
    offset: number,
  ) {
    const sql =
      kind === 'drift'
        ? 'SELECT document FROM cryptographic_drift_events WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3'
        : kind === 'notifications'
          ? 'SELECT * FROM notification_events WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3'
          : `SELECT r.document FROM remediation_recommendations r JOIN posture_snapshots p ON p.tenant_id=r.tenant_id AND p.id=r.snapshot_id WHERE r.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM snapshot_invalidations i WHERE i.tenant_id=p.tenant_id AND i.snapshot_id=p.id) AND p.id=(SELECT p2.id FROM posture_snapshots p2 JOIN assessments a2 ON a2.tenant_id=p2.tenant_id AND a2.id=p2.assessment_id WHERE p2.tenant_id=p.tenant_id AND p2.asset_id=p.asset_id AND p2.policy_id=p.policy_id ORDER BY p2.observed_at DESC,p2.created_at DESC,p2.id DESC LIMIT 1) ORDER BY r.created_at DESC,r.snapshot_id,r.rule_id LIMIT $2 OFFSET $3`;
    return this.base.scoped(tenant, async (c) =>
      (await c.query(sql, [tenant, limit, offset])).rows.map((row) =>
        kind === 'notifications' ? row : row.document,
      ),
    );
  }
  async latestValidAssessment(tenant: string, asset: string) {
    const id = await this.base.scoped(
      tenant,
      async (c) =>
        (
          await c.query(
            `SELECT p.assessment_id FROM posture_snapshots p JOIN assessments a ON a.tenant_id=p.tenant_id AND a.id=p.assessment_id WHERE p.tenant_id=$1 AND p.asset_id=$2 AND NOT EXISTS(SELECT 1 FROM snapshot_invalidations i WHERE i.tenant_id=p.tenant_id AND i.snapshot_id=p.id) ORDER BY p.observed_at DESC,p.created_at DESC LIMIT 1`,
            [tenant, asset],
          )
        ).rows[0]?.assessment_id,
    );
    return id ? this.base.get(tenant, id) : null;
  }
  invalidate(tenant: string, assessment: Assessment, reason: string) {
    return this.base.scoped(tenant, async (c) => {
      await this.lock(
        c,
        tenant,
        canonicalAssetId(assessment.observation.chainId, assessment.observation.address),
      );
      const rows = (
        await c.query(
          `SELECT p.id,p.asset_id FROM posture_snapshots p JOIN assessments a ON a.tenant_id=p.tenant_id AND a.id=p.assessment_id WHERE p.tenant_id=$1 AND (a.document->'observation'->>'chainId')::bigint=$2 AND (a.document->'observation'->>'blockHash'=$3 OR ($4::text IS NOT NULL AND a.document->'observation'->'signature'->>'blockHash'=$4))`,
          [
            tenant,
            assessment.observation.chainId,
            assessment.observation.blockHash,
            assessment.observation.signature?.blockHash ?? null,
          ],
        )
      ).rows;
      for (const row of rows) {
        await c.query(
          'INSERT INTO snapshot_invalidations(tenant_id,snapshot_id,reason,details) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',
          [
            tenant,
            row.id,
            reason,
            JSON.stringify({
              assessmentId: assessment.id,
              source: 'configured-rpc-canonicality-recheck',
            }),
          ],
        );
        await notify(c, tenant, `${row.id}:invalidated`, 'snapshot_invalidated', row.asset_id, {
          snapshotId: row.id,
          reason,
        });
        await c.query(
          'UPDATE monitoring_schedules SET next_run_at=now() WHERE tenant_id=$1 AND asset_id=$2 AND enabled',
          [tenant, row.asset_id],
        );
        const snapshotRow = (
          await c.query(
            'SELECT document,content_hash FROM posture_snapshots WHERE tenant_id=$1 AND id=$2',
            [tenant, row.id],
          )
        ).rows[0];
        const snapshot = this.verify(snapshotRow);
        for (const last of await this.latestEvents(c, tenant, row.asset_id, snapshot.policyId)) {
          if (last.status === 'resolved' && last.verification_snapshot_id === row.id)
            await this.event(
              c,
              tenant,
              snapshot,
              last.rule_id,
              'open',
              'Verification evidence was invalidated; technical resolution requires reassessment',
              'system:canonicality',
            );
        }
      }
      await audit(c, tenant, 'system:canonicality', 'cpm.invalidated', assessment.id, {
        reason,
        count: rows.length,
      });
      return rows.length;
    });
  }
  async migration(
    tenant: string,
    request: z.infer<typeof MigrationRequest>,
    actor: string,
    parentId?: string,
  ) {
    const current = await this.base.get(tenant, request.assessmentId);
    if (!current) throw new HttpException('Assessment not found', 404);
    let baseline = current,
      definition = request;
    if (parentId) {
      const parent = await this.getMigration(tenant, parentId);
      if (!parent) throw new HttpException('Migration not found', 404);
      definition = parent.request;
      baseline = (await this.base.get(tenant, parent.document.baselineAssessmentId))!;
      if (
        canonicalAssetId(current.observation.chainId, current.observation.address) !==
        parent.document.assetId
      )
        throw new HttpException('Migration asset does not match', 400);
      if (BigInt(current.observation.blockNumber) <= BigInt(baseline.observation.blockNumber))
        throw new HttpException('Verification requires a later finalized block', 409);
    }
    return this.base.scoped(tenant, async (c) => {
      await this.lock(
        c,
        tenant,
        canonicalAssetId(current.observation.chainId, current.observation.address),
      );
      const invalid =
        (await this.knownInvalid(c, current)) || (await this.knownInvalid(c, baseline));
      if (invalid) throw new HttpException('Invalidated evidence cannot verify migration', 409);
      const existing = (
        await c.query(
          'SELECT document,content_hash FROM migration_assessments WHERE tenant_id=$1 AND assessment_id=$2 AND parent_id IS NOT DISTINCT FROM $3::uuid AND request=$4::jsonb',
          [tenant, current.id, parentId ?? null, JSON.stringify(definition)],
        )
      ).rows[0];
      if (existing) {
        if (evidenceHash(existing.document) !== existing.content_hash)
          throw new Error('Migration integrity failure');
        return MigrationResult.parse(existing.document);
      }
      const result = assessMigration(definition, baseline, current);
      await c.query(
        'INSERT INTO migration_assessments(tenant_id,id,assessment_id,parent_id,request,document,content_hash,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
        [
          tenant,
          result.id,
          current.id,
          parentId ?? null,
          JSON.stringify(definition),
          JSON.stringify(result),
          evidenceHash(result),
          actor,
        ],
      );
      await audit(c, tenant, actor, 'migration.assessed', result.id, {
        status: result.status,
        scope: result.scope,
      });
      return result;
    });
  }
  getMigration(
    tenant: string,
    id: string,
  ): Promise<{ request: z.infer<typeof MigrationRequest>; document: MigrationResult } | null> {
    return this.base.scoped(tenant, async (c) => {
      const row = (
        await c.query(
          'SELECT request,document,content_hash FROM migration_assessments WHERE tenant_id=$1 AND id=$2',
          [tenant, id],
        )
      ).rows[0];
      if (!row) return null;
      if (evidenceHash(row.document) !== row.content_hash)
        throw new Error('Migration integrity failure');
      const document = MigrationResult.parse(row.document);
      const invalid = (
        await c.query(
          'SELECT 1 FROM snapshot_invalidations i JOIN posture_snapshots p ON p.tenant_id=i.tenant_id AND p.id=i.snapshot_id WHERE p.tenant_id=$1 AND p.assessment_id=ANY($2::uuid[])',
          [tenant, [document.assessmentId, document.baselineAssessmentId]],
        )
      ).rowCount;
      return {
        request: row.request,
        document: invalid
          ? { ...document, validity: 'invalidated', effectiveStatus: 'PENDING_VERIFICATION' }
          : document,
      };
    });
  }
}
