import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { z } from 'zod';
import {
  canonicalAssetId,
  type Assessment,
  type ScanInput,
} from '../../../packages/domain-models/src/index.js';
import type {
  MonitoringRequest,
  MonitoringUpdate,
} from '../../../packages/domain-models/src/cpm.js';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';
import { CpmPolicyStore, audit, notify } from './cpm-policy-store.js';
export interface Job {
  tenant_id: string;
  id: string;
  schedule_id: string;
  input: ScanInput;
  policy_id: string;
  policy_version: string;
  status: 'queued' | 'running' | 'retry' | 'succeeded' | 'failed' | 'cancelled';
  attempts: number;
  lease_token: string | null;
  lease_until: Date | null;
  worker_id: string | null;
  assessment_id: string | null;
  error_code: string | null;
}
export class MonitoringStore {
  constructor(
    readonly policies: CpmPolicyStore,
    readonly concurrency = 2,
    readonly rpcPerMinute = 120,
  ) {
    if (
      !Number.isInteger(concurrency) ||
      concurrency < 1 ||
      concurrency > 8 ||
      !Number.isInteger(rpcPerMinute) ||
      rpcPerMinute < 1 ||
      rpcPerMinute > 10000
    )
      throw new Error('Invalid worker limits');
  }
  get base() {
    return this.policies.base;
  }
  async lock(c: PoolClient, tenant: string) {
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${tenant}:monitoring`]);
  }
  create(tenant: string, request: z.infer<typeof MonitoringRequest>, actor: string) {
    return this.base.scoped(tenant, async (c) => {
      await this.lock(c, tenant);
      const assetId = canonicalAssetId(request.input.chainId, request.input.address);
      if (
        !(
          await c.query('SELECT 1 FROM assets WHERE tenant_id=$1 AND asset_id=$2', [
            tenant,
            assetId,
          ])
        ).rowCount
      )
        throw new HttpException('Assess and register the asset before scheduling', 404);
      const policy = await this.policies.load(c, tenant, request.policy, assetId),
        id = randomUUID();
      const existing = (
        await c.query(
          'SELECT * FROM monitoring_schedules WHERE tenant_id=$1 AND asset_id=$2 AND policy_id=$3 AND enabled',
          [tenant, assetId, policy.id],
        )
      ).rows[0];
      if (existing) {
        if (
          existing.policy_version === policy.version &&
          existing.interval_seconds === request.intervalSeconds &&
          evidenceHash(existing.input) === evidenceHash(request.input)
        )
          return existing;
        throw new HttpException(
          'Active monitoring already exists for this asset and policy; update or pause it first',
          409,
        );
      }
      if (
        Number(
          (
            await c.query(
              'SELECT count(*) AS count FROM monitoring_schedules WHERE tenant_id=$1 AND enabled',
              [tenant],
            )
          ).rows[0].count,
        ) >= 100
      )
        throw new HttpException('Monitoring schedule limit reached', 429);
      const row = (
        await c.query(
          'INSERT INTO monitoring_schedules(tenant_id,id,asset_id,input,policy_id,policy_version,interval_seconds,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
          [
            tenant,
            id,
            assetId,
            JSON.stringify(request.input),
            policy.id,
            policy.version,
            request.intervalSeconds,
            actor,
          ],
        )
      ).rows[0];
      await audit(c, tenant, actor, 'monitoring.created', id, request);
      return row;
    });
  }
  list(tenant: string, limit: number, offset: number) {
    return this.base.scoped(
      tenant,
      async (c) =>
        (
          await c.query(
            `SELECT s.*,j.status AS worker_state,j.id AS latest_job_id,j.error_code, w.heartbeat_at
      FROM monitoring_schedules s LEFT JOIN LATERAL (SELECT * FROM assessment_jobs WHERE tenant_id=s.tenant_id AND schedule_id=s.id ORDER BY created_at DESC,id DESC LIMIT 1) j ON true
      LEFT JOIN worker_leases w ON w.tenant_id=j.tenant_id AND w.worker_id=j.worker_id
      WHERE s.tenant_id=$1 ORDER BY s.created_at DESC,s.id LIMIT $2 OFFSET $3`,
            [tenant, limit, offset],
          )
        ).rows,
    );
  }
  update(tenant: string, id: string, input: z.infer<typeof MonitoringUpdate>, actor: string) {
    return this.base.scoped(tenant, async (c) => {
      await this.lock(c, tenant);
      const existing = (
        await c.query('SELECT * FROM monitoring_schedules WHERE tenant_id=$1 AND id=$2', [
          tenant,
          id,
        ])
      ).rows[0];
      if (!existing) throw new HttpException('Schedule not found', 404);
      if (input.enabled && !existing.enabled) {
        if (
          (
            await c.query(
              'SELECT 1 FROM monitoring_schedules WHERE tenant_id=$1 AND asset_id=$2 AND policy_id=$3 AND enabled',
              [tenant, existing.asset_id, existing.policy_id],
            )
          ).rowCount
        )
          throw new HttpException('Active monitoring already exists', 409);
        if (
          Number(
            (
              await c.query(
                'SELECT count(*) AS count FROM monitoring_schedules WHERE tenant_id=$1 AND enabled',
                [tenant],
              )
            ).rows[0].count,
          ) >= 100
        )
          throw new HttpException('Monitoring schedule limit reached', 429);
      }
      const row = (
        await c.query(
          'UPDATE monitoring_schedules SET enabled=COALESCE($3,enabled),interval_seconds=COALESCE($4,interval_seconds),next_run_at=now() WHERE tenant_id=$1 AND id=$2 RETURNING *',
          [tenant, id, input.enabled ?? null, input.intervalSeconds ?? null],
        )
      ).rows[0];
      if (!row) throw new HttpException('Schedule not found', 404);
      if (!row.enabled)
        await c.query(
          "UPDATE assessment_jobs SET status='cancelled',lease_token=NULL,lease_until=NULL,finished_at=now() WHERE tenant_id=$1 AND schedule_id=$2 AND status IN ('queued','running','retry')",
          [tenant, id],
        );
      await audit(c, tenant, actor, 'monitoring.updated', id, input);
      return row;
    });
  }
  enqueueDue(tenant: string) {
    return this.base.scoped(tenant, async (c) => {
      await this.lock(c, tenant);
      const due = (
        await c.query(
          `SELECT s.* FROM monitoring_schedules s JOIN cryptographic_policies p ON p.tenant_id=s.tenant_id AND p.id=s.policy_id
        WHERE s.tenant_id=$1 AND s.enabled AND p.active AND s.next_run_at<=now()
        AND NOT EXISTS(SELECT 1 FROM assessment_jobs j WHERE j.tenant_id=s.tenant_id AND j.schedule_id=s.id AND j.status IN ('queued','running','retry'))
        ORDER BY s.next_run_at,s.id LIMIT 50 FOR UPDATE OF s SKIP LOCKED`,
          [tenant],
        )
      ).rows;
      for (const s of due) {
        const key = `${s.id}:${new Date(s.next_run_at).toISOString()}`;
        await c.query(
          'INSERT INTO assessment_jobs(tenant_id,id,schedule_id,idempotency_key,input,policy_id,policy_version) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING',
          [tenant, randomUUID(), s.id, key, JSON.stringify(s.input), s.policy_id, s.policy_version],
        );
        await c.query(
          "UPDATE monitoring_schedules SET next_run_at=now()+interval_seconds*interval '1 second' WHERE tenant_id=$1 AND id=$2",
          [tenant, s.id],
        );
      }
      return due.length;
    });
  }
  claim(tenant: string, worker: string, leaseSeconds = 75): Promise<Job | null> {
    if (
      !/^[a-zA-Z0-9:_-]{1,100}$/.test(worker) ||
      !Number.isInteger(leaseSeconds) ||
      leaseSeconds < 1 ||
      leaseSeconds > 300
    )
      throw new Error('Invalid lease configuration');
    return this.base.scoped(tenant, async (c) => {
      await this.lock(c, tenant);
      await c.query(
        'INSERT INTO worker_leases(tenant_id,worker_id) VALUES($1,$2) ON CONFLICT(tenant_id,worker_id) DO UPDATE SET heartbeat_at=now()',
        [tenant, worker],
      );
      const expired = (
        await c.query(
          "UPDATE assessment_jobs SET status=CASE WHEN attempts>=5 THEN 'failed' ELSE 'retry' END, error_code='lease_expired',lease_token=NULL,lease_until=NULL,available_at=now()+LEAST(300,power(2,attempts)::integer)*interval '1 second' WHERE tenant_id=$1 AND status='running' AND lease_until<=clock_timestamp() RETURNING *",
          [tenant],
        )
      ).rows as Job[];
      for (const job of expired) await this.recordFailure(c, job, 'lease_expired');
      const active = Number(
        (
          await c.query(
            "SELECT count(*) AS count FROM assessment_jobs WHERE tenant_id=$1 AND status='running'",
            [tenant],
          )
        ).rows[0].count,
      );
      if (active >= this.concurrency) return null;
      const result = await c.query(
        `WITH next AS (SELECT j.id FROM assessment_jobs j JOIN monitoring_schedules s ON s.tenant_id=j.tenant_id AND s.id=j.schedule_id JOIN cryptographic_policies p ON p.tenant_id=j.tenant_id AND p.id=j.policy_id
        WHERE j.tenant_id=$1 AND j.status IN ('queued','retry') AND j.available_at<=now() AND j.attempts<5 AND s.enabled AND p.active ORDER BY j.available_at,j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED)
        UPDATE assessment_jobs j SET status='running',attempts=attempts+1,lease_token=$2,lease_until=clock_timestamp()+$3*interval '1 second',worker_id=$4,started_at=now()
        FROM next WHERE j.tenant_id=$1 AND j.id=next.id RETURNING j.*`,
        [tenant, randomUUID(), leaseSeconds, worker],
      );
      return result.rows[0] ?? null;
    });
  }
  async recordFailure(c: PoolClient, job: Job, code: string) {
    await c.query(
      'UPDATE monitoring_schedules SET last_failure_at=now(),last_failure=$3 WHERE tenant_id=$1 AND id=$2',
      [job.tenant_id, job.schedule_id, code],
    );
    await notify(
      c,
      job.tenant_id,
      `${job.id}:failure:${job.attempts}`,
      'collection_failure',
      job.id,
      { code, attempt: job.attempts, posture: 'unknown', previousFindingsPreserved: true },
    );
  }
  fail(
    job: Job,
    code:
      | 'collection_failed'
      | 'assessment_timeout'
      | 'lease_expired'
      | 'rpc_budget_exceeded'
      | 'canonicality_changed',
  ) {
    return this.base.scoped(job.tenant_id, async (c) => {
      await this.lock(c, job.tenant_id);
      const result = await c.query(
        "UPDATE assessment_jobs SET status=CASE WHEN attempts>=5 THEN 'failed' ELSE 'retry' END,error_code=$4,lease_token=NULL,lease_until=NULL,available_at=now()+LEAST(300,power(2,attempts)::integer)*interval '1 second',finished_at=CASE WHEN attempts>=5 THEN now() ELSE NULL END WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND status='running' RETURNING *",
        [job.tenant_id, job.id, job.lease_token, code],
      );
      if (!result.rowCount) return false;
      await this.recordFailure(c, result.rows[0], code);
      return true;
    });
  }
  async assertLease(c: PoolClient, job: Job) {
    const row = (
      await c.query(
        "SELECT j.* FROM assessment_jobs j JOIN monitoring_schedules s ON s.tenant_id=j.tenant_id AND s.id=j.schedule_id WHERE j.tenant_id=$1 AND j.id=$2 AND j.lease_token=$3 AND j.status='running' AND j.lease_until>clock_timestamp() AND s.enabled FOR UPDATE OF j",
        [job.tenant_id, job.id, job.lease_token],
      )
    ).rows[0];
    if (!row) throw new HttpException('Job lease is no longer active', 409);
  }
  complete(job: Job, assessment: Assessment, persist: (c: PoolClient) => Promise<unknown>) {
    return this.base.scoped(job.tenant_id, async (c) => {
      await this.lock(c, job.tenant_id);
      await this.assertLease(c, job);
      await this.base.insert(c, assessment, `worker:${job.worker_id}`);
      await persist(c);
      // Recheck wall clock after all work; rollback everything if the lease expired.
      const result = await c.query(
        "UPDATE assessment_jobs SET status='succeeded',assessment_id=$4,finished_at=now(),lease_token=NULL,lease_until=NULL,error_code=NULL WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND lease_until>clock_timestamp() AND status='running' RETURNING id",
        [job.tenant_id, job.id, job.lease_token, assessment.id],
      );
      if (!result.rowCount) throw new HttpException('Job lease expired before commit', 409);
      await c.query(
        'UPDATE monitoring_schedules SET last_success_at=now() WHERE tenant_id=$1 AND id=$2',
        [job.tenant_id, job.schedule_id],
      );
      return assessment;
    });
  }
  consumeRpc(job: Job): Promise<boolean> {
    return this.base.scoped(job.tenant_id, async (c) => {
      await this.assertLease(c, job);
      const r = await c.query(
        `INSERT INTO rpc_budgets(tenant_id,chain_id,window_start,used) VALUES($1,$2,date_trunc('minute',clock_timestamp()),1)
        ON CONFLICT(tenant_id,chain_id) DO UPDATE SET window_start=date_trunc('minute',clock_timestamp()),used=CASE WHEN rpc_budgets.window_start<date_trunc('minute',clock_timestamp()) THEN 1 ELSE rpc_budgets.used+1 END
        WHERE rpc_budgets.window_start<date_trunc('minute',clock_timestamp()) OR rpc_budgets.used<$3 RETURNING used`,
        [job.tenant_id, job.input.chainId, this.rpcPerMinute],
      );
      return !!r.rowCount;
    });
  }
  get(tenant: string, id: string) {
    return this.base.scoped(
      tenant,
      async (c) =>
        (await c.query('SELECT * FROM assessment_jobs WHERE tenant_id=$1 AND id=$2', [tenant, id]))
          .rows[0] ?? null,
    );
  }
  cancel(tenant: string, id: string, actor: string) {
    return this.base.scoped(tenant, async (c) => {
      await this.lock(c, tenant);
      const row = (
        await c.query(
          "UPDATE assessment_jobs SET status='cancelled',lease_token=NULL,lease_until=NULL,finished_at=now() WHERE tenant_id=$1 AND id=$2 AND status IN ('queued','running','retry') RETURNING id",
          [tenant, id],
        )
      ).rows[0];
      if (!row) throw new HttpException('Cancellable job not found', 404);
      await audit(c, tenant, actor, 'job.cancelled', id, {});
      return { id, status: 'cancelled' };
    });
  }
  // Only transient operational rows are pruned. Evidence, policies, findings and audit remain append-only.
  prune(tenant: string) {
    return this.base.scoped(tenant, async (c) => {
      await c.query(
        "DELETE FROM assessment_jobs WHERE tenant_id=$1 AND id IN (SELECT id FROM assessment_jobs WHERE tenant_id=$1 AND status IN ('succeeded','failed','cancelled') AND COALESCE(finished_at,created_at)<now()-interval '90 days' ORDER BY created_at LIMIT 1000)",
        [tenant],
      );
      await c.query(
        "DELETE FROM worker_leases WHERE tenant_id=$1 AND heartbeat_at<now()-interval '7 days'",
        [tenant],
      );
    });
  }
}
