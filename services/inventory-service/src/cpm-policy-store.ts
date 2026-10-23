import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { CpmPolicy, PolicyRef, PolicyAssignment } from '../../../packages/domain-models/src/cpm.js';
import { defaultPolicy } from '../../../core/policy-engine/policies/web3.js';
import { policyHash } from '../../../core/policy-engine/rule-versioning/index.js';
import type { PostgresRepository } from './repository.js';
import type { z } from 'zod';

export async function audit(
  client: PoolClient,
  tenant: string,
  actor: string,
  action: string,
  resource: string,
  details: unknown,
) {
  await client.query(
    'INSERT INTO audit_events(tenant_id,id,actor,action,resource,details) VALUES($1,$2,$3,$4,$5,$6)',
    [tenant, randomUUID(), actor, action, resource, JSON.stringify(details)],
  );
}
export async function notify(
  client: PoolClient,
  tenant: string,
  id: string,
  kind: string,
  resource: string,
  details: unknown,
) {
  await client.query(
    'INSERT INTO notification_events(tenant_id,id,kind,resource,details) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
    [tenant, id, kind, resource, JSON.stringify(details)],
  );
}
export class CpmPolicyStore {
  constructor(readonly base: PostgresRepository) {}
  async seed(client: PoolClient, tenant: string) {
    await client.query(
      'INSERT INTO cryptographic_policies(tenant_id,id) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [tenant, defaultPolicy.id],
    );
    await client.query(
      'INSERT INTO policy_versions(tenant_id,policy_id,version,document,content_hash,actor) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
      [
        tenant,
        defaultPolicy.id,
        defaultPolicy.version,
        JSON.stringify(defaultPolicy),
        policyHash(defaultPolicy),
        'system:baseline',
      ],
    );
  }
  async load(
    client: PoolClient,
    tenant: string,
    ref?: z.infer<typeof PolicyRef>,
    assetId?: string,
    historical = false,
  ) {
    await this.seed(client, tenant);
    if (!ref && assetId) {
      const assignment = (
        await client.query(
          'SELECT policy_id,policy_version FROM policy_assignments WHERE tenant_id=$1 AND asset_id=$2',
          [tenant, assetId],
        )
      ).rows[0];
      if (assignment) ref = { id: assignment.policy_id, version: assignment.policy_version };
    }
    ref ??= { id: defaultPolicy.id, version: defaultPolicy.version };
    const row = (
      await client.query(
        'SELECT v.document,v.content_hash,p.active FROM policy_versions v JOIN cryptographic_policies p ON p.tenant_id=v.tenant_id AND p.id=v.policy_id WHERE v.tenant_id=$1 AND v.policy_id=$2 AND v.version=$3',
        [tenant, ref.id, ref.version],
      )
    ).rows[0];
    if (!row) throw new HttpException('Policy version not found', 404);
    if (!row.active && !historical) throw new HttpException('Policy is retired', 409);
    const policy = CpmPolicy.parse(row.document);
    if (policyHash(policy) !== row.content_hash) throw new Error('Policy integrity failure');
    return policy;
  }
  list(tenant: string, limit: number, offset: number) {
    return this.base.scoped(tenant, async (c) => {
      await this.seed(c, tenant);
      return (
        await c.query(
          'SELECT p.active,v.document,v.content_hash,v.actor,v.created_at FROM policy_versions v JOIN cryptographic_policies p ON p.tenant_id=v.tenant_id AND p.id=v.policy_id WHERE v.tenant_id=$1 ORDER BY v.created_at DESC,v.policy_id,v.version LIMIT $2 OFFSET $3',
          [tenant, limit, offset],
        )
      ).rows.map((row) => {
        if (policyHash(CpmPolicy.parse(row.document)) !== row.content_hash)
          throw new Error('Policy integrity failure');
        return row;
      });
    });
  }
  publish(tenant: string, input: CpmPolicy, actor: string) {
    const policy = CpmPolicy.parse(input);
    return this.base.scoped(tenant, async (c) => {
      await this.seed(c, tenant);
      await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
        `${tenant}:policy:${policy.id}`,
      ]);
      const exists = (
        await c.query(
          'SELECT content_hash FROM policy_versions WHERE tenant_id=$1 AND policy_id=$2 AND version=$3',
          [tenant, policy.id, policy.version],
        )
      ).rows[0];
      if (exists) {
        if (exists.content_hash !== policyHash(policy))
          throw new HttpException('Policy versions are immutable; publish a new version', 409);
        return policy;
      }
      await c.query(
        'INSERT INTO cryptographic_policies(tenant_id,id) VALUES($1,$2) ON CONFLICT DO NOTHING',
        [tenant, policy.id],
      );
      await c.query(
        'INSERT INTO policy_versions(tenant_id,policy_id,version,document,content_hash,actor) VALUES($1,$2,$3,$4,$5,$6)',
        [tenant, policy.id, policy.version, JSON.stringify(policy), policyHash(policy), actor],
      );
      await audit(c, tenant, actor, 'policy.published', `${policy.id}/${policy.version}`, {
        hash: policyHash(policy),
      });
      return policy;
    });
  }
  setActive(tenant: string, id: string, active: boolean, actor: string) {
    return this.base.scoped(tenant, async (c) => {
      const result = await c.query(
        'UPDATE cryptographic_policies SET active=$3 WHERE tenant_id=$1 AND id=$2 RETURNING id',
        [tenant, id, active],
      );
      if (!result.rowCount) throw new HttpException('Policy not found', 404);
      await audit(c, tenant, actor, 'policy.lifecycle', id, { active });
      return { id, active };
    });
  }
  assign(tenant: string, input: z.infer<typeof PolicyAssignment>, actor: string) {
    return this.base.scoped(tenant, async (c) => {
      await this.load(c, tenant, input.policy);
      if (
        !(
          await c.query('SELECT 1 FROM assets WHERE tenant_id=$1 AND asset_id=$2', [
            tenant,
            input.assetId,
          ])
        ).rowCount
      )
        throw new HttpException('Asset not found', 404);
      await c.query(
        'INSERT INTO policy_assignments(tenant_id,asset_id,policy_id,policy_version,operational_importance,actor) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,asset_id) DO UPDATE SET policy_id=$3,policy_version=$4,operational_importance=$5,actor=$6,updated_at=now()',
        [
          tenant,
          input.assetId,
          input.policy.id,
          input.policy.version,
          input.operationalImportance,
          actor,
        ],
      );
      await audit(c, tenant, actor, 'policy.assigned', input.assetId, input);
      return input;
    });
  }
}
