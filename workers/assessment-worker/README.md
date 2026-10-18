# Durable CPM assessment worker

The TypeScript worker reassesses registered assets using PostgreSQL schedules and leases. It is separate from the optional single-checkpoint Go block indexer.

## Run

Use Node 22 or 24 LTS and the repository lockfile. Provision `DATABASE_URL` with the restricted runtime role, configured tenants/memberships and approved `CHAINS`. Run migrations using a separate migration identity. API and worker must use the same tenant and chain configuration.

```sh
pnpm install --frozen-lockfile
pnpm db:migrate
pnpm build
pnpm start:api
# Separate supervised process, same configuration:
pnpm start:worker
# Separate console process:
pnpm --filter @chainvanta/web-console start
```

For development use `pnpm worker:cpm`. For a self-contained fixture workflow use `pnpm demo:cpm`; this creates and disposes a test database/schema, not application data. Register an asset through `POST /v1/assessments`, then create a schedule through `POST /v1/cpm/monitoring` or the CPM console. Merely starting a worker does not create schedules or scan arbitrary addresses.

Set `NODE_ENV=production` for both API and worker in deployment. Demonstration providers and HTTP endpoints are rejected in production. TLS and hostname verification remain enabled for HTTPS RPC; destinations are restricted to configured URLs, checked public DNS answers and read-only methods. Configure separate private authenticated/TLS database and Redis connections, secret injection, HTTPS termination and `WEB_ORIGIN`; do not deploy the local `.env` or development Compose unchanged.

## Execution limits and recovery

- Schedules: 60 seconds–30 days, at most 100 enabled per tenant, one active schedule per asset/policy. Identical create requests reuse the active schedule. Pause before changing input or pinned policy version. Missed slots coalesce instead of backfilling an unbounded queue.
- Each process polls its configured tenants sequentially every five seconds and executes one job per tenant per sweep. Multiple replicas provide concurrency. All replicas must share `CPM_TENANT_CONCURRENCY` (default 2, maximum 8) and `CPM_RPC_PER_MINUTE` (default 120, maximum 10,000).
- A tenant advisory lock, row locking and a unique pending-job index prevent duplicate claims. A 75-second lease and random fencing token protect atomic commits; the collection deadline is 60 seconds. SIGTERM stops polling and drains the current bounded job. Allow at least 75 seconds before forced termination.
- At most five attempts per job. Backoff is `min(300, 2^attempts)` seconds. An expired lease records failure and becomes retryable; the old token cannot commit. A terminal failure is preserved; a future scheduled run can try again.
- RPC usage is counted in PostgreSQL per tenant/chain/minute, across worker replicas, with a separate maximum of 60 calls per job. Each request has a 10-second deadline, three attempts maximum, and a 1 MiB response cap. Budget is per tenant/chain, not a global commercial provider subscription quota. Size shared provider quotas for the sum of tenants.
- Successful collection, base assessment, CPM, findings, recommendations, drift and job completion commit together. A failed or cancelled job cannot save a passing assessment. Failure events retain earlier findings and project current posture as unknown.
- Provider canonicality is rechecked before reassessment. Changed finalized evidence is invalidated append-only, affected schedules are due again, and invalidated technical resolutions reopen. Recollection never rewrites original evidence. This trusts the configured provider rather than independently verifying consensus.

## Operations and retention

`GET /health/ready` checks API database/migration and Redis access, not fleet liveness. Authenticated monitoring endpoints expose persisted last success/failure, job state, heartbeat and next run. Alert on stale heartbeats, overdue schedules and repeated failures. Notification events are durable API-readable events; external email/webhook delivery is not implemented.

Each process periodically prunes up to 1,000 terminal jobs older than 90 days and heartbeat rows older than seven days. Policy, evidence, assessment, finding, invalidation, migration and audit history is append-only and never silently deleted. Capacity-plan this retained evidence and establish a reviewed archival/backup policy; unlimited-history storage is not bounded by job retention.

Back up before applying `010_cpm.sql`; it is additive and preserves assessment schema 0.1. It reuses existing evidence/findings/audit tables. Deploy the matching API and worker together after migrating. To roll back application binaries, stop workers and leave the additive tables intact; do not delete customer history. Validate backup restoration and replay behavior in staging before rollout.

The worker enumerates tenants from operator API-key/OIDC membership configuration. Tenant onboarding/removal requires configuration rollout. A paused schedule cancels outstanding jobs. Retiring a policy stops new claims without resolving its findings; already running work remains pinned to its original immutable version.
