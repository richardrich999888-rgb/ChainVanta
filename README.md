# ChainVanta

**Cryptographic Intelligence for Web3 · Developed by SYNTRIASS**

Evidence-driven Web3 CPM with durable monitoring, immutable policy history and scoped remediation verification. Deployment approval requires the operational gates in the [CPM assurance report](docs/development/cpm-implementation-report.md).

```text
Read-only EVM RPC → hash-pinned finalized account state / supplied transaction / explicit token adapter
                 → CBOM → QBOM → CPM policies, durable monitoring, drift and verification
                 → tenant-isolated PostgreSQL evidence, assets, audit and graph
                 → NestJS API + Redis quotas → Next.js console / generated client / JSON reports
```

## Implemented foundation

- NestJS modular monolith with request validation, viewer/analyst/admin authorization, opaque API keys and optional OIDC JWT verification. OIDC subjects map to operator-provisioned memberships; arbitrary tenant/role claims are ignored.
- PostgreSQL migrations, separate runtime role, forced row-level security, atomic evidence persistence, canonical asset deduplication, durable idempotency keys, append-only finding events and audit records.
- Read-only EVM snapshots pinned by **block hash** using EIP-1898, chain validation, response bounds, timeouts and bounded retries. Providers must support finalized blocks and EIP-1898.
- Optional verification of supplied finalized legacy, EIP-2930 and EIP-1559 transactions using viem serialization, transaction hashing and sender recovery. Receipts and block context are checked. Unsupported formats fail explicitly.
- Evidence-backed CBOM, versioned QBOM rules and posture findings. An observed transaction signature does **not** establish the account's complete authorization policy or private-key custody. Unknowns remain unknown.
- Explicit `ownable-erc20` adapter reads `owner()`, `totalSupply()` and `decimals()`. This is a partial Stablecoin Assurance capability; it does not discover stablecoin identity or prove mint/burn rights, reserves, proxy semantics or regulatory compliance.
- Relational graph edges with bounded traversal; historical snapshot comparison; an immutable findings lifecycle, timed exceptions and technical resolution only after later supporting evidence.
- Redis-backed request quotas in the running API. Redis failure denies protected API access rather than bypassing quotas.
- Next.js dark console with inventory, CBOM, QBOM, CPM, interactive relationship inspection, evidence and JSON reports. Counts describe recent observations, not invented risk scores. Demonstration records are visibly marked.
- Go finalized-block worker with chain checks, bounded RPC, replay-safe API submissions and atomic local checkpoints. Reorganizations stop ingestion for review. This is a **single-worker prototype**, with no shared lease, PostgreSQL cursor or automatic rollback of finalized history.
- PostgreSQL scheduled CPM workers with fenced leases, bounded retries, failure reporting, reorganization invalidation and tenant/chain RPC budgets. Policies, drift, remediation, monitoring and scoped migration verification are exposed through authenticated API/SDK and console views.
- Runtime Zod contracts, generated OpenAPI TypeScript types, deterministic tests, CI configuration, Node dependency SBOM exporter and dependency auditing.

Wallet Intelligence and Stablecoin Assurance are **partially implemented**. The other ten modules are **planned** and have contracts, threat boundaries and acceptance test specifications; no operational adapters are registered for them.

## Repository structure

The repository follows the supplied [ChainVanta tree](docs/development/repository-structure.txt).
Run `pnpm check:structure` to verify all 303 required directories, 41 required files and the
declared directory boundaries. CI runs this check. Empty reserved directories contain `.gitkeep`;
their presence does not mean their capabilities are implemented.

All ten console routes have page entry points: `/dashboard`, `/inventory`, `/cbom`, `/qbom`,
`/posture`, `/trust-graph`, `/findings`, `/migrations`, `/reports` and `/settings`.
Migration execution remains planned; settings includes the module availability catalog.
See [structure conventions](docs/development/repository-layout.md) for code locations and the
supporting framework files retained alongside the supplied tree.

## Start locally

Requirements: Node 22 or 24 LTS recommended (this session also tested Node 25.2.1), pnpm 9.15.4, Docker with a running daemon. Go 1.27.2 is required only for the optional worker; Rust and Python are intentionally deferred.

```sh
pnpm install --frozen-lockfile
pnpm bootstrap                 # first setup only; preserves existing configuration
# Review CHAINS in .env and choose an approved read-only RPC provider.
docker compose up -d --wait
pnpm db:migrate
pnpm db:seed --demo             # optional, visibly marked local demonstration data
pnpm dev
# In a separate terminal after migrating: pnpm worker:cpm
```

Open **http://127.0.0.1:3000**. Use the generated tenant API key in `.env` → `TENANT_API_KEYS`. Do not paste wallet secrets. The API binds to **127.0.0.1:4000**. `/health/live` checks the process and `/health/ready` checks PostgreSQL migrations and Redis.

An existing `.env` is never overwritten. `REDIS_URL` defaults to `redis://127.0.0.1:6379`. Existing API keys without a role retain **analyst** privileges. To manage finding status, provision a separate key with `"role":"admin"`; use `"role":"viewer"` for read-only users. Re-run migrations when provisioning additional tenants.

`pnpm bootstrap` currently defaults CHAINS to a public Ethereum RPC. Change it before scanning; the selected provider receives the public account address. No RPC call is made merely by viewing a stored assessment. `pnpm dev:fixture` starts a clearly designated local deterministic RPC provider; configure its chain with `"demonstration":true`. The demo seed uses that fixture transport in-process and requires no live RPC.

`pnpm build` creates production builds. Start with `pnpm start:api`, `pnpm start:worker` and `pnpm --filter @chainvanta/web-console start`. Production session cookies require HTTPS and an exact `WEB_ORIGIN`. Local Compose is not a hardened production deployment.

For a complete deterministic workflow using a disposable database and no external RPC, run `pnpm demo:cpm`. See the [CPM worker runbook](workers/assessment-worker/README.md) for scheduling and deployment.

## Authentication and API

Optional API-only OIDC configuration:

```dotenv
OIDC_CONFIG='{"issuer":"https://identity.example","audience":"chainvanta","jwksUrl":"https://identity.example/jwks","memberships":[{"subject":"approved-subject","tenantId":"YOUR-TENANT-UUID","role":"viewer"}]}'
```

JWT signatures, issuer, audience, expiry and required subject/issued-at claims are verified with `jose`, using RS256 or ES256. One tenant membership per subject is supported. Interactive browser OIDC login, SCIM and credential rotation remain planned; the console currently uses an HttpOnly, SameSite API-key session cookie.

- `POST /v1/assessments`: `{address, chainId, transactionHash?, adapter?}`. Optional `Idempotency-Key` (8–128 alphanumeric, underscore or hyphen characters) replays the exact stored result. Reusing a key with different input returns 409. Tenant identity is never accepted in the body.
- `GET /v1/assessments`, `/v1/assessments/:id`, `/v1/reports`.
- `GET /v1/history?chainId=1&address=...` compares the latest two snapshots.
- `GET /v1/graph?source=eip155:1:0x...` traverses supported evidence edges, maximum three hops.
- `GET /v1/findings/events`; `PATCH /v1/assessments/:id/findings/:ruleId` (admin) accepts status, reason and an expiry for exceptions.
- `/v1/cpm/*`: versioned policy registry, assignments, posture/history, schedules/jobs, drift, remediation, notification events, finding transitions and migration assessment/verification. Lists use `limit` (1–100) and `offset`; management is administrator-only. See generated OpenAPI for precise request schemas.
- `GET /v1/audit` (admin). Reports are limited to the latest 50 assessments; history to 100; event history to 500. Reports count observations and do not apply exception statuses as a risk score.

[OpenAPI](packages/api-contracts/openapi.yaml) · [Generated types](packages/api-contracts/generated.ts) · [TypeScript client](sdks/typescript/src/index.ts)

## Verify

```sh
pnpm check:structure
pnpm api:generate
pnpm typecheck
pnpm lint
pnpm format:check
pnpm test
pnpm build
pnpm exec playwright install chromium
pnpm test:e2e
pnpm audit --prod --audit-level high
pnpm sbom
```

Default database tests run real PostgreSQL semantics through PGlite. For native PostgreSQL, set `TEST_DATABASE_URL` to a disposable database and run `pnpm test` or `pnpm test:e2e`. Each run creates an isolated schema. CI supplies PostgreSQL 17. Locally, after creating the dedicated `chainvanta_foundation_test` database, `pnpm test:native` and `pnpm test:e2e:native` derive its URL from `MIGRATION_DATABASE_URL` without printing credentials.

For Go, run `pnpm test:go` with Go installed. See [worker instructions](workers/blockchain-indexer/README.md) for the tested container alternative.

`pnpm sbom` emits `.local/sbom.cdx.json` for installed **Node production dependencies only**; it excludes Go, container OS packages, licenses and artifact digests. It is not a full release attestation.

## Security and remaining work

No customer signing secrets or write-capable blockchain methods are supported. Evidence hashes detect content changes; they do not authenticate an RPC provider or provide independent tamper resistance. A malicious provider can still misreport canonical/finalized chain state.

Remaining deployment work includes managed secrets and rotation, tenant provisioning, infrastructure TLS/encryption, backups and recovery exercises, load validation, external audit anchoring, telemetry/alert delivery and reviewed releases. Browser OIDC and verified bridge/custody/authority adapters remain unsupported. The separate Go indexer still uses a local checkpoint; CPM scheduling uses PostgreSQL leases. RPC sockets validate and pin DNS answers; network egress controls remain defense in depth. Local Redis has no authentication and both data stores are loopback-only; deploy private networks, TLS, access controls and encrypted volumes before production use.

[CPM implementation and assurance report](docs/development/cpm-implementation-report.md) · [Foundation implementation and validation report](docs/development/implementation-report.md) · [Security architecture](docs/architecture/security-architecture.md) · [Release strategy](security/supply-chain/README.md)

The CPM work is isolated on `feature/web3-cpm-engine`, based on the verified platform foundation; it has not been pushed or merged. See [CONTRIBUTING](CONTRIBUTING.md) for the branch workflow. Repository publication does not indicate production deployment or certification. See [LICENSE](LICENSE).
