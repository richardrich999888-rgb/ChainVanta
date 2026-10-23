# Web3 CPM implementation and assurance report

## Revision and scope

Implementation and local verification: 17–18 October 2026.

- Working branch: `feature/web3-cpm-engine`.
- Verified foundation/base: `7fe7d3fed3c9f9e63cbf590e563dd5e766f4ad4e`.
- Implementation commit: `ce045d9148f037202d6247107f06f49d4cfb0353` (all source changes and runbooks). This report is recorded in a following documentation-only commit.
- Isolated checkout: `/Users/richardrich/.codex/worktrees/web3-cpm-engine/chainvanta`.
- The original `codex/chainvanta-graph` checkout and its uncommitted graph/Agility work were preserved. Those changes are outside this branch. No push, merge or customer-data migration was performed.

The base already implemented CBOM/QBOM, finalized hash-pinned EVM account collection, verified supplied type 0/1/2 transaction signatures, the explicit ownable ERC20 accessor adapter, evidence/assessment persistence, graph relationships, tenant RLS, authentication, Redis quotas and the console. CPM previously consisted of baseline findings; durable scheduling, versioned policy storage, snapshots, drift persistence and technical verification were absent. Administrative finding labels could previously claim resolution.

This implementation completes the CPM workflow for the declared evidence scope. It is locally validated software, not an approval of an unspecified production environment or a certification claim.

## Implemented functionality

| Workstream              | Delivered behavior                                                                                                                                                                                          | Evidence and bounds                                                                                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A: Posture              | Deterministic immutable snapshots consume existing assessments/CBOM and reference original evidence, policy hash and evaluator version.                                                                     | Verified signature exposure is separate from unknown authorization/custody. Address-only evidence never implies safety or exposed public keys.                                 |
| B: Policies             | Ten fixed rule kinds; immutable versions, publish/retire, tenant/asset assignment and operator importance. Data-only configuration, admin writes, retained historical versions.                             | Unknown domains remain unknown. Disabling a rule does not suppress factual exposure or resolve outstanding findings.                                                           |
| C: Monitoring           | Durable schedules/jobs, concurrent claim protection, fencing, cancellation, restart recovery, bounded attempts/backoff/timeouts, tenant concurrency and tenant/chain RPC budgets.                           | Scheduled evidence, derived CPM and job success commit atomically. Failures preserve history and project unknown current posture.                                              |
| D: Drift                | Algorithm, signature format, owner accessor, dependency, quantum exposure, evidence coverage and policy comparisons; deterministic event IDs and evidence links to both assessments.                        | Disappearing observations are incomplete evidence, not verified removals. Policy changes are distinguished from observed changes.                                              |
| E: Quantum intelligence | Explainable observed secp256k1 dependency/public-key recoverability from verified supplied transactions; unknown coverage and migration constraints.                                                        | No present-exploitability, private-key compromise, quantum-arrival date or independent consensus claim.                                                                        |
| F: Remediation          | Evidence-linked recommendations with dependency, rationale, next action, constraints and verification requirements. Authorized importance can raise a verified dependency from MEDIUM to HIGH.              | Unverified authority, custody and blast radius remain NEEDS_EVIDENCE. CRITICAL/LOW are supported classes but not fabricated from absent data.                                  |
| G: Findings             | Append-only open/acknowledged/in-remediation/pending-verification/resolved lifecycle, timed exceptions, administrative closure and reopening. Legacy supported finding writes share the same state machine. | Technical resolution requires later finalized evidence satisfying the same rule semantics. Expired exceptions become actionable; invalidated verification reopens findings.    |
| H: Migration            | Idempotent readiness records and later reassessment against explicit owner-accessor/bytecode/signature observation criteria. Immutable results with invalidation projection.                                | Unchanged baseline properties do not demonstrate improvement. PQC execution/compatibility is unsupported; scoped verification does not prove complete authorization or safety. |

The additive migration `010_cpm.sql` creates the requested logical entities, with tenant foreign keys, forced RLS, append-only triggers and indexed chronology/queue access. It extends existing findings rather than creating a competing findings table. Stored assessment schema 0.1 remains readable. No existing evidence is deleted. Runtime startup rejects database superuser/BYPASSRLS identities.

The API exposes all requested CPM routes plus policy assignments, job cancellation, notification reads, finding transitions and migration verification. Authentication, roles, strict validation, 8 KiB body limits, pagination (default 25, maximum 100), Redis quotas and structured errors apply. OpenAPI and the TypeScript SDK include the corresponding contracts/methods. Lease tokens are excluded from job responses.

The existing console now displays posture and unknowns, assessment time, monitoring schedule/job/heartbeat health, failure status, findings/administrative transitions, recommendations, drift evidence, snapshot history and migration assessment/verification. Viewer controls are read-only; administrator transitions are enforced server-side. Mobile overflow and desktop/mobile screenshots were checked. Counters explicitly describe the displayed bounded page rather than pretending to be global totals.

The production API and worker use a read-only RPC transport with configured URL allowlisting, validated and socket-pinned DNS answers, private/special-address rejection, HTTPS verification, redirect rejection, aborts and bounded bodies. Loopback fixtures require explicit non-production demonstration configuration. Existing crypto primitives remain delegated to viem and Node; no custom signature algorithm was added.

## Partially supported and unsupported functionality

- Continuous collection reobserves registered addresses and explicitly supplied transactions/adapters. It does not automatically discover every transaction, authorization scheme or on-chain dependency.
- `owner()` is an observed accessor, not proof of actual mint/burn/upgrade rights, a complete administrator set, concentration, TVL or causal blast radius. Such remediation inputs remain unknown.
- Native EVM PQC migration, blockchain writes, wallet-key handling, bridges, validators, custody/MPC/HSM, ZK and cross-chain execution are unsupported. The new module boundaries do not imply those adapters exist.
- Migration verification is limited to the stated collected property. It does not establish full protocol/wallet/custody compatibility. General posture migration readiness stays unknown where those inputs are absent.
- Notification events are persisted and exposed by API. External email, webhook and paging delivery is not implemented or configured.
- The separate Go block indexer remains its original single-writer local-checkpoint prototype. Its tests still pass; the PostgreSQL CPM scheduler does not transform it into distributed block ingestion.
- On-demand base assessment persistence and CPM evaluation are separate idempotent transactions; retry recovers a saved base assessment after a CPM failure. Scheduled execution commits both atomically. On-demand concurrency remains process-local; Redis quotas are shared. Worker RPC budgets are per tenant/chain across replicas, not a provider-wide subscription quota.
- Exceptions retain the foundation contract requiring a future expiry; indefinite exceptions are not supported.
- UI lists/history are bounded; the API supports pagination. Tenant provisioning and worker tenant enumeration use operator configuration. Browser OIDC, self-service onboarding and credential rotation workflows remain outside this scope.
- Evidence and audit history are intentionally append-only. Terminal jobs older than 90 days and heartbeats older than seven days are pruned in bounded batches; evidence archival requires an operator retention/backup plan.

## Assurance results

Final verification uses deterministic providers and disposable database schemas. It does not assert live-network validation.

| Check                                  | Executed result                                                                                                                               |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm check:structure`                 | Passed: 303 required directories, 41 required files.                                                                                          |
| `pnpm api:generate`                    | Passed: generated OpenAPI and TypeScript contracts.                                                                                           |
| `pnpm typecheck`                       | Passed: backend/shared code and Next route/client types.                                                                                      |
| `pnpm lint`                            | Passed.                                                                                                                                       |
| `pnpm format:check`                    | Passed.                                                                                                                                       |
| `pnpm test`                            | Passed: 65 tests across 15 files, PGlite PostgreSQL semantics.                                                                                |
| `pnpm test:native`                     | Passed: the same 65 tests on native PostgreSQL, including independent-client lease races, RLS, rollback, retries and reorganization handling. |
| `pnpm build`                           | Passed: compiled API/worker and optimized Next.js build.                                                                                      |
| `pnpm test:e2e:native`                 | Passed: all four browser workflows on native PostgreSQL.                                                                                      |
| `pnpm audit --prod --audit-level high` | Passed: no known vulnerabilities reported at execution time.                                                                                  |
| `pnpm sbom`                            | Passed: `.local/sbom.cdx.json`, 195 production Node components. Excludes Go, OS packages, licenses and artifact digests.                      |
| Go `test`, `vet`, `build`              | Passed in existing `golang:1.27.2-alpine` with a read-only source mount. No Go source was changed.                                            |
| `pnpm demo:cpm`                        | Passed: complete fixture workflow with assertions and explicit demonstration output.                                                          |

The ten requested scenarios are exercised: verified ECDSA exposure, unknown authorization, owner-accessor drift, incomplete provider data, retained policy versions, competing workers, exception expiry, tenant isolation, finalized-state invalidation and migration verification. Additional coverage includes transport private/mixed-DNS rejection, redirect/write/body/abort boundaries, cancelled/expired-token rejection, atomic rollback, retry exhaustion, schedule idempotence, disabled-policy finding retention, legacy endpoint consistency and invalidated verification reopening.

Earlier development runs exposed a shared-browser-fixture tenant quota collision, an inaccessible exact form label, and a test-helper TypeScript annotation error. These were corrected by isolating the browser tenant, supplying explicit labels and fixing the helper type; no rate limit, assertion or existing test was weakened. Earlier failures are not counted as passing runs. An explicit formatter invocation on `.env.example` reported that no parser exists for that format; the repository's supported `format:check` remains the release gate.

Browser artifacts are local/ignored: `test-results/cpm-desktop.png`, `test-results/cpm-mobile.png`. SBOM and build output are generated artifacts rather than committed evidence of a deployed service. Production dependencies and lockfile were not changed.

## Deployment gates and security limitations

1. Provision a target staging/production environment with private authenticated/TLS PostgreSQL and Redis, restricted runtime identity, separate migration identity, encrypted storage, managed secrets/rotation, HTTPS and exact `WEB_ORIGIN`. The task did not alter the existing application database or deploy infrastructure.
2. Validate an approved provider's actual finalized/EIP-1898 behavior, chains and quotas. The collector trusts provider-reported state and does not independently verify consensus. DNS/socket controls do not make an upstream provider honest; apply network egress policy too.
3. Configure and supervise API, console and CPM worker replicas, identical concurrency/budget settings, graceful termination and tenant membership rollout. Monitor overdue schedules, stale heartbeats and collection failures; wire external alert delivery as required.
4. Exercise sustained load, recovery/restart, backup restoration and evidence archival at the intended tenant/schedule scale. The local concurrency/failure tests are not a production load or disaster-recovery certification.
5. Complete deployment-specific authorization/security review and release approval. Hashes and append-only runtime grants are not protection against a database owner replacing evidence and hashes. External audit anchoring/WORM is not implemented.

No customer signing keys or seed phrases are collected. No blockchain transactions are signed or sent. No certification, FIPS, formal verification, quantum safety or unconditional production-readiness assertion is made.

## Reproduce

From this checkout, use the pinned pnpm lockfile and Node 22/24 LTS:

```sh
pnpm install --frozen-lockfile
pnpm demo:cpm
pnpm check:structure
pnpm api:generate
pnpm typecheck
pnpm lint
pnpm format:check
pnpm test
pnpm test:native
pnpm build
pnpm test:e2e:native
pnpm audit --prod --audit-level high
pnpm sbom
```

`demo:cpm` defaults to a disposable PGlite instance and makes no external RPC calls. If `TEST_DATABASE_URL` is explicitly set, it uses an isolated schema in that disposable database. Never point test administration at customer data. Native scripts derive the dedicated `chainvanta_foundation_test` database from the local migration connection and create/remove only isolated test schemas. They do not migrate the application database. Browser tests start their own fixture API and console on loopback ports 4400 and 3400.

The demo registers an asset, builds CBOM/QBOM/CPM, schedules a durable assessment, supplies a verified transaction, detects algorithm/quantum/policy drift, generates remediation and verifies only the missing-transaction-evidence finding. It asserts that the quantum finding remains open and the unsupported native PQC migration is TECHNICALLY_BLOCKED. Fixture UUIDs/timestamps vary; classifications and assertions are deterministic.

For ongoing local UI use, review `.env`, apply migrations with the separate migration identity, run `pnpm dev` and `pnpm worker:cpm`, register an asset and schedule it in CPM. To use the local RPC fixture, run `pnpm dev:fixture` and explicitly configure its chain with `demonstration:true`. See the worker runbook for compiled deployment commands and limits.

Design references: [PostgreSQL row locking](https://www.postgresql.org/docs/current/sql-select.html), [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898), [NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography), and Node's [HTTPS](https://nodejs.org/api/https.html), [DNS](https://nodejs.org/api/dns.html), and [IP block-list](https://nodejs.org/api/net.html#class-netblocklist) APIs. These references inform implementation; they are not certification evidence.

## Changed files

The implementation commit changes 59 files; this report adds the sixtieth. Generated contract files account for much of the diff. Run `git diff --name-status 7fe7d3fed3c9f9e63cbf590e563dd5e766f4ad4e HEAD` to reproduce the complete branch manifest, including this report.

```text
M	.env.example
M	README.md
A	apps/web-console/src/app/api/cpm/[...path]/route.ts
M	apps/web-console/src/components/console-page.tsx
M	apps/web-console/src/components/console.tsx
A	apps/web-console/src/components/cpm-console.tsx
M	apps/web-console/src/components/intelligence.tsx
M	apps/web-console/src/styles/globals.css
M	connectors/blockchains/ethereum/src/index.ts
A	connectors/blockchains/ethereum/src/transport.ts
A	core/cpm-engine/drift-detection/index.ts
A	core/cpm-engine/posture-evaluation/snapshot.ts
A	core/migration-engine/assess.ts
A	core/policy-engine/evaluators/index.ts
A	core/policy-engine/exceptions/index.ts
A	core/policy-engine/policies/web3.ts
A	core/policy-engine/rule-versioning/index.ts
A	core/risk-engine/remediation.ts
A	database/migrations/010_cpm.sql
A	database/policies/cpm-runtime.sql
M	docs/architecture/data-flow.md
M	docs/architecture/security-architecture.md
M	docs/architecture/service-boundaries.md
M	docs/architecture/system-overview.md
M	modules/01-wallet-intelligence/src/assessment/index.ts
M	package.json
M	packages/api-contracts/generated.ts
M	packages/api-contracts/openapi.yaml
M	packages/config/src/index.ts
M	packages/config/tsconfig.json
A	packages/domain-models/src/cpm.ts
M	packages/test-fixtures/src/database.ts
M	scripts/database/migrate.ts
A	scripts/development/cpm-contracts.ts
A	scripts/development/cpm-demo.ts
M	scripts/development/generate-api.ts
M	sdks/typescript/src/index.ts
M	services/api-gateway/src/app.ts
A	services/api-gateway/src/cpm-controller.ts
M	services/api-gateway/src/main.ts
A	services/api-gateway/src/tenant-guard.ts
M	services/assessment-service/src/index.ts
A	services/inventory-service/src/cpm-policy-store.ts
A	services/inventory-service/src/cpm-repository.ts
A	services/inventory-service/src/monitoring-store.ts
M	services/inventory-service/src/repository.ts
M	services/job-worker/README.md
A	services/job-worker/cpm-worker.ts
M	tests/end-to-end/console.spec.ts
A	tests/end-to-end/cpm.spec.ts
A	tests/integration/cpm-api.test.ts
A	tests/integration/cpm-monitoring.test.ts
A	tests/integration/cpm-workflow.test.ts
M	tests/integration/server.ts
A	tests/unit/cpm-drift.test.ts
A	tests/unit/cpm.test.ts
A	tests/unit/rpc-transport.test.ts
M	workers/assessment-worker/README.md
A	workers/assessment-worker/main.ts
A	docs/development/cpm-implementation-report.md
```
