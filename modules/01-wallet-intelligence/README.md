# ChainVanta Discover

Status: **Partially implemented**.

Finalized EVM account observations, explicit transaction signature verification (types 0/1/2), CBOM, versioned QBOM/CPM findings, evidence references and relational observation graph. The API validates source chain, block context, transaction hash, recovered sender and receipt context. Assessments persist atomically with tenant RLS and idempotency.

No exhaustive wallet discovery, custody inference, account-abstraction semantics, complete transaction history or independent consensus validation. A verified historical transaction does not prove the account's current authorization mechanism. Unknowns remain unknown.

Tests: `tests/unit/{assessment,rpc,intelligence}.test.ts`, `tests/integration/pipeline.test.ts`.
