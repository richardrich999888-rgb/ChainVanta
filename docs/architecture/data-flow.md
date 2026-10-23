# Evidence flow

1. Authenticate a server-owned tenant principal, check role and apply the shared Redis request quota.
2. Validate strict request schemas and size limits. Register assets through the existing idempotent assessment API before scheduling them.
3. Pin RPC sockets to validated DNS answers for approved URLs. Check chain/finalized context, perform hash-pinned read-only requests and optionally verify a supplied transaction or token accessor.
4. Preserve the existing CBOM, QBOM, evidence, assessment, graph and asset models. CPM creates a deterministic snapshot referencing the original assessment and immutable policy version/hash.
5. Compare compatible snapshots; missing data is incomplete coverage. Persist drift, evidence references, recommendations and findings without overwriting originals. Policy retirement or omission cannot technically resolve findings.
6. For scheduled work, claim a durable PostgreSQL lease under a tenant lock, enforce concurrency and RPC budgets, and commit evidence/CPM/job success in one transaction. Timeout, cancellation or lease expiry fences the old worker. Bounded retry and collection-failure events never represent a passing assessment.
7. Recheck prior finalized state at the configured provider before collection. Append invalidations, preserve history, reopen invalidated verification and schedule recollection when canonical hashes change.
8. Verify hashes on retrieval and expose authenticated, paginated API/SDK views. The console distinguishes recorded classification from current stale/failure status.
9. Migration assessment compares an explicit definition to a later finalized assessment of the same asset. Only supported tested properties receive VERIFIED_FOR_DEFINED_SCOPE; absent signature data cannot verify PQC migration.

No wallet secrets, transaction signing or financial writes are supported. Provider evidence is not independent consensus verification. Durable notification events are available to operators; delivery to external messaging systems remains unimplemented. The separate Go indexer keeps its existing single-writer checkpoint behavior.
