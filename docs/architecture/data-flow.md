# Evidence flow

1. Validate credential, server-owned membership and role; apply Redis quota.
2. Validate the request and optional idempotency key. Replays return the previously committed assessment.
3. Verify configured chain, collect a finalized block and read state by canonical block hash.
4. If requested, verify a supported transaction hash/signature/sender and receipt/block context; or read the explicit token ABI adapter.
5. Derive CBOM, supported QBOM and versioned posture findings; retain unknowns and limitations.
6. Atomically append evidence, assessment, canonical asset registration, graph, audit and idempotency metadata under tenant RLS.
7. Verify hashes and runtime schemas on retrieval; present saved records in Next.js and export JSON reports.

No signing or financial write occurs. Provider reports are not independently verified consensus proofs. Drift comparison is on demand; continuous alerts are planned. Go retries partial blocks using the same assessment keys, advancing its local checkpoint only after all submissions succeed.
