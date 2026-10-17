# Architecture

One NestJS API process hosts identity, inventory, assessment, evidence, reporting and finding-lifecycle domains. Next.js is the console and same-origin backend-for-frontend. Shared TypeScript modules are compiled under the root package; they are source boundaries, not separate network services. Go indexing is optional and invokes the same assessment API.

PostgreSQL is authoritative for immutable evidence, assessments, assets, request idempotency, graph edges, finding events and audit events. Assessments contain versioned JSON documents validated by Zod. Composite tenant keys, foreign keys and forced RLS constrain references. Redis is a disposable shared request-quota store; loss denies access until recovery, without losing persisted evidence.

The EVM connector obtains finalized context and hash-pinned reads. Optional transaction verification yields observed ECDSA-secp256k1 dependency evidence. The explicit ownable ERC20 adapter yields raw/decoded accessor observations. CBOM inventories known and unknown dependencies; QBOM evaluates verified transaction signatures; CPM emits versioned, reproducible findings. Risk is expressed as explained rule severity, with no fabricated composite score.

UI views consume actual API documents. JSON reporting covers the latest 50 assessments. Historical comparison is on demand. Graph traversal stays in PostgreSQL. Ten planned modules have schema/interface contracts and activation criteria; none are registered as operational functionality.

Deferred infrastructure: S3 evidence storage, Terraform deployments, OpenTelemetry exporters, Prometheus/Grafana stack, managed scheduling/queues, dedicated administrative/developer applications and Rust/Python runtimes. These are intentionally not presented as working services.
