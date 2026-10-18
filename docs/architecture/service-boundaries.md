# Service boundaries

The NestJS modular monolith owns tenant authentication, collection APIs, inventory, evidence, policy management, findings, migration assessment and reporting. PostgreSQL is the authoritative store; Redis provides shared request quotas. Next.js supplies the console and same-origin authenticated proxy.

`workers/assessment-worker/main.ts` hosts the independently supervised CPM polling loop. `services/job-worker/cpm-worker.ts` orchestrates bounded collection. Inventory repositories own tenant-scoped transactions, jobs and policies. Core policy, posture, drift, remediation and migration engines are deterministic source boundaries, not new network services. The separate Go indexer remains optional.

Notifications are stored durable events with an authenticated read API; there is no external delivery service. Dedicated administrative/developer applications, object storage and full infrastructure deployment remain future boundaries. Directory existence is not evidence of an operational capability. See the implementation report and worker runbook for limits and deployment gates.
