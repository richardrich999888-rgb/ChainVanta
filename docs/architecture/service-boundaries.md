# Service boundaries

The first release uses one NestJS API process. Inventory, evidence, assessment, identity, reporting, finding lifecycle and tenant authorization are modules, not independent microservices. Redis handles quotas; PostgreSQL is authoritative for evidence and metadata. Next.js is the console and same-origin proxy. The optional Go worker invokes the same API and has a single local checkpoint file.

Unimplemented service directories are future boundaries only. Notification, scheduling, distributed orchestration, separate admin/developer applications and external object storage are not running services. See the root README and implementation report for exact status.
