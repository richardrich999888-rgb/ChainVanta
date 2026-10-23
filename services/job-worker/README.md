# CPM job execution

`cpm-worker.ts` implements durable scheduled assessment execution through the shared inventory repository and core engines. It uses bounded RPC, reorganization invalidation, transactional fenced completion and explicit failure recording. Start the independent entry point with `pnpm worker:cpm` or the compiled `pnpm start:worker`.

See the [assessment-worker runbook](../../workers/assessment-worker/README.md) for leases, limits, configuration, shutdown and deployment requirements. External notification delivery is not implemented; durable events are exposed through the authenticated CPM API.
