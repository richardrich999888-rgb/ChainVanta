import { createRpcTransport } from '../../connectors/blockchains/ethereum/src/transport.js';
import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { readConfig } from '../../packages/config/src/index.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { CpmRepository } from '../../services/inventory-service/src/cpm-repository.js';
import { CpmWorker } from '../../services/job-worker/cpm-worker.js';
async function main() {
  const config = readConfig(),
    pool = new Pool({
      connectionString: config.databaseUrl,
      max: 10,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
    });
  pool.on('error', () => console.error(JSON.stringify({ event: 'worker_database_error' })));
  const base = new PostgresRepository(pool);
  await base.ping();
  const worker = new CpmWorker(
    new CpmRepository(base),
    config.chains,
    `cpm-${randomUUID()}`,
    createRpcTransport(config.chains),
    60000,
    Number(process.env.CPM_TENANT_CONCURRENCY ?? 2),
    Number(process.env.CPM_RPC_PER_MINUTE ?? 120),
  );
  const tenants = [
    ...new Set([...config.tenantKeys, ...(config.oidc?.memberships ?? [])].map((k) => k.tenantId)),
  ];
  let stopped = false,
    ticks = 0;
  process.on('SIGTERM', () => {
    stopped = true;
  });
  process.on('SIGINT', () => {
    stopped = true;
  });
  try {
    while (!stopped) {
      for (const tenant of tenants) {
        if (stopped) break;
        try {
          await worker.tick(tenant);
          if (ticks % 720 === 0) await worker.jobs.prune(tenant);
        } catch {
          console.error(JSON.stringify({ event: 'worker_tick_failed', tenantId: tenant }));
        }
      }
      ticks++;
      if (!stopped) await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  } finally {
    await pool.end();
  }
}
main().catch(() => {
  console.error('CPM worker startup failed. Verify configuration and migrations.');
  process.exitCode = 1;
});
