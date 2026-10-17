import { readFile, readdir } from 'node:fs/promises';
import { Pool, escapeLiteral } from 'pg';
import { readConfig } from '../../packages/config/src/index.js';
const config = readConfig();
const pool = new Pool({
  connectionString: process.env.MIGRATION_DATABASE_URL ?? config.databaseUrl,
});
try {
  // Local bootstrap only. Production operators may provision this role independently.
  if (process.env.POSTGRES_APP_PASSWORD) {
    const existing = await pool.query("SELECT 1 FROM pg_roles WHERE rolname = 'chainvanta_app'");
    if (!existing.rowCount) {
      await pool.query(
        `CREATE ROLE chainvanta_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD ${escapeLiteral(process.env.POSTGRES_APP_PASSWORD)}`,
      );
    }
  }
  const directory = new URL('../../database/migrations/', import.meta.url);
  for (const file of (await readdir(directory)).filter((f) => f.endsWith('.sql')).sort())
    await pool.query(await readFile(new URL(file, directory), 'utf8'));
  for (const { tenantId } of [...config.tenantKeys, ...(config.oidc?.memberships ?? [])])
    await pool.query('INSERT INTO tenants(id) VALUES ($1) ON CONFLICT DO NOTHING', [tenantId]);
  await pool.query(
    "DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'chainvanta_app') THEN GRANT SELECT, INSERT ON evidence, assessments, assets, scan_requests, graph_edges, finding_events, audit_events TO chainvanta_app; GRANT SELECT ON schema_migrations TO chainvanta_app; END IF; END $$",
  );
  console.log('Applied migrations 001–002 and provisioned configured tenants.');
} finally {
  await pool.end();
}
