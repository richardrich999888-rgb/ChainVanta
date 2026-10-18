import { randomUUID } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { Pool, type PoolClient } from 'pg';
import { readFile, readdir } from 'node:fs/promises';
import { TENANT_A, TENANT_B } from './fixtures.js';

// PGlite executes real PostgreSQL SQL in WASM. It does not exercise TCP, pool behavior or deployment.
// TEST_DATABASE_URL selects a disposable native PostgreSQL database instead (CI uses this).
export async function testDatabase() {
  const schema = `test_${randomUUID().replaceAll('-', '')}`;
  const embedded = process.env.TEST_DATABASE_URL ? null : new PGlite();
  const native = process.env.TEST_DATABASE_URL
    ? new Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema},public`,
      })
    : null;
  if (native) await native.query(`CREATE SCHEMA ${schema}`);
  const admin = async (sql: string, params?: unknown[]) => {
    if (native) return native.query(sql, params);
    if (!embedded) throw new Error('Database missing');
    if (params) return embedded.query(sql, params);
    const results = await embedded.exec(sql);
    return results[results.length - 1]!;
  };
  const directory = new URL('../../../database/migrations/', import.meta.url);
  for (const file of (await readdir(directory)).filter((f) => f.endsWith('.sql')).sort())
    await admin(await readFile(new URL(file, directory), 'utf8'));
  await admin('INSERT INTO tenants (id) VALUES ($1), ($2) ON CONFLICT DO NOTHING', [
    TENANT_A,
    TENANT_B,
  ]);
  await admin(
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'chainvanta_test_app') THEN CREATE ROLE chainvanta_test_app NOSUPERUSER NOBYPASSRLS; END IF; END $$; GRANT USAGE ON SCHEMA public TO chainvanta_test_app; GRANT SELECT, INSERT ON evidence, assessments, assets, scan_requests, graph_edges, finding_events, audit_events TO chainvanta_test_app; GRANT SELECT ON schema_migrations TO chainvanta_test_app;",
  );
  if (native) await admin(`GRANT USAGE ON SCHEMA ${schema} TO chainvanta_test_app`);
  await admin(
    (
      await readFile(new URL('../../../database/policies/cpm-runtime.sql', import.meta.url), 'utf8')
    ).replaceAll('chainvanta_runtime', 'chainvanta_test_app'),
  );
  // Serialize embedded connections; native tests use real PoolClients and independent transactions.
  let tail = Promise.resolve();
  const connect = async () => {
    const previous = tail;
    let unlock!: () => void;
    tail = new Promise<void>((resolve) => {
      unlock = resolve;
    });
    if (embedded) await previous;
    const client = native ? await native.connect() : null;
    const query = async (sql: string, values?: unknown[]) => {
      if (client) return client.query(sql, values);
      const result = await embedded!.query(sql, values);
      return { rows: result.rows, rowCount: result.rows.length || result.affectedRows || 0 };
    };
    await query('SET ROLE chainvanta_test_app');
    return {
      query,
      release: () => {
        if (client) client.release();
        unlock();
      },
    } as unknown as PoolClient;
  };
  const pool = {
    connect,
    query: async (sql: string, params?: unknown[]) => {
      const client = await connect();
      try {
        return await client.query(sql, params);
      } finally {
        client.release();
      }
    },
  } as unknown as Pool;
  return {
    pool,
    admin,
    close: async () => {
      await embedded?.close();
      if (native) {
        const cleanup = await native.connect();
        try {
          await cleanup.query('RESET ROLE');
          await cleanup.query(`DROP SCHEMA ${schema} CASCADE`);
        } finally {
          cleanup.release();
          await native.end();
        }
      }
    },
  };
}
