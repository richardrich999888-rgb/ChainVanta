import { createClient } from 'redis';
import { RedisLimiter } from '../../../core/tenant-authorization/src/rate-limit.js';
import { Pool } from 'pg';
import { readConfig } from '../../../packages/config/src/index.js';
import { PostgresRepository } from '../../inventory-service/src/repository.js';
import { createApp } from './app.js';

async function main() {
  const config = readConfig();
  const pool = new Pool({
    connectionString: config.databaseUrl,
    max: 10,
    connectionTimeoutMillis: 5000,
    statement_timeout: 10_000,
  });
  pool.on('error', () => console.error(JSON.stringify({ event: 'database_connection_error' })));
  const repository = new PostgresRepository(pool);
  await repository.ping();
  const redis = createClient({
    url: config.redisUrl,
    socket: {
      connectTimeout: 5000,
      reconnectStrategy: (retries) => (retries < 3 ? 500 : new Error('Redis unavailable')),
    },
  });
  redis.on('error', () => console.error(JSON.stringify({ event: 'redis_unavailable' })));
  await redis.connect();
  const app = await createApp(config, repository, fetch, new RedisLimiter(redis));
  const server = await app.listen(config.port, config.host);
  server.on('close', () => {
    void pool.end();
    void redis.close();
  });
  console.log(`ChainVanta API listening on ${config.host}:${config.port}`);
}
main().catch(() => {
  console.error(
    'Startup failed. Verify environment configuration, database access and migrations.',
  );
  process.exit(1);
});
