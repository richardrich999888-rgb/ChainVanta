import { createApp } from '../../services/api-gateway/src/app.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import { fixtureTransport, testConfig } from '../../packages/test-fixtures/src/fixtures.js';
if (process.env.CHAINVANTA_TEST_MODE !== '1')
  throw new Error('Test server requires CHAINVANTA_TEST_MODE=1');
const database = await testDatabase();
const app = await createApp(testConfig, new PostgresRepository(database.pool), fixtureTransport);
await app.listen(4400, '127.0.0.1');
console.log('Fixture-only test API on 127.0.0.1:4400. No live blockchain data.');
