import { createApp } from '../../services/api-gateway/src/app.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import { fixtureTransport, testConfig } from '../../packages/test-fixtures/src/fixtures.js';
import { CpmRepository } from '../../services/inventory-service/src/cpm-repository.js';
import { CpmWorker } from '../../services/job-worker/cpm-worker.js';
if (process.env.CHAINVANTA_TEST_MODE !== '1')
  throw new Error('Test server requires CHAINVANTA_TEST_MODE=1');
const database = await testDatabase();
const cpmTenant = '33333333-3333-4333-8333-333333333333';
await database.admin('INSERT INTO tenants(id) VALUES($1)', [cpmTenant]);
const repository = new PostgresRepository(database.pool);
const app = await createApp(
  {
    ...testConfig,
    tenantKeys: [
      ...testConfig.tenantKeys,
      { tenantId: cpmTenant, key: 'browser-admin-fixture-at-least-32-characters', role: 'admin' },
      {
        tenantId: cpmTenant,
        key: 'browser-analyst-fixture-at-least-32-characters',
        role: 'analyst',
      },
    ],
  },
  repository,
  fixtureTransport,
);
const worker = new CpmWorker(
  new CpmRepository(repository),
  testConfig.chains,
  'browser-fixture-worker',
  fixtureTransport,
);
let working = false;
setInterval(async () => {
  if (working) return;
  working = true;
  try {
    await worker.tick(cpmTenant);
  } finally {
    working = false;
  }
}, 1000);
await app.listen(4400, '127.0.0.1');
console.log('Fixture-only test API on 127.0.0.1:4400. No live blockchain data.');
