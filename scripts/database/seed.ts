import { Pool } from 'pg';
import { readConfig } from '../../packages/config/src/index.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { AssessmentService } from '../../services/assessment-service/src/index.js';
import { ADDRESS, fixtureTransport } from '../../packages/test-fixtures/src/fixtures.js';
if (!process.argv.includes('--demo'))
  throw new Error('Explicit --demo required: this creates marked demonstration data');
const config = readConfig();
const tenantId = config.tenantKeys[0]?.tenantId ?? config.oidc?.memberships[0]?.tenantId;
if (!tenantId) throw new Error('Provision a tenant before seeding');
const pool = new Pool({ connectionString: config.databaseUrl });
try {
  const service = new AssessmentService(
    new PostgresRepository(pool),
    [
      {
        chainId: 1,
        name: 'Deterministic demonstration',
        rpcUrl: 'http://127.0.0.1:8545',
        demonstration: true,
      },
    ],
    fixtureTransport,
  );
  const result = await service.scan(
    tenantId,
    { address: ADDRESS, chainId: 1 },
    'local-demonstration-v1',
    'local-demo-seed',
  );
  console.log(
    JSON.stringify({
      demonstration: true,
      assessmentId: result.id,
      tenantId,
      asset: result.observation.address,
      evidenceHash: result.evidenceHash,
    }),
  );
} finally {
  await pool.end();
}
