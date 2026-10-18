import assert from 'node:assert/strict';
import { testDatabase } from '../../packages/test-fixtures/src/database.js';
import {
  TENANT_A,
  observation,
  testConfig,
  fixtureTransport,
  BLOCK_HASH,
} from '../../packages/test-fixtures/src/fixtures.js';
import { signedTransactionFixture } from '../../packages/test-fixtures/src/transaction.js';
import { PostgresRepository } from '../../services/inventory-service/src/repository.js';
import { CpmRepository } from '../../services/inventory-service/src/cpm-repository.js';
import { AssessmentService } from '../../services/assessment-service/src/index.js';
import { CpmWorker } from '../../services/job-worker/cpm-worker.js';

// Disposable database/schema only. No external provider, user account or wallet secrets.
const db = await testDatabase();
try {
  const base = new PostgresRepository(db.pool),
    cpm = new CpmRepository(base);
  const tx = await signedTransactionFixture();
  const service = new AssessmentService(base, testConfig.chains, fixtureTransport, cpm);
  const first = await service.scan(
    TENANT_A,
    { address: tx.address, chainId: 1 },
    'demonstration-register',
    'demo:analyst',
  );
  const before = (await cpm.posture(TENANT_A, `eip155:1:${tx.address}`))!;
  assert.equal(before.snapshot.quantumExposure, 'unknown');
  for (const status of ['acknowledged', 'in_remediation', 'pending_verification'] as const)
    await cpm.transition(
      TENANT_A,
      before.snapshot.id,
      'CV-CPM-EVIDENCE',
      { status, reason: 'Collect and verify a supplied finalized transaction signature' },
      'demo:admin',
    );
  const transport: typeof fetch = async (url, init) => {
    const call = JSON.parse(String(init?.body));
    let result: unknown;
    if (call.method === 'eth_getTransactionByHash') result = tx.raw;
    if (call.method === 'eth_getTransactionReceipt') result = tx.receipt;
    if (call.method === 'eth_getBlockByNumber')
      result =
        call.params[0] === observation.blockNumber
          ? { number: '0x100', hash: BLOCK_HASH, timestamp: '0x65000000' }
          : { number: '0x101', hash: `0x${'cd'.repeat(32)}`, timestamp: '0x65000001' };
    return result ? Response.json({ jsonrpc: '2.0', id: 1, result }) : fixtureTransport(url, init);
  };
  const worker = new CpmWorker(cpm, testConfig.chains, 'demo-worker', transport);
  const schedule = await worker.jobs.create(
    TENANT_A,
    { input: { address: tx.address, chainId: 1, transactionHash: tx.hash }, intervalSeconds: 60 },
    'demo:analyst',
  );
  assert.equal(await worker.tick(TENANT_A), true);
  const after = (await cpm.posture(TENANT_A, before.snapshot.assetId))!;
  assert.equal(after.snapshot.quantumExposure, 'exposed');
  assert.equal(after.lifecycle.find((f) => f.rule_id === 'CV-CPM-EVIDENCE')?.status, 'resolved');
  assert.equal(after.lifecycle.find((f) => f.rule_id === 'CV-QUANTUM-001')?.status, 'open');
  const drift = await cpm.list(TENANT_A, 'drift', 100, 0),
    recommendations = await cpm.list(TENANT_A, 'remediation', 100, 0);
  assert(drift.some((d) => d.type === 'ALGORITHM_OBSERVED'));
  assert(recommendations.some((r) => r.ruleId === 'CV-QUANTUM-001' && r.priority === 'MEDIUM'));
  const migration = await cpm.migration(
    TENANT_A,
    {
      assessmentId: after.snapshot.assessmentId,
      goal: 'cryptographic-migration',
      scope: 'Assess replacing the observed native EVM transaction signature',
      criteria: [{ kind: 'signature_algorithm', expected: 'ML-DSA' }],
    },
    'demo:analyst',
  );
  assert.equal(migration.status, 'TECHNICALLY_BLOCKED');
  await worker.jobs.update(TENANT_A, schedule.id, { enabled: false }, 'demo:admin');
  console.log(
    JSON.stringify(
      {
        demonstration: true,
        liveNetworkValidation: false,
        asset: before.snapshot.assetId,
        registeredAssessment: first.id,
        monitoredAssessment: after.snapshot.assessmentId,
        policy: `${after.snapshot.policyId}/${after.snapshot.policyVersion}`,
        quantumExposure: {
          before: before.snapshot.quantumExposure,
          after: after.snapshot.quantumExposure,
        },
        verifiedOutcome: 'Missing-transaction-evidence finding resolved for its defined scope',
        remainingQuantumFinding: 'open',
        drift: drift.map((d) => d.type),
        migration: migration.status,
        assertions: 'passed',
      },
      null,
      2,
    ),
  );
} finally {
  await db.close();
}
