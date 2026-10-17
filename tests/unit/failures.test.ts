import { expect, it } from 'vitest';
import { AssessmentService } from '../../services/assessment-service/src/index.js';
import type { Repository } from '../../services/inventory-service/src/repository.js';
import {
  ADDRESS,
  TENANT_A,
  fixtureTransport,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';
it('never persists failed RPC observations and releases capacity after failure', async () => {
  let saves = 0;
  const repository: Repository = {
    save: async () => {
      saves++;
    },
    list: async () => [],
    get: async () => null,
    ping: async () => {},
  };
  let fail = true;
  const service = new AssessmentService(repository, testConfig.chains, async (...args) => {
    if (fail) throw new Error('offline');
    return fixtureTransport(...args);
  });
  await expect(service.scan(TENANT_A, { address: ADDRESS, chainId: 1 })).rejects.toThrow();
  expect(saves).toBe(0);
  fail = false;
  await service.scan(TENANT_A, { address: ADDRESS, chainId: 1 });
  expect(saves).toBe(1);
});
