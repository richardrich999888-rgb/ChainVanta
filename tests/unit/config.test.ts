import { it, expect } from 'vitest';
import { Chains } from '../../packages/config/src/index.js';
import { ScanRequest } from '../../packages/domain-models/src/index.js';
it('rejects caller supplied endpoints, unsafe protocols and metadata endpoints', () => {
  for (const rpcUrl of [
    'file:///etc/passwd',
    'http://169.254.169.254/latest/meta-data',
    'https://169.254.169.254',
    'https://metadata.google.internal',
    'https://user:secret@example.com',
    'http://example.com',
  ])
    expect(Chains.safeParse([{ chainId: 1, name: 'x', rpcUrl }]).success).toBe(false);
  expect(
    Chains.safeParse([{ chainId: 1, name: 'local', rpcUrl: 'http://127.0.0.1:8545' }]).success,
  ).toBe(true);
  expect(
    ScanRequest.safeParse({
      chainId: 1,
      address: '0x' + '00'.repeat(20),
      rpcUrl: 'http://localhost',
    }).success,
  ).toBe(false);
});
