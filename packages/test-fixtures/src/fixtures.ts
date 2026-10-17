import type { Observation } from '../../domain-models/src/index.js';
export const TENANT_A = '11111111-1111-4111-8111-111111111111';
export const TENANT_B = '22222222-2222-4222-8222-222222222222';
export const KEY_A = 'test-only-tenant-a-key-with-at-least-32-characters';
export const KEY_B = 'test-only-tenant-b-key-with-at-least-32-characters';
export const ADDRESS = '0x0000000000000000000000000000000000000001';
export const BLOCK_HASH = `0x${'ab'.repeat(32)}`;
export const observation: Observation = {
  chainId: 1,
  address: ADDRESS,
  blockNumber: '0x100',
  blockHash: BLOCK_HASH,
  blockTimestamp: '0x65000000',
  balanceWei: '12345',
  transactionCount: '2',
  code: '0x',
  source: 'configured-rpc:1',
  observedAt: '2026-10-17T00:00:00.000Z',
  finality: 'finalized',
};
export const testConfig = {
  tenantKeys: [
    { tenantId: TENANT_A, key: KEY_A },
    { tenantId: TENANT_B, key: KEY_B },
  ],
  chains: [
    {
      chainId: 1,
      name: 'Ethereum (test fixture)',
      rpcUrl: 'http://127.0.0.1:8545',
      demonstration: true,
    },
  ],
};
export function rpcResult(method: string): unknown {
  switch (method) {
    case 'eth_chainId':
      return '0x1';
    case 'eth_getBlockByNumber':
      return { number: '0x100', hash: BLOCK_HASH, timestamp: '0x65000000' };
    case 'eth_getBalance':
      return '0x3039';
    case 'eth_getTransactionCount':
      return '0x2';
    case 'eth_getCode':
      return '0x';
    default:
      throw new Error('Unexpected RPC method');
  }
}
export const fixtureTransport: typeof fetch = async (_url, init) => {
  const body = JSON.parse(String(init?.body));
  return Response.json({ jsonrpc: '2.0', id: body.id, result: rpcResult(body.method) });
};
