import { describe, expect, it } from 'vitest';
import { EvmConnector } from '../../connectors/blockchains/ethereum/src/index.js';
import {
  ADDRESS,
  BLOCK_HASH,
  fixtureTransport,
  rpcResult,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';
const chain = testConfig.chains[0]!;
describe('Read-only finalized EVM collection', () => {
  it('pins account reads to the observed block and preserves large integers', async () => {
    const calls: { method: string; params: unknown[] }[] = [];
    const connector = new EvmConnector(chain, async (_url, init) => {
      const request = JSON.parse(String(init?.body));
      calls.push(request);
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result:
          request.method === 'eth_getBalance'
            ? '0xffffffffffffffffffffffffffffffff'
            : rpcResult(request.method),
      });
    });
    const result = await connector.observe(ADDRESS);
    expect(result.balanceWei).toBe(BigInt('0xffffffffffffffffffffffffffffffff').toString());
    expect(result.blockHash).toBe(BLOCK_HASH);
    expect(
      calls
        .filter((call) =>
          ['eth_getCode', 'eth_getBalance', 'eth_getTransactionCount'].includes(call.method),
        )
        .every(
          (call) =>
            JSON.stringify(call.params[1]) ===
            JSON.stringify({ blockHash: BLOCK_HASH, requireCanonical: true }),
        ),
    ).toBe(true);
    expect(calls.some((call) => /send|sign/i.test(call.method))).toBe(false);
  });
  it('rejects a mismatched provider chain', async () => {
    await expect(
      new EvmConnector({ ...chain, chainId: 10 }, fixtureTransport).observe(ADDRESS),
    ).rejects.toThrow('chain');
  });
  it('fails closed on a block change', async () => {
    let blocks = 0;
    const transport: typeof fetch = async (_url, init) => {
      const request = JSON.parse(String(init?.body));
      let result = rpcResult(request.method);
      if (request.method === 'eth_getBlockByNumber' && ++blocks === 2)
        result = { number: '0x100', hash: `0x${'cd'.repeat(32)}`, timestamp: '0x65000000' };
      return Response.json({ jsonrpc: '2.0', id: 1, result });
    };
    await expect(new EvmConnector(chain, transport).observe(ADDRESS)).rejects.toThrow('changed');
  });
  it.each(['error', 'invalid', 'oversized', 'network'])(
    'rejects %s responses without leaking upstream secrets',
    async (kind) => {
      const transport: typeof fetch = async () => {
        if (kind === 'network') throw new Error('secret-provider-token');
        if (kind === 'oversized') return new Response('x'.repeat(1_048_577));
        if (kind === 'invalid') return Response.json({ jsonrpc: '2.0', id: 1, result: '0xzz' });
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          error: { message: 'secret-provider-token' },
        });
      };
      await expect(new EvmConnector(chain, transport).observe(ADDRESS)).rejects.toThrow(
        'consistent finalized snapshot',
      );
    },
  );
});
