import { afterEach, describe, it, expect, vi } from 'vitest';
import { createServer, type Server, type RequestListener } from 'node:http';
import {
  createRpcTransport,
  publicRpcAddress,
} from '../../connectors/blockchains/ethereum/src/transport.js';
const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] });
const init = { method: 'POST', body };
let server: Server | undefined;
afterEach(async () => {
  vi.unstubAllEnvs();
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  server = undefined;
});
async function fixture(handler: RequestListener) {
  server = createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing fixture port');
  const url = `http://127.0.0.1:${address.port}`;
  return {
    url,
    transport: createRpcTransport([
      { chainId: 1, name: 'Fixture', rpcUrl: url, demonstration: true },
    ]),
  };
}
describe('RPC destination and socket boundary', () => {
  it('rejects private, metadata, mapped, multicast and transition addresses', () => {
    for (const address of [
      '0.0.0.0',
      '127.1.2.3',
      '10.0.0.1',
      '169.254.169.254',
      '100.100.100.200',
      '192.168.1.2',
      '172.20.1.1',
      '224.0.0.1',
      '::1',
      'fc00::1',
      'fe80::1',
      '::ffff:8.8.8.8',
      '2002:7f00:1::',
      '2001:db8::1',
      '2001::1',
      '3fff::1',
    ])
      expect(publicRpcAddress(address), address).toBe(false);
    for (const address of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111'])
      expect(publicRpcAddress(address), address).toBe(true);
  });
  it('rejects mixed DNS answers before connecting and never leaks provider credentials', async () => {
    const resolve = vi.fn(async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    const url = 'https://rpc.example/private-provider-key';
    const transport = createRpcTransport([{ chainId: 1, name: 'RPC', rpcUrl: url }], resolve);
    await expect(transport(url, init)).rejects.toThrow('Approved RPC transport failed');
    expect(resolve).toHaveBeenCalledTimes(1);
    await expect(transport('https://attacker.example', init)).rejects.toThrow(
      'Approved RPC transport failed',
    );
    expect(resolve).toHaveBeenCalledTimes(1);
  });
  it('allows only explicit local fixtures and read-only RPC, with bounded responses', async () => {
    let mode = 'normal',
      calls = 0;
    const { url, transport } = await fixture((_req, res) => {
      calls++;
      if (mode === 'redirect') {
        res.writeHead(302, { location: 'http://169.254.169.254' });
        res.end();
      } else {
        res.end(
          mode === 'oversize' ? 'x'.repeat(1048577) : '{"jsonrpc":"2.0","id":1,"result":"0x1"}',
        );
      }
    });
    expect((await (await transport(url, init)).json()).result).toBe('0x1');
    const storage = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_getStorageAt',
      params: ['0x' + '00'.repeat(20), '0x0', 'latest'],
    });
    expect((await transport(url, { method: 'POST', body: storage })).ok).toBe(true);
    for (const method of ['eth_setStorageAt', 'hardhat_setStorageAt', 'anvil_setStorageAt'])
      await expect(
        transport(url, {
          method: 'POST',
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
        }),
      ).rejects.toThrow();
    await expect(
      transport(url, {
        method: 'POST',
        body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_sendRawTransaction', params: ['0x'] }),
      }),
    ).rejects.toThrow();
    expect(calls).toBe(2);
    mode = 'redirect';
    await expect(transport(url, init)).rejects.toThrow();
    mode = 'oversize';
    await expect(transport(url, init)).rejects.toThrow();
    vi.stubEnv('NODE_ENV', 'production');
    await expect(transport(url, init)).rejects.toThrow();
  });
  it('aborts an unresponsive socket without returning partial evidence', async () => {
    const { url, transport } = await fixture(() => {});
    await expect(transport(url, { ...init, signal: AbortSignal.timeout(25) })).rejects.toThrow(
      'Approved RPC transport failed',
    );
  });
});
