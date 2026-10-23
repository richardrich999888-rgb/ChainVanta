import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { BlockList, isIP } from 'node:net';
import type { ChainConfig } from './index.js';

const denied = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['192.88.99.0', 24],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const)
  denied.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of [
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
] as const)
  denied.addSubnet(address, prefix, 'ipv6');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
export function publicRpcAddress(address: string): boolean {
  if (address.includes('%')) return false;
  const family = isIP(address);
  return family === 4
    ? !denied.check(address, 'ipv4')
    : family === 6 && globalV6.check(address, 'ipv6') && !denied.check(address, 'ipv6');
}
const methods = new Set([
  'eth_chainId',
  'eth_getBlockByNumber',
  'eth_getBalance',
  'eth_getTransactionCount',
  'eth_getCode',
  'eth_getTransactionByHash',
  'eth_getTransactionReceipt',
  'eth_call',
]);
const genericError = () => new Error('Approved RPC transport failed');
type Resolver = (hostname: string) => Promise<{ address: string; family: number }[]>;
/** Restricts destinations to configured URLs and pins each socket to a checked DNS answer.
 * No redirects, proxy environment, pooled socket reuse, or write-capable JSON-RPC methods.
 */
export function createRpcTransport(
  chains: ChainConfig[],
  resolve: Resolver = (hostname) => lookup(hostname, { all: true, verbatim: true }),
): typeof fetch {
  const approved = new Map(chains.map((chain) => [new URL(chain.rpcUrl).href, chain]));
  return async (input, init) => {
    try {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      );
      const chain = approved.get(url.href),
        host = url.hostname.replace(/^\[|\]$/g, '');
      const local =
        !!chain?.demonstration &&
        process.env.NODE_ENV !== 'production' &&
        ['localhost', '127.0.0.1', '::1'].includes(host);
      if (
        !chain ||
        url.username ||
        url.password ||
        url.hash ||
        !(url.protocol === 'https:' || (local && url.protocol === 'http:'))
      )
        throw genericError();
      if (
        init?.method !== 'POST' ||
        typeof init.body !== 'string' ||
        Buffer.byteLength(init.body) > 8192
      )
        throw genericError();
      const body = JSON.parse(init.body);
      if (
        Array.isArray(body) ||
        body.jsonrpc !== '2.0' ||
        !methods.has(body.method) ||
        !Array.isArray(body.params)
      )
        throw genericError();
      const permitted = (address: string) =>
        publicRpcAddress(address) || (local && ['127.0.0.1', '::1'].includes(address));
      if (isIP(host) && !permitted(host)) throw genericError();
      const signal = AbortSignal.any([
        AbortSignal.timeout(10000),
        ...(init.signal ? [init.signal] : []),
      ]);
      signal.throwIfAborted();
      return await new Promise<Response>((accept, reject) => {
        const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(
          url,
          {
            method: 'POST',
            agent: false,
            signal,
            maxHeaderSize: 16384,
            headers: {
              'content-type': 'application/json',
              'content-length': Buffer.byteLength(init.body as string),
              'accept-encoding': 'identity',
            },
            lookup: (_hostname, options, callback) => {
              void resolve(host)
                .then((records) => {
                  if (
                    !records.length ||
                    records.some((r) => !permitted(r.address) || isIP(r.address) !== r.family)
                  )
                    throw genericError();
                  const address = records[0]!;
                  // The connection consumes this exact checked answer, without a second DNS lookup.
                  if (options.all) callback(null, [address]);
                  else callback(null, address.address, address.family);
                })
                .catch(() => callback(genericError(), '', 4));
            },
          },
          (response) => {
            if (
              response.statusCode !== 200 ||
              (response.headers['content-encoding'] &&
                response.headers['content-encoding'] !== 'identity')
            ) {
              response.resume();
              request.destroy();
              reject(genericError());
              return;
            }
            const chunks: Buffer[] = [];
            let size = 0;
            response.on('data', (chunk: Buffer) => {
              size += chunk.length;
              if (size > 1_048_576) {
                request.destroy(genericError());
                return;
              }
              chunks.push(chunk);
            });
            response.on('end', () =>
              accept(
                new Response(Buffer.concat(chunks), {
                  status: 200,
                  headers: { 'content-type': 'application/json' },
                }),
              ),
            );
            response.on('error', () => reject(genericError()));
            response.on('aborted', () => reject(genericError()));
          },
        );
        request.on('error', () => reject(genericError()));
        request.end(init.body);
      });
    } catch {
      throw genericError();
    }
  };
}
