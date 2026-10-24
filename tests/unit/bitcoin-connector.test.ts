import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BITCOIN_RPC_POLICY,
  BitcoinConnector,
  BitcoinRpcFailure,
} from '../../connectors/blockchains/bitcoin/src/index.js';
import { createPinnedRpcTransport } from '../../connectors/blockchains/ethereum/src/transport.js';
import { InvalidAddress } from '../../modules/01-wallet-intelligence/src/key-dependencies/bitcoin-codec.js';
import {
  DUMMY_SIGNATURE,
  TIP_HASH,
  TX_BLOCK,
  fakeBitcoinNode,
  p2pkScript,
  p2pkhScript,
  p2wpkhAddress,
  p2wpkhScript,
  spendingTransaction,
  testKey,
  type FakeNode,
} from '../../packages/test-fixtures/src/bitcoin.js';
import { BITCOIN_NETWORKS } from '../../packages/domain-models/src/bitcoin.js';

const NODE = {
  network: 'regtest' as const,
  name: 'regtest',
  rpcUrl: 'http://127.0.0.1:18443',
  demonstration: true,
};
const KEY = testKey(1);
const ADDRESS = p2wpkhAddress('regtest', KEY);
const TXID = '0a'.repeat(32);
const utxo = (overrides: Partial<NonNullable<FakeNode['unspents']>[number]> = {}) => ({
  txid: '0b'.repeat(32),
  vout: 0,
  scriptPubKey: p2wpkhScript(KEY),
  amount: 0.29,
  height: 190,
  ...overrides,
});
const observe = (node: FakeNode, input: Record<string, unknown> = { address: ADDRESS }) =>
  new BitcoinConnector(NODE, fakeBitcoinNode(node)).observe({
    network: 'regtest',
    ...input,
  } as never);

describe('Bitcoin Core connector', () => {
  it('collects a UTXO snapshot with exact satoshi amounts and confirmations', async () => {
    const o = await observe({
      unspents: [utxo(), utxo({ txid: '0c'.repeat(32), amount: 20999999.9769, height: 200 })],
    });
    expect(o).toMatchObject({
      chainId: 'bip122:0f9188f13cb7b2c71f2a335e3a4fc328',
      target: { kind: 'address', scriptTypes: ['p2wpkh'], descriptor: `addr(${ADDRESS})` },
      tipHeight: 200,
      tipHash: TIP_HASH,
      utxoCount: 2,
      // 0.29 BTC is 28999999.999999996 sats as a double; rounding recovers the exact value.
      totalSats: (29_000_000n + 2_099_999_997_690_000n).toString(),
      revealedSpend: null,
    });
    expect(o.groups).toEqual([
      {
        scriptType: 'p2wpkh',
        keyExposure: 'hash-locked',
        count: 2,
        sats: o.totalSats,
        minConfirmations: 1,
      },
    ]);
    expect(o.sampleOutpoints.map((s) => s.height)).toEqual([190, 200]);
  });

  it('scans every standard script for a public key with combo()', async () => {
    const o = await observe(
      {
        unspents: [
          utxo({ scriptPubKey: p2pkScript(KEY) }),
          utxo({ txid: '0d'.repeat(32), scriptPubKey: p2pkhScript(KEY) }),
        ],
      },
      { publicKey: KEY },
    );
    expect(o.target).toMatchObject({ kind: 'public-key', descriptor: `combo(${KEY})` });
    expect(o.target.scriptTypes).toEqual(['p2pk', 'p2pkh', 'p2wpkh', 'p2sh']);
    expect(o.groups.map((g) => [g.scriptType, g.keyExposure])).toEqual([
      ['p2pk', 'public-key-in-script'],
      ['p2pkh', 'hash-locked'],
    ]);
  });

  it('records spend evidence that revealed the address key', async () => {
    const o = await observe(
      {
        unspents: [utxo()],
        transactions: { [TXID]: spendingTransaction(TXID, { witness: [DUMMY_SIGNATURE, KEY] }) },
      },
      { address: ADDRESS, spendTransaction: { txid: TXID, blockHash: TX_BLOCK } },
    );
    expect(o.revealedSpend).toMatchObject({
      txid: TXID,
      source: 'p2wpkh-witness',
      publicKeys: [KEY],
    });
  });

  it.each([
    ['the node is on another network', { genesis: BITCOIN_NETWORKS.mainnet.genesis }],
    [
      'the scan returns an output the target does not control',
      { unspents: [utxo({ scriptPubKey: p2wpkhScript(testKey(2)) })] },
    ],
    ['an output is above the scan tip', { unspents: [utxo({ height: 201 })] }],
    ['the tip changes during collection', { tipAfterScan: 'ee'.repeat(32) }],
    ['an amount exceeds the 21M supply', { unspents: [utxo({ amount: 21_000_001 })] }],
  ])('fails closed when %s', async (_, node) => {
    await expect(observe(node as FakeNode)).rejects.toBeInstanceOf(BitcoinRpcFailure);
  });

  it('fails closed when a supplied spend does not reveal the target key', async () => {
    await expect(
      observe(
        {
          transactions: {
            [TXID]: spendingTransaction(TXID, { witness: [DUMMY_SIGNATURE, testKey(2)] }),
          },
        },
        { address: ADDRESS, spendTransaction: { txid: TXID, blockHash: TX_BLOCK } },
      ),
    ).rejects.toThrow('does not reveal');
  });

  it('rejects addresses for another network before contacting the node scan', async () => {
    const node = fakeBitcoinNode();
    await expect(
      new BitcoinConnector(NODE, node).observe({
        network: 'regtest',
        address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
      }),
    ).rejects.toBeInstanceOf(InvalidAddress);
    expect(node.methods).not.toContain('scantxoutset');
  });

  it('never surfaces upstream error text or credentials', async () => {
    const leaky: typeof fetch = async () =>
      Response.json({ result: null, error: { code: -1, message: 'rpcpassword=hunter2' } });
    const error = await new BitcoinConnector(NODE, leaky)
      .observe({ network: 'regtest', address: ADDRESS })
      .catch((e: Error) => e);
    expect(error).toBeInstanceOf(BitcoinRpcFailure);
    expect(String((error as Error).message)).not.toContain('hunter2');
  });
});

describe('pinned Bitcoin RPC transport', () => {
  let server: Server | undefined;
  afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));
  async function listen() {
    const seen: IncomingHttpHeaders[] = [];
    server = createServer((req, res) => {
      seen.push(req.headers);
      res.end('{"result":"ok","error":null,"id":1}');
    });
    await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('no port');
    return { url: `http://127.0.0.1:${address.port}/`, seen };
  }
  const call = (method: string) => ({
    method: 'POST',
    headers: { authorization: 'Bearer caller-supplied', cookie: 'x=1' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
  });

  it('attaches configured credentials and never forwards caller headers', async () => {
    const { url, seen } = await listen();
    const transport = createPinnedRpcTransport(
      [{ rpcUrl: url, demonstration: true, authorization: 'Basic dGVzdDp0ZXN0' }],
      BITCOIN_RPC_POLICY,
    );
    expect((await transport(url, call('getblockhash'))).ok).toBe(true);
    expect(seen[0]?.authorization).toBe('Basic dGVzdDp0ZXN0');
    expect(seen[0]?.cookie).toBeUndefined();
  });

  it('allows only read-only scan methods', async () => {
    const { url, seen } = await listen();
    const transport = createPinnedRpcTransport(
      [{ rpcUrl: url, demonstration: true }],
      BITCOIN_RPC_POLICY,
    );
    for (const method of [
      'sendrawtransaction',
      'dumpprivkey',
      'stop',
      'walletpassphrase',
      'eth_call',
    ])
      await expect(transport(url, call(method))).rejects.toThrow();
    expect(seen).toHaveLength(0);
    expect(BITCOIN_RPC_POLICY.timeoutMs('scantxoutset')).toBeGreaterThan(
      BITCOIN_RPC_POLICY.timeoutMs('getblockhash'),
    );
  });
});
