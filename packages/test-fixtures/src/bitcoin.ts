import { secp256k1 } from '@noble/curves/secp256k1';
import { bech32, createBase58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { BITCOIN_NETWORKS, type BitcoinNetwork } from '../../domain-models/src/bitcoin.js';
import {
  hash160,
  toHex,
} from '../../../modules/01-wallet-intelligence/src/key-dependencies/bitcoin-codec.js';

/** TEST ONLY secp256k1 keys. Deterministic, never funded, never used on a network. */
export const testKey = (n: number) =>
  toHex(secp256k1.getPublicKey(new Uint8Array(32).fill(0x30 + n), true));

/** Push encoding for scripts up to 75 bytes (enough for keys, hashes and test signatures). */
export const push = (hex: string) => `${(hex.length / 2).toString(16).padStart(2, '0')}${hex}`;
/** DER-shaped placeholder: exposure analysis never validates signatures (see bitcoin-spend.ts). */
export const DUMMY_SIGNATURE = `3044022011${'11'.repeat(31)}0220${'22'.repeat(32)}01`;

export const p2pkhAddress = (network: BitcoinNetwork, key: string) =>
  createBase58check(sha256).encode(
    new Uint8Array([BITCOIN_NETWORKS[network].p2pkhVersion, ...hash160(Buffer.from(key, 'hex'))]),
  );
export const p2wpkhAddress = (network: BitcoinNetwork, key: string) =>
  bech32.encode(BITCOIN_NETWORKS[network].hrp, [
    0,
    ...bech32.toWords(hash160(Buffer.from(key, 'hex'))),
  ]);
export const p2pkhScript = (key: string) => `76a914${toHex(hash160(Buffer.from(key, 'hex')))}88ac`;
export const p2wpkhScript = (key: string) => `0014${toHex(hash160(Buffer.from(key, 'hex')))}`;
export const p2pkScript = (key: string) => `${push(key)}ac`;

export const TIP_HASH = 'cd'.repeat(32);
export const TX_BLOCK = 'ef'.repeat(32);

export interface FakeNode {
  network?: BitcoinNetwork;
  genesis?: string;
  tipHeight?: number;
  tipHash?: string;
  /** Hash returned for `getblockhash(tipHeight)` after the scan (models a reorganization). */
  tipAfterScan?: string;
  unspents?: { txid: string; vout: number; scriptPubKey: string; amount: number; height: number }[];
  transactions?: Record<string, unknown>;
}

/** JSON-RPC transport emulating the Bitcoin Core methods the connector uses. */
export function fakeBitcoinNode(node: FakeNode = {}): typeof fetch & { methods: string[] } {
  const network = node.network ?? 'regtest';
  const tipHeight = node.tipHeight ?? 200;
  const tipHash = node.tipHash ?? TIP_HASH;
  const methods: string[] = [];
  const transport = async (_url: RequestInfo | URL, init?: RequestInit) => {
    const { id, method, params } = JSON.parse(String(init?.body));
    methods.push(method);
    const reply = (result: unknown) => Response.json({ jsonrpc: '2.0', id, result, error: null });
    const fail = () =>
      Response.json({ jsonrpc: '2.0', id, result: null, error: { code: -5, message: 'x' } });
    switch (method) {
      case 'getblockhash':
        return params[0] === 0
          ? reply(node.genesis ?? BITCOIN_NETWORKS[network].genesis)
          : reply(node.tipAfterScan ?? tipHash);
      case 'scantxoutset':
        return reply({
          success: true,
          txouts: 1000,
          height: tipHeight,
          bestblock: tipHash,
          unspents: (node.unspents ?? []).map((u) => ({ ...u, desc: 'ignored-by-connector' })),
          total_amount: 0,
        });
      case 'getrawtransaction':
        return node.transactions?.[params[0]] ? reply(node.transactions[params[0]]) : fail();
      default:
        return fail();
    }
  };
  return Object.assign(transport as typeof fetch, { methods });
}

/** A verbose `getrawtransaction` result with one input. */
export const spendingTransaction = (
  txid: string,
  input: { scriptSig?: string; witness?: string[] },
  overrides: Record<string, unknown> = {},
) => ({
  txid,
  blockhash: TX_BLOCK,
  confirmations: 12,
  in_active_chain: true,
  vin: [{ scriptSig: { hex: input.scriptSig ?? '' }, txinwitness: input.witness ?? [] }],
  ...overrides,
});
