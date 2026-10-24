import { z } from 'zod';
import { createPinnedRpcTransport, type RpcPolicy } from '../../ethereum/src/transport.js';
import {
  BITCOIN_NETWORKS,
  BitcoinObservation,
  MAX_SAMPLE_OUTPOINTS,
  bip122ChainId,
  type BitcoinNetwork,
  type BitcoinScanInput,
  type ScriptType,
} from '../../../../packages/domain-models/src/bitcoin.js';
import {
  InvalidAddress,
  classifyScript,
  decodeAddress,
  fromHex,
  hash160,
  isValidPublicKey,
  keyExposure,
  toHex,
} from '../../../../modules/01-wallet-intelligence/src/key-dependencies/bitcoin-codec.js';
import {
  InvalidSpendEvidence,
  extractRevealedSpend,
  type SpendTarget,
} from '../../../../modules/01-wallet-intelligence/src/signature-analysis/bitcoin-spend.js';

/**
 * Read-only Bitcoin Core collector. The UTXO set comes from `scantxoutset` (no address index
 * required). Network identity is proven by block 0's hash; every returned output script is
 * re-derived and checked against the target; the scan tip is re-checked after the scan.
 */

export type BitcoinNodeConfig = {
  network: BitcoinNetwork;
  name: string;
  rpcUrl: string;
  demonstration?: boolean;
  /** HTTP Basic credentials, resolved from the environment by configuration, never logged. */
  credentials?: { user: string; password: string };
};

export class BitcoinRpcFailure extends Error {
  constructor(message = 'Bitcoin node could not complete a consistent UTXO snapshot') {
    super(message);
  }
}

// A UTXO-set scan reads the whole chainstate: minutes on mainnet. Everything else is fast.
const SCAN_TIMEOUT_MS = 170_000;
const CALL_TIMEOUT_MS = 10_000;
export const BITCOIN_RPC_POLICY: RpcPolicy = {
  methods: new Set(['getblockhash', 'scantxoutset', 'getrawtransaction']),
  timeoutMs: (method) => (method === 'scantxoutset' ? SCAN_TIMEOUT_MS : CALL_TIMEOUT_MS),
};
const SATS_PER_BTC = 100_000_000;
const MAX_SUPPLY_BTC = 21_000_000;
const BlockHash = z.string().regex(/^[0-9a-f]{64}$/);
const Reply = z.object({
  result: z.unknown(),
  // Bitcoin Core legacy replies carry `error: null` on success.
  error: z.unknown().nullable().optional(),
});
const Scan = z.object({
  success: z.literal(true),
  height: z.number().int().nonnegative(),
  bestblock: BlockHash,
  unspents: z.array(
    z.object({
      txid: BlockHash,
      vout: z.number().int().nonnegative(),
      scriptPubKey: z.string().regex(/^(?:[0-9a-f]{2})+$/),
      amount: z.number().finite().nonnegative().max(MAX_SUPPLY_BTC),
      height: z.number().int().nonnegative(),
    }),
  ),
});

/**
 * BTC amounts arrive as JSON numbers with at most 8 decimals. Any such value below 2^53 / 1e8 BTC
 * (far above the 21M supply) is within half a satoshi of its double, so rounding is exact.
 */
const toSats = (btc: number) => BigInt(Math.round(btc * SATS_PER_BTC));

/** The scripts `combo(<key>)` covers, as hex, keyed by script type. */
function comboScripts(key: Uint8Array): Map<string, ScriptType> {
  const h = toHex(hash160(key));
  const scripts = new Map<string, ScriptType>([
    [`${key.length.toString(16)}${toHex(key)}ac`, 'p2pk'],
    [`76a914${h}88ac`, 'p2pkh'],
  ]);
  // Segwit forms exist only for compressed keys (BIP-143 policy).
  if (key.length === 33) {
    scripts.set(`0014${h}`, 'p2wpkh');
    scripts.set(`a914${toHex(hash160(fromHex(`0014${h}`)))}87`, 'p2sh');
  }
  return scripts;
}

export class BitcoinConnector {
  private id = 0;
  constructor(
    private readonly node: BitcoinNodeConfig,
    private readonly transport: typeof fetch = createPinnedRpcTransport(
      [
        {
          rpcUrl: node.rpcUrl,
          demonstration: node.demonstration,
          ...(node.credentials
            ? {
                authorization: `Basic ${Buffer.from(`${node.credentials.user}:${node.credentials.password}`).toString('base64')}`,
              }
            : {}),
        },
      ],
      BITCOIN_RPC_POLICY,
    ),
  ) {}

  private async rpc(method: string, params: unknown[]): Promise<unknown> {
    try {
      const response = await this.transport(this.node.rpcUrl, {
        method: 'POST',
        redirect: 'error',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }),
        signal: AbortSignal.timeout(BITCOIN_RPC_POLICY.timeoutMs(method) + 1_000),
      });
      if (!response.ok) throw new BitcoinRpcFailure();
      const reply = Reply.parse(await response.json());
      if (reply.error !== null && reply.error !== undefined) throw new BitcoinRpcFailure();
      return reply.result;
    } catch {
      // Never expose credentials, provider URLs or upstream error text.
      throw new BitcoinRpcFailure();
    }
  }

  /**
   * Collects a UTXO snapshot for an address or public key, plus optional spend evidence.
   * Errors: InvalidAddress for caller input; BitcoinRpcFailure for anything the node returned or
   * failed to return, including malformed data, so provider faults never read as caller faults.
   */
  async observe(input: BitcoinScanInput): Promise<BitcoinObservation> {
    try {
      return await this.collect(input);
    } catch (error) {
      if (error instanceof BitcoinRpcFailure || error instanceof InvalidAddress) throw error;
      throw new BitcoinRpcFailure();
    }
  }

  private async collect(input: BitcoinScanInput): Promise<BitcoinObservation> {
    if (input.network !== this.node.network)
      throw new BitcoinRpcFailure('Requested network is not this node');
    const genesis = BlockHash.parse(await this.rpc('getblockhash', [0]));
    if (genesis !== BITCOIN_NETWORKS[this.node.network].genesis)
      throw new BitcoinRpcFailure('Node network does not match configuration');

    let target: BitcoinObservation['target'];
    let spendTarget: SpendTarget;
    let expected: (script: string) => ScriptType | null;
    if (input.address) {
      const decoded = decodeAddress(this.node.network, input.address);
      target = {
        kind: 'address',
        value: input.address,
        scriptTypes: [decoded.scriptType],
        descriptor: `addr(${input.address})`,
      };
      spendTarget = { kind: 'address', decoded };
      expected = (script) => (script === decoded.scriptPubKey ? decoded.scriptType : null);
    } else {
      const key = fromHex(input.publicKey!);
      if (!isValidPublicKey(key)) throw new BitcoinRpcFailure('Public key is not a valid point');
      const scripts = comboScripts(key);
      target = {
        kind: 'public-key',
        value: input.publicKey!,
        scriptTypes: [...new Set(scripts.values())],
        descriptor: `combo(${input.publicKey})`,
      };
      spendTarget = { kind: 'public-key', key: input.publicKey! };
      expected = (script) => scripts.get(script) ?? null;
    }

    const scan = Scan.parse(await this.rpc('scantxoutset', ['start', [target.descriptor]]));
    const groups = new Map<ScriptType, { count: number; sats: bigint; minConfirmations: number }>();
    let total = 0n;
    const outputs = scan.unspents.map((u) => {
      // The node's scan must only return scripts the target controls; anything else is
      // inconsistent provider data, not something to reinterpret.
      const scriptType = expected(u.scriptPubKey);
      if (!scriptType || classifyScript(u.scriptPubKey).scriptType !== scriptType)
        throw new BitcoinRpcFailure('Scan returned an output outside the target');
      if (u.height > scan.height) throw new BitcoinRpcFailure('Output above scan tip');
      const sats = toSats(u.amount);
      const confirmations = scan.height - u.height + 1;
      const group = groups.get(scriptType) ?? { count: 0, sats: 0n, minConfirmations: Infinity };
      group.count += 1;
      group.sats += sats;
      group.minConfirmations = Math.min(group.minConfirmations, confirmations);
      groups.set(scriptType, group);
      total += sats;
      return { txid: u.txid, vout: u.vout, sats: sats.toString(), height: u.height, scriptType };
    });

    let revealedSpend = null;
    if (input.spendTransaction) {
      const { txid, blockHash } = input.spendTransaction;
      try {
        revealedSpend = extractRevealedSpend(
          await this.rpc('getrawtransaction', [txid, true, blockHash]),
          { txid, blockHash },
          spendTarget,
        );
      } catch (error) {
        if (error instanceof InvalidSpendEvidence) throw new BitcoinRpcFailure(error.message);
        throw error;
      }
      if (!revealedSpend)
        throw new BitcoinRpcFailure(
          'Supplied transaction does not reveal key material for the target',
        );
    }

    // The scan's tip must still be on the active chain after collection.
    const tip = BlockHash.parse(await this.rpc('getblockhash', [scan.height]));
    if (tip !== scan.bestblock)
      throw new BitcoinRpcFailure('Chain tip changed during collection; retry the assessment');

    return BitcoinObservation.parse({
      network: this.node.network,
      chainId: bip122ChainId(this.node.network),
      target,
      tipHeight: scan.height,
      tipHash: scan.bestblock,
      utxoCount: outputs.length,
      totalSats: total.toString(),
      groups: [...groups].map(([scriptType, g]) => ({
        scriptType,
        keyExposure: keyExposure(scriptType),
        count: g.count,
        sats: g.sats.toString(),
        minConfirmations: g.minConfirmations,
      })),
      // Deterministic sample: oldest first, then txid and output index.
      sampleOutpoints: [...outputs]
        .sort((a, b) => a.height - b.height || a.txid.localeCompare(b.txid) || a.vout - b.vout)
        .slice(0, MAX_SAMPLE_OUTPOINTS),
      revealedSpend,
      source: `bitcoin-core:${this.node.network}`,
      observedAt: new Date().toISOString(),
      parserVersion: 'bitcoin-snapshot/1.0.0',
      ...(this.node.demonstration ? { demonstration: true } : {}),
    });
  }
}
