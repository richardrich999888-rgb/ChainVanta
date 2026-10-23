import { createRpcTransport } from './transport.js';
import { verifyTransaction } from '../../../../modules/01-wallet-intelligence/src/signature-analysis/verify-transaction.js';
import { observeToken } from '../../../../modules/09-stablecoin-assurance/src/privileged-roles/index.js';
import {
  discoverAccountStructure,
  type ProbeResult,
  type StructureReader,
} from '../../../../modules/01-wallet-intelligence/src/discovery/account-structure.js';
import type { Hex } from 'viem';
import { z } from 'zod';
import {
  Address,
  Hash,
  HexData,
  HexQuantity,
  Observation,
} from '../../../../packages/domain-models/src/index.js';

export type ChainConfig = {
  chainId: number;
  name: string;
  rpcUrl: string;
  demonstration?: boolean;
};
export class RpcFailure extends Error {
  constructor(message = 'Blockchain provider could not complete a consistent finalized snapshot') {
    super(message);
  }
}
const Block = z.object({ number: HexQuantity, hash: Hash, timestamp: HexQuantity });
const MAX_RESPONSE_BYTES = 1_048_576;
// Some providers return storage as a minimal quantity (e.g. 0x0); normalize to a 32-byte word.
const StorageWord = z
  .string()
  .regex(/^0x[0-9a-fA-F]{1,64}$/)
  .transform((v) => `0x${v.slice(2).toLowerCase().padStart(64, '0')}` as Hex);
type RpcReply = { ok: true; result: unknown } | { ok: false; code: number | null; message: string };

/**
 * EVM execution failures (reverts and exceptional halts) are answers for interface probes: the
 * target did not return data for that selector. Clients disagree on codes and wording, e.g.
 * geth/reth/anvil: 3 or -32000 "execution reverted", "invalid opcode: INVALID", "out of gas";
 * Hardhat: -32603 "VM Exception while processing transaction: ..." or "...reverted...";
 * revm-based clients: "EVM error ..."; Nethermind: "VM execution error".
 * So: code 3, or a message naming an execution failure. Anything else (rate limits, missing state,
 * internal errors) is a provider failure and fails the observation rather than reading as absent.
 * Pre-0.8 Solidity compiles array bounds and assert failures to INVALID, so halts must count.
 */
const EXECUTION_FAILURE =
  /\brevert|invalid opcode|out of gas|stack (?:underflow|overflow)|invalid jump|\bVM (?:Exception|execution error)|\bEVM ?error/i;
const isExecutionFailure = (reply: Extract<RpcReply, { ok: false }>) =>
  reply.code === 3 || EXECUTION_FAILURE.test(reply.message);

export class EvmConnector {
  constructor(
    private readonly chain: ChainConfig,
    private readonly transport: typeof fetch = createRpcTransport([chain]),
  ) {}

  private async rpc(method: string, params: unknown[]): Promise<unknown> {
    return this.withRetry(async () => {
      const reply = await this.rpcOnce(method, params);
      if (!reply.ok) throw new RpcFailure();
      return reply.result;
    });
  }
  /** eth_call where execution failure is a valid outcome. Such failures are deterministic and not retried. */
  private async probe(params: unknown[]): Promise<ProbeResult> {
    const reply = await this.withRetry(async () => {
      const value = await this.rpcOnce('eth_call', params);
      if (!value.ok && !isExecutionFailure(value)) throw new RpcFailure();
      return value;
    });
    return reply.ok
      ? { outcome: 'returned', data: HexData.parse(reply.result) as Hex }
      : { outcome: 'reverted' };
  }
  private async withRetry<T>(action: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await action();
      } catch (error) {
        if (attempt >= 2) throw error;
        await new Promise((resolve) => setTimeout(resolve, 100 * 2 ** attempt));
      }
    }
  }
  private async rpcOnce(method: string, params: unknown[]): Promise<RpcReply> {
    try {
      const response = await this.transport(this.chain.rpcUrl, {
        method: 'POST',
        redirect: 'error',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok || !response.body) throw new RpcFailure();
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw new RpcFailure();
        }
        chunks.push(value);
      }
      const payload = z
        .object({
          jsonrpc: z.literal('2.0'),
          id: z.literal(1),
          // Optional: JSON-RPC error replies carry no result; success requires it (checked below).
          result: z.unknown().optional(),
          error: z
            .object({ code: z.number().int().optional(), message: z.string().max(4096).optional() })
            .optional(),
        })
        .parse(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      // The upstream message is used only for revert classification and is never surfaced.
      if (payload.error !== undefined)
        return {
          ok: false,
          code: payload.error.code ?? null,
          message: payload.error.message ?? '',
        };
      if (!Object.hasOwn(payload, 'result')) throw new RpcFailure();
      return { ok: true, result: payload.result };
    } catch {
      throw new RpcFailure();
    } // Never expose credential-bearing provider URLs or upstream errors.
  }

  /** Structure discovery port; every read is pinned to the snapshot's canonical block hash. */
  private structureReader(blockHash: string): StructureReader {
    const pinned = { blockHash, requireCanonical: true };
    return {
      storage: async (target, slot) =>
        StorageWord.parse(await this.rpc('eth_getStorageAt', [target, slot, pinned])),
      code: async (target) => HexData.parse(await this.rpc('eth_getCode', [target, pinned])) as Hex,
      call: (target, data) => this.probe([{ to: target, data }, pinned]),
    };
  }

  async isCanonical(observation: Observation): Promise<boolean> {
    try {
      if (
        BigInt(HexQuantity.parse(await this.rpc('eth_chainId', []))) !== BigInt(this.chain.chainId)
      )
        throw new RpcFailure('Provider chain does not match configured chain');
      for (const context of [
        observation,
        ...(observation.signature ? [observation.signature] : []),
      ]) {
        const block = Block.parse(
          await this.rpc('eth_getBlockByNumber', [context.blockNumber, false]),
        );
        if (block.number !== context.blockNumber) throw new RpcFailure();
        if (block.hash.toLowerCase() !== context.blockHash.toLowerCase()) return false;
      }
      return true;
    } catch (error) {
      if (error instanceof RpcFailure) throw error;
      throw new RpcFailure();
    }
  }

  async observe(
    inputAddress: string,
    options: { transactionHash?: string; adapter?: 'ownable-erc20' } = {},
  ): Promise<Observation> {
    const address = Address.parse(inputAddress);
    try {
      const chainId = BigInt(HexQuantity.parse(await this.rpc('eth_chainId', [])));
      if (chainId !== BigInt(this.chain.chainId))
        throw new RpcFailure('Provider chain does not match configured chain');
      const block = Block.parse(await this.rpc('eth_getBlockByNumber', ['finalized', false]));
      const [rawBalance, rawNonce, rawCode] = await Promise.all([
        this.rpc('eth_getBalance', [address, { blockHash: block.hash, requireCanonical: true }]),
        this.rpc('eth_getTransactionCount', [
          address,
          { blockHash: block.hash, requireCanonical: true },
        ]),
        this.rpc('eth_getCode', [address, { blockHash: block.hash, requireCanonical: true }]),
      ]);
      const balance = HexQuantity.parse(rawBalance);
      const nonce = HexQuantity.parse(rawNonce);
      const code = HexData.parse(rawCode);
      let signature;
      if (options.transactionHash) {
        const hash = Hash.parse(options.transactionHash);
        signature = await verifyTransaction(
          await this.rpc('eth_getTransactionByHash', [hash]),
          await this.rpc('eth_getTransactionReceipt', [hash]),
          this.chain.chainId,
          address,
          hash,
        );
        if (BigInt(signature.blockNumber) > BigInt(block.number))
          throw new RpcFailure('Transaction is not finalized');
        const txBlock = Block.parse(
          await this.rpc('eth_getBlockByNumber', [signature.blockNumber, false]),
        );
        if (txBlock.hash !== signature.blockHash)
          throw new RpcFailure('Transaction block is not canonical');
      }
      let token;
      if (options.adapter) {
        if (code === '0x')
          throw new RpcFailure('Selected token adapter requires contract bytecode');
        token = await observeToken(async (data) =>
          HexData.parse(
            await this.rpc('eth_call', [
              { to: address, data },
              { blockHash: block.hash, requireCanonical: true },
            ]),
          ),
        );
      }
      const structure = await discoverAccountStructure(
        this.structureReader(block.hash),
        address as Hex,
        code as Hex,
      );
      const after = Block.parse(await this.rpc('eth_getBlockByNumber', [block.number, false]));
      if (after.hash !== block.hash || after.number !== block.number)
        throw new RpcFailure('Canonical block changed during collection; retry the assessment');
      return Observation.parse({
        chainId: this.chain.chainId,
        address,
        blockNumber: block.number,
        blockHash: block.hash,
        blockTimestamp: block.timestamp,
        balanceWei: BigInt(balance).toString(),
        transactionCount: BigInt(nonce).toString(),
        code,
        source: `configured-rpc:${this.chain.chainId}`,
        observedAt: new Date().toISOString(),
        finality: 'finalized',
        parserVersion: 'evm-snapshot/1.0.0',
        ...(signature ? { signature } : {}),
        ...(token ? { token } : {}),
        ...(structure ? { structure } : {}),
        ...(this.chain.demonstration ? { demonstration: true } : {}),
      });
    } catch (error) {
      if (error instanceof RpcFailure) throw error;
      throw new RpcFailure();
    }
  }
}
