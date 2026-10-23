import { createRpcTransport } from './transport.js';
import { verifyTransaction } from '../../../../modules/01-wallet-intelligence/src/signature-analysis/verify-transaction.js';
import { observeToken } from '../../../../modules/09-stablecoin-assurance/src/privileged-roles/index.js';
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

export class EvmConnector {
  constructor(
    private readonly chain: ChainConfig,
    private readonly transport: typeof fetch = createRpcTransport([chain]),
  ) {}

  private async rpc(method: string, params: unknown[]): Promise<unknown> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.rpcOnce(method, params);
      } catch (error) {
        if (attempt >= 2) throw error;
        await new Promise((resolve) => setTimeout(resolve, 100 * 2 ** attempt));
      }
    }
  }
  private async rpcOnce(method: string, params: unknown[]): Promise<unknown> {
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
          result: z.unknown(),
          error: z.unknown().optional(),
        })
        .parse(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      if (payload.error !== undefined || !Object.hasOwn(payload, 'result')) throw new RpcFailure();
      return payload.result;
    } catch {
      throw new RpcFailure();
    } // Never expose credential-bearing provider URLs or upstream errors.
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
        ...(this.chain.demonstration ? { demonstration: true } : {}),
      });
    } catch (error) {
      if (error instanceof RpcFailure) throw error;
      throw new RpcFailure();
    }
  }
}
