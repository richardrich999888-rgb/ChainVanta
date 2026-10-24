import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';
import {
  BitcoinConnector,
  type BitcoinNodeConfig,
} from '../../../connectors/blockchains/bitcoin/src/index.js';
import { InvalidAddress } from '../../../modules/01-wallet-intelligence/src/key-dependencies/bitcoin-codec.js';
import { assessBitcoin } from '../../../modules/01-wallet-intelligence/src/assessment/bitcoin.js';
import type { BitcoinScanInput } from '../../../packages/domain-models/src/bitcoin.js';
import type { PostgresRepository } from '../../inventory-service/src/repository.js';

type BitcoinRepository = Pick<
  PostgresRepository,
  'replayBitcoin' | 'saveBitcoinOnce' | 'listBitcoin' | 'getBitcoin'
>;

/** Orchestrates one-shot Bitcoin assessments: replay, collection, assessment, persistence. */
export class BitcoinAssessmentService {
  /** Bitcoin Core runs one UTXO-set scan at a time per node; refuse instead of queueing. */
  private readonly scanning = new Set<string>();
  constructor(
    readonly repository: BitcoinRepository,
    readonly nodes: BitcoinNodeConfig[],
    private readonly transport?: typeof fetch,
  ) {}

  async scan(
    tenantId: string,
    input: BitcoinScanInput,
    key: string = randomUUID(),
    actor = 'internal',
  ) {
    const requestHash = evidenceHash({ bitcoin: input });
    const replay = await this.repository.replayBitcoin(tenantId, key, requestHash);
    if (replay) return replay;
    const node = this.nodes.find((n) => n.network === input.network);
    if (!node) throw new HttpException('Bitcoin network is not configured', 400);
    if (this.scanning.has(node.network))
      throw new HttpException('A UTXO scan is already running on this node; retry shortly', 429);
    this.scanning.add(node.network);
    try {
      const connector = this.transport
        ? new BitcoinConnector(node, this.transport)
        : new BitcoinConnector(node);
      const observation = await connector.observe(input).catch((error: unknown) => {
        if (error instanceof InvalidAddress)
          throw new HttpException(`Invalid ${input.network} address: ${error.message}`, 400);
        throw error;
      });
      return await this.repository.saveBitcoinOnce(
        assessBitcoin(tenantId, observation),
        key,
        requestHash,
        actor,
      );
    } finally {
      this.scanning.delete(node.network);
    }
  }
}
