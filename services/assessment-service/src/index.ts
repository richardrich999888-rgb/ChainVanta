import { randomUUID } from 'node:crypto';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';
import { HttpException } from '@nestjs/common';
import {
  EvmConnector,
  type ChainConfig,
} from '../../../connectors/blockchains/ethereum/src/index.js';
import type { ScanInput } from '../../../packages/domain-models/src/index.js';
import { assessWallet } from '../../../modules/01-wallet-intelligence/src/assessment/index.js';
import type { Repository } from '../../inventory-service/src/repository.js';

export class AssessmentService {
  private active = new Set<string>();
  constructor(
    readonly repository: Repository,
    readonly chains: ChainConfig[],
    private readonly transport: typeof fetch = fetch,
  ) {}
  async scan(tenantId: string, input: ScanInput, key: string = randomUUID(), actor = 'internal') {
    const requestHash = evidenceHash(input);
    const replay = await this.repository.replay?.(tenantId, key, requestHash);
    if (replay) return replay;
    const chain = this.chains.find((value) => value.chainId === input.chainId);
    if (!chain) throw new HttpException('Chain is not configured', 400);
    if (this.active.has(tenantId) || this.active.size >= 8)
      throw new HttpException('Assessment capacity reached; retry shortly', 429);
    this.active.add(tenantId);
    try {
      const observation = await new EvmConnector(chain, this.transport).observe(
        input.address,
        input,
      );
      const assessment = assessWallet(tenantId, observation);
      if (this.repository.saveOnce)
        return await this.repository.saveOnce(assessment, key, requestHash, actor);
      await this.repository.save(assessment);
      return assessment;
    } finally {
      this.active.delete(tenantId);
    }
  }
}
