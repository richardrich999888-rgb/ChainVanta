import { randomUUID } from 'node:crypto';
import { evidenceHash } from '../../../core/evidence-engine/evidence-hashing/index.js';
import { HttpException } from '@nestjs/common';
import {
  EvmConnector,
  type ChainConfig,
} from '../../../connectors/blockchains/ethereum/src/index.js';
import { canonicalAssetId, type ScanInput } from '../../../packages/domain-models/src/index.js';
import { assessWallet } from '../../../modules/01-wallet-intelligence/src/assessment/index.js';
import type { Repository } from '../../inventory-service/src/repository.js';
import type { CpmRepository } from '../../inventory-service/src/cpm-repository.js';

export class AssessmentService {
  private active = new Set<string>();
  constructor(
    readonly repository: Repository,
    readonly chains: ChainConfig[],
    private readonly transport: typeof fetch = fetch,
    private readonly cpm?: CpmRepository,
  ) {}
  async scan(tenantId: string, input: ScanInput, key: string = randomUUID(), actor = 'internal') {
    const requestHash = evidenceHash(input);
    const replay = await this.repository.replay?.(tenantId, key, requestHash);
    if (replay) {
      await this.cpm?.assess(tenantId, replay.id, undefined, actor);
      return replay;
    }
    const chain = this.chains.find((value) => value.chainId === input.chainId);
    if (!chain) throw new HttpException('Chain is not configured', 400);
    if (this.active.has(tenantId) || this.active.size >= 8)
      throw new HttpException('Assessment capacity reached; retry shortly', 429);
    this.active.add(tenantId);
    try {
      const connector = new EvmConnector(chain, this.transport);
      const previous = await this.cpm?.latestValidAssessment(
        tenantId,
        canonicalAssetId(input.chainId, input.address),
      );
      if (previous && !(await connector.isCanonical(previous.observation))) {
        await this.cpm!.invalidate(
          tenantId,
          previous,
          'Finalized block hash changed at the configured provider',
        );
        throw new HttpException('Canonicality changed; retry collection', 502);
      }
      const observation = await connector.observe(input.address, input);
      if (previous && BigInt(observation.blockNumber) < BigInt(previous.observation.blockNumber))
        throw new HttpException('Finalized provider head regressed', 502);
      const assessment = assessWallet(tenantId, observation);
      const stored = this.repository.saveOnce
        ? await this.repository.saveOnce(assessment, key, requestHash, actor)
        : (await this.repository.save(assessment), assessment);
      await this.cpm?.assess(tenantId, stored.id, undefined, actor);
      return stored;
    } finally {
      this.active.delete(tenantId);
    }
  }
}
