import { EvmConnector, type ChainConfig } from '../../connectors/blockchains/ethereum/src/index.js';
import { canonicalAssetId } from '../../packages/domain-models/src/index.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import type { CpmRepository } from '../inventory-service/src/cpm-repository.js';
import { MonitoringStore } from '../inventory-service/src/monitoring-store.js';
export class CpmWorker {
  readonly jobs: MonitoringStore;
  constructor(
    readonly cpm: CpmRepository,
    readonly chains: ChainConfig[],
    readonly id: string,
    readonly transport: typeof fetch = fetch,
    readonly timeoutMs = 60000,
    concurrency = 2,
    rpcPerMinute = 120,
  ) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000)
      throw new Error('Invalid assessment timeout');
    this.jobs = new MonitoringStore(cpm.policies, concurrency, rpcPerMinute);
  }
  async tick(tenant: string) {
    await this.jobs.enqueueDue(tenant);
    const job = await this.jobs.claim(tenant, this.id);
    if (!job) return false;
    const controller = new AbortController();
    let failure: Parameters<MonitoringStore['fail']>[1] = 'collection_failed',
      calls = 0;
    let timer: ReturnType<typeof setTimeout>;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        failure = 'assessment_timeout';
        controller.abort();
        reject(new Error('Assessment timeout'));
      }, this.timeoutMs);
    });
    const transport: typeof fetch = async (url, init) => {
      controller.signal.throwIfAborted();
      if (++calls > 60 || !(await this.jobs.consumeRpc(job))) {
        failure = 'rpc_budget_exceeded';
        throw new Error('RPC budget exceeded');
      }
      controller.signal.throwIfAborted();
      return this.transport(url, {
        ...init,
        signal: AbortSignal.any([controller.signal, ...(init?.signal ? [init.signal] : [])]),
      });
    };
    const execute = async () => {
      const chain = this.chains.find((c) => c.chainId === job.input.chainId);
      if (!chain) throw new Error('Unconfigured chain');
      const connector = new EvmConnector(chain, transport);
      const previous = await this.cpm.latestValidAssessment(
        tenant,
        canonicalAssetId(job.input.chainId, job.input.address),
      );
      if (previous && !(await connector.isCanonical(previous.observation))) {
        controller.signal.throwIfAborted();
        failure = 'canonicality_changed';
        await this.cpm.invalidate(
          tenant,
          previous,
          'Finalized block hash changed at the configured provider',
        );
        throw new Error('Canonicality changed');
      }
      const observation = await connector.observe(job.input.address, job.input);
      controller.signal.throwIfAborted();
      if (previous && BigInt(observation.blockNumber) < BigInt(previous.observation.blockNumber))
        throw new Error('Finalized provider head regressed');
      const assessment = assessWallet(tenant, observation);
      await this.jobs.complete(job, assessment, async (c) => {
        controller.signal.throwIfAborted();
        await this.cpm.persist(
          c,
          assessment,
          { id: job.policy_id, version: job.policy_version },
          `worker:${this.id}`,
        );
        controller.signal.throwIfAborted();
      });
    };
    try {
      await Promise.race([execute(), timeout]);
    } catch {
      controller.abort();
      await this.jobs.fail(job, failure);
    } finally {
      clearTimeout(timer!);
    }
    return true;
  }
}
