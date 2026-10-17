import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';
import { ScanRequest } from '../../../../packages/domain-models/src/index.js';

export function scan(client: Pick<ChainVantaClient, 'assess'>, address?: string, chain?: string) {
  return client.assess(ScanRequest.parse({ address, chainId: Number(chain ?? '1') }));
}
