import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';
import { canonicalAssetId } from '../../../../packages/domain-models/src/index.js';
import { AssetId } from '../../../../packages/domain-models/src/cpm.js';

const DEFAULT_CHAIN_ID = 1;

/**
 * Current CPM posture of one asset: `posture <eip155:chain:address>` or `posture <address> [chainId]`.
 * The asset id is validated locally so malformed input never reaches the API.
 */
export function posture(client: Pick<ChainVantaClient, 'posture'>, target: string, chain?: string) {
  if (target.startsWith('eip155:')) {
    if (chain !== undefined) throw new Error('An asset id already includes its chain');
    return client.posture(AssetId.parse(target));
  }
  return client.posture(AssetId.parse(canonicalAssetId(Number(chain ?? DEFAULT_CHAIN_ID), target)));
}
