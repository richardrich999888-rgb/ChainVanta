import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';

/** CycloneDX 1.6 CBOM export of one assessment. */
export function cbom(client: Pick<ChainVantaClient, 'cbom'>, assessmentId: string) {
  return client.cbom(assessmentId);
}
