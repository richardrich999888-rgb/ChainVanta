import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';

export function report(client: Pick<ChainVantaClient, 'get'>, assessmentId: string) {
  return client.get(assessmentId);
}
