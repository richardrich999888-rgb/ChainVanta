import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';

/** Findings with effective lifecycle status for one assessment, or the latest 50 without one. */
export function posture(client: Pick<ChainVantaClient, 'findings'>, assessmentId?: string) {
  return client.findings(assessmentId);
}
