import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';

/** Quantum exposure record of one assessment, with the evidence it is bound to. */
export async function qbom(client: Pick<ChainVantaClient, 'get'>, assessmentId: string) {
  const assessment = await client.get(assessmentId);
  return {
    assessmentId: assessment.id,
    evidenceHash: assessment.evidenceHash,
    qbom: assessment.qbom,
  };
}
