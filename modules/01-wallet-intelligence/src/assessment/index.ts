import { randomUUID } from 'node:crypto';
import { Observation, type Assessment } from '../../../../packages/domain-models/src/index.js';
import { evidenceHash } from '../../../../core/evidence-engine/evidence-hashing/index.js';
import { buildCbom } from '../../../../core/cbom-engine/generators/index.js';
import { buildQbom } from '../../../../core/qbom-engine/quantum-risk-rules/index.js';
import { evaluatePosture } from '../../../../core/cpm-engine/posture-evaluation/index.js';
import { buildTrustGraph } from '../../../../core/trust-graph-engine/graph-builders/index.js';

export function assessWallet(tenantId: string, input: Observation): Assessment {
  const observation = Observation.parse(input);
  const hash = evidenceHash(observation);
  return {
    schemaVersion: '0.1',
    id: randomUUID(),
    tenantId,
    createdAt: new Date().toISOString(),
    observation,
    evidenceHash: hash,
    assetKind: observation.code === '0x' ? 'no-code-account' : 'code-bearing-account',
    cbom: buildCbom(observation),
    qbom: buildQbom(observation),
    posture: evaluatePosture(observation, hash),
    trustGraph: buildTrustGraph(observation, hash),
    limitations: [
      'Provider-reported finalized snapshot; no independent consensus verification.',
      'Only an explicitly supplied transaction is verified; no exhaustive transaction history, proxy resolution or custody discovery.',
      'CBOM and QBOM are experimental ChainVanta formats, not CycloneDX exports.',
      'Evidence hashing detects content changes; it does not authenticate the provider or prove external timestamping.',
      'One-shot assessment; continuous monitoring and drift detection are planned.',
    ],
  };
}
