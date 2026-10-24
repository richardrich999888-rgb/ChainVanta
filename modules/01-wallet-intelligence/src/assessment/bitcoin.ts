import { randomUUID } from 'node:crypto';
import {
  BitcoinAssessment,
  BitcoinObservation,
} from '../../../../packages/domain-models/src/bitcoin.js';
import { evidenceHash } from '../../../../core/evidence-engine/evidence-hashing/index.js';
import { buildBitcoinCbom } from '../../../../core/cbom-engine/generators/bitcoin.js';
import { buildBitcoinQbom } from '../../../../core/qbom-engine/quantum-risk-rules/bitcoin.js';
import { evaluateBitcoinPosture } from '../../../../core/cpm-engine/posture-evaluation/bitcoin.js';
import { buildBitcoinTrustGraph } from '../../../../core/trust-graph-engine/graph-builders/bitcoin.js';

/** Builds a Bitcoin assessment from a validated observation. Deterministic apart from id/time. */
export function assessBitcoin(tenantId: string, input: BitcoinObservation): BitcoinAssessment {
  const observation = BitcoinObservation.parse(input);
  const hash = evidenceHash(observation);
  return BitcoinAssessment.parse({
    schemaVersion: '0.1',
    kind: 'bitcoin',
    id: randomUUID(),
    tenantId,
    createdAt: new Date().toISOString(),
    observation,
    evidenceHash: hash,
    assetKind: observation.target.kind === 'address' ? 'bitcoin-address' : 'bitcoin-public-key',
    cbom: buildBitcoinCbom(observation, hash),
    qbom: buildBitcoinQbom(observation),
    posture: evaluateBitcoinPosture(observation, hash),
    trustGraph: buildBitcoinTrustGraph(observation, hash),
    limitations: [
      'UTXO set reported by the configured Bitcoin Core node; no independent consensus verification. Bitcoin has no finality.',
      'Spend history is not indexed: key reuse is established only from an explicitly supplied confirmed transaction.',
      'Hash-protected means the key is not in output scripts; it does not rule out off-chain disclosure or unindexed spends.',
      'Script-hash targets (P2SH, P2WSH) reveal their script only when spent; taproot script paths are not visible.',
      'Response size limits apply: very large UTXO sets fail the scan rather than being truncated.',
    ],
  });
}
