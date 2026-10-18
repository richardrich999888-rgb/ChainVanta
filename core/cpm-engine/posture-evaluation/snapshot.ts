import { Assessment, canonicalAssetId } from '../../../packages/domain-models/src/index.js';
import { CpmPolicy, PostureSnapshot } from '../../../packages/domain-models/src/cpm.js';
import { evidenceHash } from '../../evidence-engine/evidence-hashing/index.js';
import { evaluateRules } from '../../policy-engine/evaluators/index.js';
import { policyHash } from '../../policy-engine/rule-versioning/index.js';

export function evaluateCpm(input: Assessment, definition: CpmPolicy): PostureSnapshot {
  const a = Assessment.parse(input),
    policy = CpmPolicy.parse(definition);
  if (evidenceHash(a.observation) !== a.evidenceHash) throw new Error('Evidence integrity failure');
  const evaluations = evaluateRules(a, policy),
    hash = policyHash(policy);
  const observedAlgorithms = [
    ...new Set(
      a.cbom.components
        .filter(
          (c) =>
            c.confidence === 'observed' &&
            c.evidenceRefs?.includes(a.evidenceHash) &&
            c.algorithm !== 'unknown',
        )
        .map((c) => c.algorithm),
    ),
  ].sort();
  // Classification is evidence-derived and cannot be suppressed by a policy override.
  const signature = a.observation.signature;
  return PostureSnapshot.parse({
    id: evidenceHash({ assessment: a.id, policy: hash, evaluator: 'web3-cpm/1.0.0' }),
    assetId: canonicalAssetId(a.observation.chainId, a.observation.address),
    chainId: a.observation.chainId,
    assessmentId: a.id,
    policyId: policy.id,
    policyVersion: policy.version,
    policyHash: hash,
    evaluatorVersion: 'web3-cpm/1.0.0',
    assessedAt: a.createdAt,
    observedAlgorithms,
    quantumExposure: signature ? 'exposed' : 'unknown',
    publicKeyExposure: signature ? 'recoverable-from-verified-signature' : 'not_observed',
    migrationReadiness: 'unknown',
    confidence: signature ? 'observed' : 'unknown',
    findings: evaluations
      .filter((e) => e.result === 'violation' || e.result === 'unknown')
      .map((e) => {
        const rule = policy.rules.find((r) => r.id === e.ruleId)!;
        return {
          ruleId: e.ruleId,
          ruleVersion: policy.version,
          severity: rule.severity,
          confidence: e.confidence,
          title:
            e.result === 'unknown' && rule.kind === 'quantum-signature'
              ? 'Transaction signature exposure is unknown'
              : e.result === 'unknown' && rule.kind === 'migration-required'
                ? 'Signature migration requirements are unknown'
                : rule.title,
          rationale: e.rationale,
          evidenceHash: a.evidenceHash,
        };
      }),
    evaluations,
    evidenceReferences: [a.evidenceHash],
    coverage: {
      account: true,
      signature: !!signature,
      owner: !!a.observation.token,
      authorization: false,
      custody: false,
    },
    ...(a.observation.token ? { owner: a.observation.token.owner } : {}),
    ...(signature
      ? {
          signatureType: signature.serializedTransaction.startsWith('0x01')
            ? 'eip2930'
            : signature.serializedTransaction.startsWith('0x02')
              ? 'eip1559'
              : 'legacy',
        }
      : {}),
    dependencies: a.trustGraph.edges
      .filter((e) => ['verified-signature-uses', 'owner-accessor-reports'].includes(e.relation))
      .map((e) => `${e.relation}:${e.to}`)
      .sort(),
    demonstration: a.observation.demonstration ?? false,
    limitations: [
      'Provider-reported finality; no independent consensus verification.',
      'Public-key recoverability applies to the verified supplied transaction only.',
      'Unknown authorization and custody prevent a quantum-safety or migration-compatibility conclusion.',
    ],
  });
}
