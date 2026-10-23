import type {
  CpmPolicy,
  PostureSnapshot,
  Remediation,
} from '../../packages/domain-models/src/cpm.js';
export function recommend(
  snapshot: PostureSnapshot,
  policy: CpmPolicy,
  importance: 'normal' | 'high' | 'critical' = 'normal',
): Remediation[] {
  return snapshot.findings.map((f) => {
    const rule = policy.rules.find((r) => r.id === f.ruleId)!;
    const exposed =
      f.confidence === 'observed' &&
      ['quantum-signature', 'migration-required'].includes(rule.kind);
    return {
      assetId: snapshot.assetId,
      snapshotId: snapshot.id,
      ruleId: f.ruleId,
      priority: exposed ? (importance === 'normal' ? 'MEDIUM' : 'HIGH') : 'NEEDS_EVIDENCE',
      dependency: exposed
        ? 'verified-signature-uses:algorithm:ECDSA-secp256k1'
        : 'unverified-authorization',
      rationale: exposed
        ? `Verified transaction-signature dependency; operator importance is ${importance}. Priority is not current exploitability.`
        : 'Evidence is insufficient to assign cryptographic risk priority.',
      evidenceReferences: snapshot.evidenceReferences,
      constraints: [
        'Native EVM transaction signatures cannot be replaced by changing wallet configuration.',
        'Owner accessor edges are not verified authority or TVL evidence.',
        'Custody and protocol compatibility are unknown.',
      ],
      nextAction: rule.remediation,
      verificationRequirements: [
        'Retain the original evidence and policy version.',
        'Collect later finalized evidence and test explicitly defined supported properties.',
        'Missing signatures do not verify quantum migration.',
      ],
    };
  });
}
