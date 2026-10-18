import type { Assessment } from '../../../packages/domain-models/src/index.js';
import type { CpmPolicy, PostureSnapshot } from '../../../packages/domain-models/src/cpm.js';
import { ruleHash } from '../rule-versioning/index.js';

export function evaluateRules(a: Assessment, policy: CpmPolicy): PostureSnapshot['evaluations'] {
  return policy.rules
    .filter((r) => policy.enabled && r.enabled)
    .map((rule) => {
      let result: PostureSnapshot['evaluations'][number]['result'] = 'unknown';
      let rationale = 'This evidence does not establish the required property.';
      let confidence: PostureSnapshot['confidence'] = 'unknown';
      const signature = !!a.observation.signature;
      switch (rule.kind) {
        case 'quantum-signature':
        case 'migration-required':
          if (signature) {
            result = 'violation';
            confidence = 'observed';
            rationale =
              'Verified secp256k1 ECDSA dependency is vulnerable to a sufficiently capable quantum computer. This does not establish present exploitability, key compromise or a migration date.';
          }
          break;
        case 'missing-evidence':
          result = signature ? 'satisfied' : 'violation';
          confidence = 'observed';
          rationale = signature
            ? 'Supported finalized transaction evidence is present.'
            : 'No supported transaction was supplied; public-key exposure remains unobserved.';
          break;
        case 'signature-format':
          result = signature ? 'satisfied' : 'unknown';
          confidence = signature ? 'observed' : 'unknown';
          rationale = signature
            ? 'The existing verifier accepted the supplied EVM transaction format.'
            : 'Unsupported formats fail collection; no signature format can be inferred from an address.';
          break;
        case 'unknown-algorithm':
        case 'inventory-completeness':
          rationale =
            'Account authorization is incomplete. Application, transport and consensus domains remain unknown.';
          break;
        case 'authority-concentration':
          rationale = a.observation.token
            ? 'owner() accessor evidence exists but does not prove complete authorization or concentration.'
            : 'No verified authority relationships are available.';
          break;
        case 'key-lifecycle':
          rationale = 'No custody, rotation or revocation metadata is available.';
          break;
        case 'policy-exception':
          result = 'not_applicable';
          rationale =
            'Exceptions are a time-dependent lifecycle projection; original policy results remain immutable.';
          break;
        case 'migration-verification':
          rationale =
            'Use a scoped migration assessment and later evidence to verify defined properties.';
          break;
      }
      const available = {
        'account-state': true,
        'transaction-signature': signature,
        'owner-accessor': !!a.observation.token,
        custody: false,
        'migration-verification': false,
      };
      const missing = rule.evidenceRequirements.filter((requirement) => !available[requirement]);
      // Absence is itself evidence for the missing-transaction rule. Other unmet
      // declared requirements cannot be treated as a satisfied or observed rule.
      if (
        result !== 'not_applicable' &&
        missing.some(
          (requirement) =>
            !(rule.kind === 'missing-evidence' && requirement === 'transaction-signature'),
        )
      ) {
        result = 'unknown';
        confidence = 'unknown';
        rationale = `Required evidence is unavailable: ${missing.join(', ')}. No satisfying conclusion can be drawn.`;
      }
      if (!policy.assetKinds.includes(a.assetKind)) {
        result = 'not_applicable';
        confidence = 'unknown';
        rationale = 'Asset kind is outside this policy scope.';
      }
      return {
        ruleId: rule.id,
        ruleHash: ruleHash(rule),
        result,
        confidence,
        rationale,
        evidenceReferences: [a.evidenceHash],
      };
    });
}
