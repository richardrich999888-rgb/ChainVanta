import type { CpmPolicy } from '../../../packages/domain-models/src/cpm.js';
import { evidenceHash } from '../../evidence-engine/evidence-hashing/index.js';
export const policyHash = (policy: CpmPolicy) => evidenceHash(policy);
// A rule's evidence semantics, not its display severity, determine resolution compatibility.
export const ruleHash = (rule: CpmPolicy['rules'][number]) =>
  evidenceHash({
    id: rule.id,
    kind: rule.kind,
    requirements: [...rule.evidenceRequirements].sort(),
  });
