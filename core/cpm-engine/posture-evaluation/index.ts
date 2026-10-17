import type {
  Assessment,
  Finding,
  Observation,
} from '../../../packages/domain-models/src/index.js';

export function evaluatePosture(observation: Observation, hash: string): Assessment['posture'] {
  const findings: Finding[] = [
    {
      ruleId: 'CV-WALLET-001',
      ruleVersion: '1.0.0',
      severity: 'info',
      confidence: 'unknown',
      title: 'Authorization scheme needs discovery',
      rationale:
        'Read-only account state does not establish the active signing policy or underlying key custody.',
      evidenceHash: hash,
    },
  ];
  if (observation.code !== '0x')
    findings.push({
      ruleId: 'CV-WALLET-002',
      ruleVersion: '1.0.0',
      severity: 'info',
      confidence: 'observed',
      title: 'Code-bearing account',
      rationale:
        'Non-empty bytecode was returned. Contract, proxy and delegated-account semantics have not been analyzed.',
      evidenceHash: hash,
    });
  if (observation.signature)
    findings.push({
      ruleId: 'CV-QUANTUM-001',
      ruleVersion: '1.0.0',
      severity: 'medium',
      confidence: 'observed',
      title: 'Classical transaction signature verified',
      evidenceHash: hash,
      rationale:
        'A supplied finalized transaction verifies under secp256k1 ECDSA. This signature dependency requires quantum migration planning; it does not establish current compromise or the account’s complete authorization policy.',
    });
  if (observation.token)
    findings.push({
      ruleId: 'CV-TOKEN-001',
      ruleVersion: '1.0.0',
      severity: 'info',
      confidence: 'observed',
      title: 'Token owner accessor observed',
      evidenceHash: hash,
      rationale:
        'The selected ownable ERC20 adapter read owner(), totalSupply() and decimals(). Accessor responses do not prove mint/burn permissions, proxy implementation, reserve backing or stablecoin identity.',
    });
  return { status: 'needs-review', rulepack: 'wallet-baseline/0.1', findings };
}
