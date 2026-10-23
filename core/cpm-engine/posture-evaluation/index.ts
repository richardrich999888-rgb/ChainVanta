import type {
  Assessment,
  Finding,
  Observation,
} from '../../../packages/domain-models/src/index.js';
import {
  safePolicy,
  structureFacts,
} from '../../cryptographic-inventory/algorithm-classification/account-structure.js';

/** Findings derived from account structure evidence. Each states what the evidence does not prove. */
function structureFindings(observation: Observation, hash: string): Finding[] {
  const facts = structureFacts(observation);
  const findings: Finding[] = [];
  const add = (finding: Omit<Finding, 'ruleVersion' | 'evidenceHash'>) =>
    findings.push({ ...finding, ruleVersion: '1.0.0', evidenceHash: hash });
  if (facts.delegate)
    add({
      ruleId: 'CV-WALLET-003',
      severity: 'medium',
      confidence: 'observed',
      title: 'EIP-7702 delegated account retains secp256k1 authority',
      rationale: `The account delegates execution to ${facts.delegate}. Its secp256k1 key signed the delegation and can still sign transactions and re-delegate, so smart-account features do not remove the elliptic-curve dependency. Delegate code was not analyzed.`,
    });
  if (facts.eip1967?.implementation || facts.eip1967?.beacon)
    add({
      ruleId: 'CV-PROXY-001',
      severity: 'info',
      confidence: 'observed',
      title: 'EIP-1967 proxy slots are set',
      rationale: `Implementation ${facts.eip1967.implementation ?? 'via beacon ' + facts.eip1967.beacon}${
        facts.eip1967.admin ? `, admin ${facts.eip1967.admin}` : ''
      }. Whoever controls upgrades can replace contract logic, including signature verification. ${
        facts.eip1967.implementation && !facts.eip1967.implementationCodeHash
          ? 'The implementation address has no code at the observed block. '
          : ''
      }Upgrade authorization was not analyzed.`,
    });
  if (facts.minimalProxy)
    add({
      ruleId: 'CV-PROXY-002',
      severity: 'info',
      confidence: 'observed',
      title: 'EIP-1167 minimal proxy',
      rationale: `All calls delegate to ${facts.minimalProxy.implementation}. Minimal proxies are not upgradeable; authorization depends on the implementation, which was not analyzed.`,
    });
  if (facts.safe) {
    add({
      ruleId: 'CV-SAFE-001',
      severity: 'info',
      confidence: 'inferred',
      title: `Safe-compatible ${safePolicy(facts.safe)} multisig accessors`,
      rationale: `getOwners() and getThreshold() report ${facts.safe.owners.length} owners with threshold ${facts.safe.threshold}${
        facts.safe.version ? ` (VERSION ${facts.safe.version})` : ''
      }. Accessor responses do not prove the contract enforces Safe signature rules.`,
    });
    if (!facts.safe.modulesComplete || facts.safe.modules.length > 0)
      add({
        ruleId: 'CV-SAFE-002',
        severity: 'medium',
        confidence: facts.safe.modulesComplete ? 'inferred' : 'unknown',
        title: facts.safe.modulesComplete
          ? 'Safe modules can execute without owner signatures'
          : 'Safe module list is incomplete',
        rationale: facts.safe.modulesComplete
          ? `${facts.safe.modules.length} enabled module(s) can execute transactions without the owner threshold. Module authorization was not analyzed.`
          : 'Enabled modules could not be fully enumerated; modules can execute transactions without the owner threshold.',
      });
  }
  if (facts.erc4337)
    add({
      ruleId: 'CV-AA-001',
      severity: 'info',
      confidence: 'inferred',
      title: 'ERC-4337 entry point reported',
      rationale: `entryPoint() returns ${facts.erc4337.entryPoint}${
        facts.erc4337.entryPointHasCode ? '' : ', which has no code at the observed block'
      }. Account validation and signer schemes are vendor-specific and were not analyzed.`,
    });
  return findings;
}

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
  findings.push(...structureFindings(observation, hash));
  return { status: 'needs-review', rulepack: 'wallet-baseline/0.1', findings };
}
