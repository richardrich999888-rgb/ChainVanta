import type {
  Assessment,
  Finding,
  Observation,
} from '../../../packages/domain-models/src/index.js';
import {
  safePolicy,
  structureFacts,
} from '../../cryptographic-inventory/algorithm-classification/account-structure.js';
import { tokenAuthorityFacts } from '../../cryptographic-inventory/algorithm-classification/token-authority.js';

/** Findings from transaction discovery. A found transaction is reported via the signature rules. */
function discoveryFindings(observation: Observation, hash: string): Finding[] {
  const outcome = observation.discovery?.outcome;
  if (outcome === 'no-sent-transactions')
    return [
      {
        ruleId: 'CV-WALLET-004',
        ruleVersion: '1.0.0',
        severity: 'info',
        confidence: 'observed',
        title: 'No transactions sent at the observed block',
        rationale:
          'The account nonce is 0, so no on-chain transaction or EIP-7702 authorization from this account exposes its public key. Off-chain signatures (permits, EIP-712 messages) are not observable and may still expose it.',
        evidenceHash: hash,
      },
    ];
  if (outcome === 'authorization-signature')
    return [
      {
        ruleId: 'CV-QUANTUM-002',
        ruleVersion: '1.0.0',
        severity: 'medium',
        confidence: 'observed',
        title: 'Classical EIP-7702 authorization signature verified',
        rationale: `The account signed an EIP-7702 authorization (transaction ${observation.discovery!.authorization!.transactionHash}); its secp256k1 signer was recovered and matches. This signature dependency requires quantum migration planning; it does not establish current compromise or the account's complete authorization policy.`,
        evidenceHash: hash,
      },
    ];
  if (outcome === 'unsupported-transaction-type' || outcome === 'no-matching-transaction')
    return [
      {
        ruleId: 'CV-WALLET-005',
        ruleVersion: '1.0.0',
        severity: 'info',
        confidence: 'unknown',
        title: 'Latest transaction could not be verified',
        rationale:
          outcome === 'unsupported-transaction-type'
            ? `The latest sent transaction ${observation.discovery!.transactionHash} has type ${observation.discovery!.transactionType}, which the verifier does not reconstruct. Its signature was not verified.`
            : `The delegated account's nonce changed in block ${observation.discovery!.blockNumber} without a transaction or authorization it signed, consistent with contract creation by its delegated code. No signature was verified.`,
        evidenceHash: hash,
      },
    ];
  return [];
}

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

/** Findings from token authority discovery. Holder claims are accessor responses (inferred). */
function tokenAuthorityFindings(observation: Observation, hash: string): Finding[] {
  const facts = tokenAuthorityFacts(observation);
  if (!facts) return [];
  const findings: Finding[] = [];
  const add = (finding: Omit<Finding, 'ruleVersion' | 'evidenceHash'>) =>
    findings.push({ ...finding, ruleVersion: '1.0.0', evidenceHash: hash });
  const roleSummary = facts.authority.roles
    .map((r) => `${r.role} (${r.source}): ${r.holders.length ? r.holders.join(', ') : 'none'}`)
    .join('; ');
  add({
    ruleId: 'CV-TOKEN-002',
    severity: 'info',
    confidence: 'inferred',
    title: `Token authorities reported for ${facts.holders.length} address${facts.holders.length === 1 ? '' : 'es'}`,
    rationale: `${roleSummary || 'No standard authority accessor answered.'}. Accessor responses do not prove the contract enforces these roles, and custom roles are not read.`,
  });
  // One finding per rule: finding lifecycle (exceptions, closure) is keyed by rule id.
  const singleKey = facts.singleKeySupplyOrLogic;
  if (singleKey.length)
    add({
      ruleId: 'CV-TOKEN-003',
      severity: 'high',
      confidence: 'inferred',
      title: 'Single secp256k1 key can mint or replace token logic',
      rationale: `${singleKey
        .map(
          (h) =>
            `${h.address} (${h.kind === 'no-code' ? 'no code' : 'EIP-7702 delegated'}) is reported as ${h.roles.join(', ')}`,
        )
        .join(
          '; ',
        )}. Each is one elliptic-curve key, recoverable by a sufficiently capable quantum computer once its public key is exposed, that controls supply or upgrades. Key custody (HSM, MPC) is not observable on-chain.`,
    });
  const { roles, unclassified, nonEnumerable, history } = facts.incomplete;
  if (roles.length || unclassified || nonEnumerable)
    add({
      ruleId: 'CV-TOKEN-004',
      severity: 'medium',
      confidence: 'unknown',
      title: 'Token authority set is incomplete',
      rationale: [
        nonEnumerable ? 'AccessControl is not enumerable; role holders require event history.' : '',
        roles.length ? `Holder sets are not proven complete for: ${roles.join(', ')}.` : '',
        history?.gaps
          ? `Role event history has ${history.gaps} uncovered block range(s) within the request budget.`
          : '',
        history && !history.attested
          ? 'The provider is not attested to serve full log history, so event-derived role sets are not claimed complete.'
          : '',
        unclassified ? `${unclassified} holder(s) were not classified by code.` : '',
      ]
        .filter(Boolean)
        .join(' '),
    });
  if (facts.authority.paused === true)
    add({
      ruleId: 'CV-TOKEN-005',
      severity: 'medium',
      confidence: 'inferred',
      title: 'Token reports paused',
      rationale:
        'paused() returned true at the observed block. Transfers may be blocked; whether pausing covers all functions depends on the implementation.',
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
  findings.push(
    ...structureFindings(observation, hash),
    ...discoveryFindings(observation, hash),
    ...tokenAuthorityFindings(observation, hash),
  );
  return { status: 'needs-review', rulepack: 'wallet-baseline/0.1', findings };
}
