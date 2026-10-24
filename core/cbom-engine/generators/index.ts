import { evidenceHash } from '../../evidence-engine/evidence-hashing/index.js';
import {
  safePolicy,
  structureFacts,
  type StructureFacts,
} from '../../cryptographic-inventory/algorithm-classification/account-structure.js';
import { tokenAuthorityFacts } from '../../cryptographic-inventory/algorithm-classification/token-authority.js';
import type { Assessment, Observation } from '../../../packages/domain-models/src/index.js';

type Component = Assessment['cbom']['components'][number];
const SECP256K1 = 'ECDSA-secp256k1';

/** Basis for the account-authorization component that remains unknown. */
function unknownAuthorizationBasis(observation: Observation, facts: StructureFacts): string {
  if (observation.code === '0x')
    return 'No code at the observed block. Address, nonce and balance do not prove a signing scheme or public-key exposure.';
  const notes: string[] = [];
  if (facts.delegate)
    notes.push(`EIP-7702 delegate ${facts.delegate} may add authorization paths; not analyzed.`);
  if (facts.safe)
    notes.push(
      `Safe-compatible ${safePolicy(facts.safe)} threshold reported; modules ${
        facts.safe.modulesComplete ? `(${facts.safe.modules.length})` : '(unknown)'
      } can execute without owner signatures.`,
    );
  if (facts.eip1967?.implementation || facts.minimalProxy)
    notes.push('Proxy implementation logic determines authorization; not analyzed.');
  if (facts.erc4337)
    notes.push('ERC-4337 entryPoint() reported; account validation logic is vendor-specific.');
  return notes.length
    ? `Bytecode is present. ${notes.join(' ')}`
    : 'Bytecode is present. Signer schemes, delegated code and upgrade paths require additional analysis.';
}

/** Components implied by account structure. Only protocol-level consequences are claimed. */
function structureComponents(facts: StructureFacts, hash: string): Component[] {
  const components: Component[] = [];
  if (facts.delegate)
    components.push({
      algorithm: SECP256K1,
      purpose: 'account authorization (EIP-7702 delegated account key)',
      domain: 'account-authorization',
      confidence: 'observed',
      // EIP-7702 installs a designator only from a secp256k1-signed authorization, and delegation
      // does not revoke the account key, which can still sign transactions and re-delegate.
      basis: `EIP-7702 delegation designator to ${facts.delegate} is present. Designators are installed only by secp256k1-signed authorizations, and the account key remains a valid signer.`,
      evidenceRefs: [hash],
    });
  const safe = facts.safe;
  if (safe) {
    const { 'no-code': noCode, 'eip-7702-delegated': delegated } = facts.ownerCounts;
    if (noCode)
      components.push({
        algorithm: SECP256K1,
        purpose: `Safe owner authorization (${noCode} owner${noCode === 1 ? '' : 's'} without code)`,
        domain: 'account-authorization',
        // Inferred: relies on the contract enforcing Safe signature rules, which accessors
        // cannot prove, and on standard EVM account semantics for addresses without code.
        confidence: 'inferred',
        basis: `Safe-compatible ${safePolicy(safe)} policy. Owners without code can currently approve only with ECDSA secp256k1 signatures or approveHash transactions under Safe signature rules.`,
        evidenceRefs: [hash],
      });
    if (delegated)
      components.push({
        algorithm: SECP256K1,
        purpose: `Safe owner authorization (${delegated} EIP-7702 delegated owner${delegated === 1 ? '' : 's'})`,
        domain: 'account-authorization',
        confidence: 'inferred',
        basis: `Safe-compatible ${safePolicy(safe)} policy. Delegated owners retain secp256k1 keys accepted by Safe ECDSA signature rules.`,
        evidenceRefs: [hash],
      });
    const opaque = facts.ownerCounts.contract + facts.ownerCounts['not-checked'];
    if (opaque)
      components.push({
        algorithm: 'unknown',
        purpose: `Safe owner authorization (${opaque} contract or unchecked owner${opaque === 1 ? '' : 's'})`,
        domain: 'account-authorization',
        confidence: 'unknown',
        basis:
          'Contract owners authorize through EIP-1271 logic; owners beyond the code-read limit were not classified.',
      });
  }
  return components;
}

/** Token administration keys. Only single-key holders imply an algorithm; contracts stay unknown. */
function tokenAuthorityComponents(observation: Observation, hash: string): Component[] {
  const facts = tokenAuthorityFacts(observation);
  if (!facts) return [];
  const components: Component[] = facts.holders
    .filter((h) => h.kind === 'no-code' || h.kind === 'eip-7702-delegated')
    .map((h) => ({
      algorithm: SECP256K1,
      purpose: `token administration (${h.roles.join(', ')} held by ${h.address})`,
      domain: 'token-administration' as const,
      // Inferred: the role claim comes from accessors; an address without code (or a delegated
      // account) can only originate transactions with a secp256k1 signature.
      confidence: 'inferred' as const,
      basis: `Token accessors report ${h.address} as ${h.roles.join(', ')}; it ${
        h.kind === 'no-code' ? 'has no code' : 'is EIP-7702 delegated'
      }, so exercising the role requires a secp256k1 ECDSA signature from its key.`,
      evidenceRefs: [hash],
    }));
  const opaque = facts.holders.filter((h) => h.kind === 'contract' || h.kind === 'not-checked');
  if (opaque.length)
    components.push({
      algorithm: 'unknown',
      purpose: `token administration (${opaque.length} contract or unchecked holder${opaque.length === 1 ? '' : 's'})`,
      domain: 'token-administration',
      confidence: 'unknown',
      basis:
        'Contract holders (multisigs, timelocks, governors) authorize through their own logic, which was not analyzed.',
    });
  return components;
}

/** Builds the native CBOM. Unknowns stay explicit; structure adds only protocol-implied facts. */
export function buildCbom(observation: Observation): Assessment['cbom'] {
  const hash = evidenceHash(observation);
  const facts = structureFacts(observation);
  return {
    format: 'chainvanta-cbom/0.1',
    components: [
      ...(observation.signature
        ? [
            {
              algorithm: SECP256K1,
              purpose: 'transaction signature',
              domain: 'transaction-signature' as const,
              confidence: 'observed' as const,
              basis: `Verified transaction ${observation.signature.hash}; recovered sender matches the observed account.`,
              evidenceRefs: [hash],
            },
          ]
        : []),
      ...structureComponents(facts, hash),
      ...tokenAuthorityComponents(observation, hash),
      ...(observation.discovery?.authorization
        ? [
            {
              algorithm: SECP256K1,
              purpose: 'account authorization (EIP-7702 authorization signature)',
              domain: 'account-authorization' as const,
              confidence: 'observed' as const,
              basis: `Recovered the signer of the EIP-7702 authorization in transaction ${observation.discovery.authorization.transactionHash}; it matches the observed account.`,
              evidenceRefs: [hash],
            },
          ]
        : []),
      {
        algorithm: 'unknown',
        purpose: 'account authorization',
        confidence: 'unknown',
        basis: unknownAuthorizationBasis(observation, facts),
      },
    ],
  };
}
