import { describe, expect, it } from 'vitest';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { toCycloneDx } from '../../core/cbom-engine/exporters/cyclonedx.js';
import type { TransactionDiscovery } from '../../packages/domain-models/src/index.js';
import { ADDRESS, TENANT_A, observation } from '../../packages/test-fixtures/src/fixtures.js';

const discovery = (overrides: Partial<TransactionDiscovery>): TransactionDiscovery => ({
  method: 'nonce-bisection/1.0.0',
  accountNonce: '1',
  outcome: 'found',
  blockNumber: '0x6',
  transactionHash: null,
  transactionType: null,
  authorization: null,
  probes: [{ blockNumber: '0x6', nonce: '1' }],
  ...overrides,
});
const assess = (d: TransactionDiscovery) =>
  assessWallet(TENANT_A, { ...observation, discovery: d });
const ids = (a: ReturnType<typeof assess>) => a.posture.findings.map((f) => f.ruleId);

describe('discovery-aware intelligence', () => {
  it('treats a recovered EIP-7702 authorization as an observed secp256k1 signature', () => {
    const a = assess(
      discovery({
        outcome: 'authorization-signature',
        authorization: {
          transactionHash: `0x${'09'.repeat(32)}`,
          nonce: '0',
          chainId: '1',
          delegate: `0x${'cc'.repeat(20)}`,
          authority: ADDRESS,
        },
      }),
    );
    expect(a.cbom.components).toContainEqual(
      expect.objectContaining({
        algorithm: 'ECDSA-secp256k1',
        confidence: 'observed',
        evidenceRefs: [a.evidenceHash],
      }),
    );
    expect(a.qbom.status).toBe('classical-signature-observed');
    expect(ids(a)).toContain('CV-QUANTUM-002');
    // CPM picks up the observed algorithm, so drift tracks it.
    expect(evaluateCpm(a, defaultPolicy).observedAlgorithms).toEqual(['ECDSA-secp256k1']);
    expect(toCycloneDx(a).components[0]?.cryptoProperties.algorithmProperties.primitive).toBe(
      'signature',
    );
  });

  it('reports nonce 0 as observed and claims nothing about off-chain signatures', () => {
    const a = assess(discovery({ outcome: 'no-sent-transactions', accountNonce: '0', probes: [] }));
    const finding = a.posture.findings.find((f) => f.ruleId === 'CV-WALLET-004');
    expect(finding).toMatchObject({ confidence: 'observed', severity: 'info' });
    expect(finding?.rationale).toContain('Off-chain signatures');
    expect(a.qbom.status).toBe('unknown');
  });

  it('marks unverifiable outcomes unknown without inventing a signature', () => {
    for (const outcome of ['unsupported-transaction-type', 'no-matching-transaction'] as const) {
      const a = assess(
        discovery({
          outcome,
          ...(outcome === 'unsupported-transaction-type'
            ? { transactionHash: `0x${'07'.repeat(32)}`, transactionType: '0x3' }
            : {}),
        }),
      );
      expect(a.posture.findings.find((f) => f.ruleId === 'CV-WALLET-005')?.confidence).toBe(
        'unknown',
      );
      expect(a.qbom.status).toBe('unknown');
      expect(a.cbom.components.every((c) => c.algorithm === 'unknown')).toBe(true);
    }
  });

  it('adds no findings for not-applicable discovery', () => {
    expect(ids(assess(discovery({ outcome: 'not-applicable', probes: [] })))).toEqual([
      'CV-WALLET-001',
    ]);
  });
});
