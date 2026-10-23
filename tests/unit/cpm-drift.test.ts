import { describe, it, expect } from 'vitest';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { comparePosture } from '../../core/cpm-engine/drift-detection/index.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { observation, TENANT_A, ADDRESS } from '../../packages/test-fixtures/src/fixtures.js';
describe('Evidence-aware drift', () => {
  it('records owner accessor changes with both assessment and evidence identifiers', () => {
    const token = {
      adapter: 'ownable-erc20/1.0.0' as const,
      owner: ADDRESS,
      totalSupply: '10',
      decimals: 6,
      calls: Array.from({ length: 3 }, () => ({ data: '0x', result: '0x' })),
      limitation: 'Accessor evidence only',
    };
    const a = evaluateCpm(
      assessWallet(TENANT_A, { ...observation, code: '0x6000', token }),
      defaultPolicy,
    );
    const b = evaluateCpm(
      assessWallet(TENANT_A, {
        ...observation,
        code: '0x6000',
        token: { ...token, owner: `0x${'22'.repeat(20)}` },
      }),
      defaultPolicy,
    );
    const changes = comparePosture(a, b);
    const owner = changes.find((e) => e.type === 'CONTRACT_AUTHORITY_CHANGED')!;
    expect(owner.confidence).toBe('observed');
    expect(owner.evidenceReferences).toHaveLength(2);
    expect(owner.previousAssessmentId).toBe(a.assessmentId);
    expect(comparePosture(a, b)).toEqual(changes);
    const missing = evaluateCpm(assessWallet(TENANT_A, observation), defaultPolicy);
    expect(comparePosture(b, missing).some((e) => e.type === 'CONTRACT_AUTHORITY_CHANGED')).toBe(
      false,
    );
    expect(
      comparePosture(b, missing).find((e) => e.type === 'EVIDENCE_COVERAGE_CHANGED')?.confidence,
    ).toBe('incomplete');
  });
  it('does not equate a removed algorithm or a disabled policy with remediation', () => {
    const a = evaluateCpm(assessWallet(TENANT_A, observation), defaultPolicy);
    const b = {
      ...a,
      id: `sha256:${'b'.repeat(64)}`,
      observedAlgorithms: ['ECDSA-secp256k1'],
      quantumExposure: 'exposed' as const,
    };
    const changes = comparePosture(b, a);
    expect(changes.find((e) => e.type === 'ALGORITHM_NO_LONGER_OBSERVED')?.confidence).toBe(
      'incomplete',
    );
    const disabled = evaluateCpm(assessWallet(TENANT_A, observation), {
      ...defaultPolicy,
      version: '2.0.0',
      enabled: false,
    });
    expect(comparePosture(a, disabled).some((e) => e.type === 'POLICY_REMEDIATED')).toBe(false);
  });
});
