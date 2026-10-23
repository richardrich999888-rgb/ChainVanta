import { signedTransactionFixture } from '../../packages/test-fixtures/src/transaction.js';
import { verifyTransaction } from '../../modules/01-wallet-intelligence/src/signature-analysis/verify-transaction.js';
import { describe, it, expect } from 'vitest';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { CpmPolicy } from '../../packages/domain-models/src/cpm.js';
import { observation, TENANT_A } from '../../packages/test-fixtures/src/fixtures.js';
describe('CPM versioned evidence evaluation', () => {
  it('never infers safety or public-key exposure from an account address', () => {
    const a = assessWallet(TENANT_A, observation),
      p = evaluateCpm(a, defaultPolicy);
    expect(p.quantumExposure).toBe('unknown');
    expect(p.publicKeyExposure).toBe('not_observed');
    expect(p.migrationReadiness).toBe('unknown');
    expect(p.findings.every((f) => f.evidenceHash === a.evidenceHash)).toBe(true);
    expect(evaluateCpm(a, defaultPolicy)).toEqual(p);
  });
  it('retains historical classifications under explicit policy versions', () => {
    const a = assessWallet(TENANT_A, observation),
      first = evaluateCpm(a, defaultPolicy);
    const policy = CpmPolicy.parse({
      ...defaultPolicy,
      version: '2.0.0',
      rules: defaultPolicy.rules.map((r) => ({ ...r, severity: 'high' })),
    });
    const second = evaluateCpm(a, policy);
    expect(second.id).not.toBe(first.id);
    expect(second.findings[0]?.severity).toBe('high');
    expect(evaluateCpm(a, defaultPolicy)).toEqual(first);
  });
  it('enforces additional policy evidence requirements without suppressing factual exposure', async () => {
    const tx = await signedTransactionFixture();
    const signature = await verifyTransaction(tx.raw, tx.receipt, 1, tx.address, tx.hash);
    const a = assessWallet(TENANT_A, { ...observation, address: tx.address, signature });
    const policy = CpmPolicy.parse({
      ...defaultPolicy,
      version: '1.1.0',
      rules: defaultPolicy.rules.map((rule) =>
        rule.kind === 'signature-format'
          ? { ...rule, evidenceRequirements: ['transaction-signature', 'custody'] }
          : rule,
      ),
    });
    const snapshot = evaluateCpm(a, policy);
    expect(snapshot.evaluations.find((e) => e.ruleId === 'CV-CPM-FORMAT')).toMatchObject({
      result: 'unknown',
      confidence: 'unknown',
    });
    expect(snapshot.quantumExposure).toBe('exposed');
    expect(snapshot.evaluations.find((e) => e.ruleId === 'CV-CPM-EVIDENCE')?.result).toBe(
      'satisfied',
    );
  });
  it('rejects executable configuration and altered evidence', () => {
    expect(CpmPolicy.safeParse({ ...defaultPolicy, script: 'process.exit()' }).success).toBe(false);
    const a = assessWallet(TENANT_A, observation);
    a.observation.balanceWei = '99';
    expect(() => evaluateCpm(a, defaultPolicy)).toThrow('integrity');
  });
});
