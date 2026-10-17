import { describe, expect, it } from 'vitest';
import { canonicalize, evidenceHash } from '../../core/evidence-engine/evidence-hashing/index.js';
import { authorize, TenantKeys } from '../../core/tenant-authorization/src/index.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { ScanRequest } from '../../packages/domain-models/src/index.js';
import {
  KEY_A,
  TENANT_A,
  observation,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';

describe('Evidence and conservative analysis', () => {
  it('hashes independent of object key order and detects a changed value', () => {
    expect(evidenceHash({ a: 1, b: [2, 3] })).toBe(evidenceHash({ b: [2, 3], a: 1 }));
    expect(evidenceHash({ a: 2 })).not.toBe(evidenceHash({ a: 1 }));
    expect(() => canonicalize({ a: undefined })).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
  });
  it('does not infer ECDSA, public key exposure, or quantum safety from a nonce', () => {
    const assessment = assessWallet(TENANT_A, { ...observation, transactionCount: '100' });
    expect(assessment.cbom.components[0]?.algorithm).toBe('unknown');
    expect(assessment.qbom.status).toBe('unknown');
    expect(
      assessment.posture.findings.every(
        (finding) => finding.evidenceHash === assessment.evidenceHash,
      ),
    ).toBe(true);
  });
  it('does not treat arbitrary code as a verified smart contract wallet', () => {
    const assessment = assessWallet(TENANT_A, { ...observation, code: '0xef0100' });
    expect(assessment.assetKind).toBe('code-bearing-account');
    expect(assessment.posture.findings).toHaveLength(2);
    expect(assessment.cbom.components[0]?.confidence).toBe('unknown');
  });
  it('rejects a caller-supplied tenant, RPC URL, invalid address or fractional chain', () => {
    for (const extra of [
      { tenantId: TENANT_A },
      { rpcUrl: 'http://localhost' },
      { chainId: 1.2 },
      { address: '0x1234' },
    ])
      expect(
        ScanRequest.safeParse({ address: observation.address, chainId: 1, ...extra }).success,
      ).toBe(false);
  });
  it('derives the tenant only from its unique credential', () => {
    expect(authorize(`Bearer ${KEY_A}`, testConfig.tenantKeys)).toBe(TENANT_A);
    expect(authorize(`Bearer ${KEY_A}x`, testConfig.tenantKeys)).toBeNull();
    expect(authorize(undefined, testConfig.tenantKeys)).toBeNull();
    expect(TenantKeys.safeParse([testConfig.tenantKeys[0], testConfig.tenantKeys[0]]).success).toBe(
      false,
    );
  });
});
