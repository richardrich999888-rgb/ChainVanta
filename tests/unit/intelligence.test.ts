import { expect, it } from 'vitest';
import { generateKeyPair, SignJWT } from 'jose';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, parseTransaction, toHex, encodeFunctionResult, parseAbi } from 'viem';
import { Authenticator } from '../../services/identity-service/auth.js';
import { verifyTransaction } from '../../modules/01-wallet-intelligence/src/signature-analysis/verify-transaction.js';
import { observeToken } from '../../modules/09-stablecoin-assurance/src/privileged-roles/index.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { compareSnapshots } from '../../core/reporting-engine/src/index.js';
import {
  TENANT_A,
  TENANT_B,
  BLOCK_HASH,
  observation,
} from '../../packages/test-fixtures/src/fixtures.js';

it('validates OIDC signature, issuer, audience, expiry and operator membership; ignores tenant claims', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const config = {
    issuer: 'https://id.example',
    audience: 'chainvanta',
    jwksUrl: 'https://id.example/jwks',
    memberships: [{ subject: 'alice', tenantId: TENANT_A, role: 'viewer' as const }],
  };
  const auth = new Authenticator([], config, async () => publicKey);
  const token = async (aud = 'chainvanta', sub = 'alice', exp = '5m', iss = 'https://id.example') =>
    new SignJWT({ tenantId: TENANT_B, role: 'admin' })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(sub)
      .setIssuer(iss)
      .setAudience(aud)
      .setIssuedAt()
      .setExpirationTime(exp)
      .sign(privateKey);
  expect(await auth.authenticate(`Bearer ${await token()}`)).toEqual(config.memberships[0]);
  for (const jwt of [
    await token('wrong'),
    await token('chainvanta', 'mallory'),
    await token('chainvanta', 'alice', '-1s'),
    await token('chainvanta', 'alice', '5m', 'https://evil.example'),
  ])
    expect(await auth.authenticate(`Bearer ${jwt}`)).toBeNull();
  const other = await generateKeyPair('RS256');
  const bad = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject('alice')
    .setIssuer(config.issuer)
    .setAudience(config.audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(other.privateKey);
  expect(await auth.authenticate(`Bearer ${bad}`)).toBeNull();
});

it.each(['legacy', 'eip2930', 'eip1559'] as const)(
  'verifies %s transaction evidence and rejects tampered context',
  async (type) => {
    // Public deterministic TEST ONLY key. Never funded, never used with a network.
    const account = privateKeyToAccount(`0x${'11'.repeat(32)}`);
    const common = {
      chainId: 1,
      nonce: 0,
      gas: 21000n,
      to: observation.address as `0x${string}`,
      value: 0n,
    };
    const serialized = await account.signTransaction(
      type === 'legacy'
        ? { ...common, type, gasPrice: 1n }
        : type === 'eip2930'
          ? { ...common, type, gasPrice: 1n, accessList: [] }
          : { ...common, type, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, accessList: [] },
    );
    const parsed = parseTransaction(serialized);
    const hash = keccak256(serialized);
    const raw = {
      hash,
      blockHash: BLOCK_HASH,
      blockNumber: '0x100',
      from: account.address.toLowerCase(),
      to: observation.address,
      type: type === 'legacy' ? '0x0' : type === 'eip2930' ? '0x1' : '0x2',
      chainId: '0x1',
      nonce: '0x0',
      gas: '0x5208',
      value: '0x0',
      input: '0x',
      gasPrice: '0x1',
      maxFeePerGas: '0x2',
      maxPriorityFeePerGas: '0x1',
      accessList: [],
      r: parsed.r,
      s: parsed.s,
      v: toHex(parsed.v ?? BigInt(parsed.yParity!)),
    };
    const receipt = {
      transactionHash: hash,
      blockHash: BLOCK_HASH,
      blockNumber: '0x100',
      status: '0x1',
    };
    const signature = await verifyTransaction(raw, receipt, 1, raw.from, hash);
    expect(signature.serializedTransaction).toBe(serialized);
    const assessment = assessWallet(TENANT_A, { ...observation, address: raw.from, signature });
    expect(assessment.qbom.status).toBe('classical-signature-observed');
    expect(assessment.cbom.components[0]?.algorithm).toBe('ECDSA-secp256k1');
    expect(assessment.posture.findings.find((f) => f.ruleId === 'CV-QUANTUM-001')?.severity).toBe(
      'medium',
    );
    expect(assessment.cbom.components[1]?.algorithm).toBe('unknown');
    await expect(
      verifyTransaction({ ...raw, value: '0x1' }, receipt, 1, raw.from, hash),
    ).rejects.toThrow();
    await expect(
      verifyTransaction(raw, { ...receipt, blockHash: `0x${'cd'.repeat(32)}` }, 1, raw.from, hash),
    ).rejects.toThrow();
    await expect(verifyTransaction(raw, receipt, 10, raw.from, hash)).rejects.toThrow();
  },
);
it('decodes only explicit token accessors and rejects unsupported/short return values', async () => {
  const abi = parseAbi([
    'function owner() view returns (address)',
    'function totalSupply() view returns (uint256)',
    'function decimals() view returns (uint8)',
  ]);
  const results = [
    encodeFunctionResult({
      abi,
      functionName: 'owner',
      result: observation.address as `0x${string}`,
    }),
    encodeFunctionResult({ abi, functionName: 'totalSupply', result: 2n ** 100n }),
    encodeFunctionResult({ abi, functionName: 'decimals', result: 6 }),
  ];
  let call = 0;
  const token = await observeToken(async () => results[call++]!);
  expect(token.totalSupply).toBe((2n ** 100n).toString());
  expect(token.owner).toBe(observation.address);
  expect(token.limitation).toContain('mint/burn');
  await expect(observeToken(async () => '0x')).rejects.toThrow();
});
it('compares observed state without treating changed balances as cryptographic drift', () => {
  const a = assessWallet(TENANT_A, observation),
    b = assessWallet(TENANT_A, { ...observation, balanceWei: '99' });
  expect(compareSnapshots(b, a)).toEqual([]);
  b.observation.code = '0x6000';
  expect(compareSnapshots(b, a)).toEqual([{ field: 'code', before: '0x', after: '0x6000' }]);
  b.tenantId = TENANT_B;
  expect(() => compareSnapshots(b, a)).toThrow();
});
