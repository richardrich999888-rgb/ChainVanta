import { describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import { discoverTokenAuthority } from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/token-authority.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { comparePosture } from '../../core/cpm-engine/drift-detection/index.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { toCycloneDx } from '../../core/cbom-engine/exporters/cyclonedx.js';
import { EvmConnector, RpcFailure } from '../../connectors/blockchains/ethereum/src/index.js';
import {
  ADDRESS,
  TENANT_A,
  observation,
  testConfig,
} from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  designator,
  fakeChainTransport,
  fakeReader,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import {
  accessControlOnly,
  enumerableRoles,
  erc20,
  ret,
  sel,
} from '../../packages/test-fixtures/src/token-authority.js';

const RUNTIME = '0x6080604052' as Hex;
const MULTISIG = addr('22');

async function assessed(chain: FakeChain) {
  const tokenAuthority = await discoverTokenAuthority(fakeReader(chain), ADDRESS as Hex, undefined);
  return assessWallet(TENANT_A, { ...observation, code: RUNTIME, tokenAuthority });
}
const minters = (minter: Hex[], extra: Record<string, Hex> = {}): FakeChain => ({
  code: { [MULTISIG]: RUNTIME, [addr('33')]: designator(addr('99')) },
  calls: {
    [ADDRESS]: {
      ...erc20(),
      ...enumerableRoles({ 'default-admin': [MULTISIG], minter }),
      ...extra,
    },
  },
});
const ids = (a: Awaited<ReturnType<typeof assessed>>) => a.posture.findings.map((f) => f.ruleId);

describe('token-authority intelligence', () => {
  it('flags each single-key holder of a supply or logic role, not contract holders', async () => {
    const a = await assessed(minters([addr('11'), addr('33')]));
    expect(ids(a)).toContain('CV-TOKEN-002');
    const high = a.posture.findings.filter((f) => f.ruleId === 'CV-TOKEN-003');
    expect(high).toHaveLength(1);
    expect(high[0]).toMatchObject({ severity: 'high', confidence: 'inferred' });
    expect(high[0]!.rationale).toContain(`${addr('11')} (no code) is reported as minter`);
    expect(high[0]!.rationale).toContain(
      `${addr('33')} (EIP-7702 delegated) is reported as minter`,
    );
    expect(high[0]!.rationale).not.toContain(MULTISIG);
    // The EIP-7702 holder's key is not the observed account's: QBOM status does not change.
    expect(a.qbom.status).toBe('unknown');
  });

  it('does not flag single-key holders of roles that cannot mint or upgrade', async () => {
    const a = await assessed({
      calls: { [ADDRESS]: { [sel('blacklister')]: ret('blacklister', addr('11')) } },
    });
    expect(ids(a)).not.toContain('CV-TOKEN-003');
    expect(a.cbom.components.find((c) => c.domain === 'token-administration')).toMatchObject({
      algorithm: 'ECDSA-secp256k1',
      confidence: 'inferred',
    });
  });

  it('reports incomplete authority sets and pause state', async () => {
    const a = await assessed({
      calls: { [ADDRESS]: { ...accessControlOnly(), [sel('paused')]: ret('paused', true) } },
    });
    expect(ids(a)).toEqual(expect.arrayContaining(['CV-TOKEN-004', 'CV-TOKEN-005']));
    expect(a.posture.findings.find((f) => f.ruleId === 'CV-TOKEN-004')?.confidence).toBe('unknown');
  });

  it('records single-key holders as inferred CBOM components and contracts as unknown', async () => {
    const a = await assessed(minters([addr('11')]));
    const token = a.cbom.components.filter((c) => c.domain === 'token-administration');
    expect(token.map((c) => [c.algorithm, c.confidence])).toEqual([
      ['ECDSA-secp256k1', 'inferred'],
      ['unknown', 'unknown'],
    ]);
    const bom = toCycloneDx(a);
    expect(bom.components.some((c) => c.name === 'ECDSA-secp256k1')).toBe(true);
  });

  it('drifts CPM dependencies when a minter changes', async () => {
    const [before, after] = await Promise.all([
      assessed(minters([addr('11')])),
      assessed(minters([addr('12')])),
    ]);
    expect(before.trustGraph.edges).toContainEqual({
      from: `eip155:1:${ADDRESS}`,
      to: `eip155:1:${addr('11')}`,
      relation: 'token-minter-accessor-reports',
    });
    const [a, b] = [before, after].map((x) => evaluateCpm(x, defaultPolicy));
    expect(a!.dependencies).toContain(`token-minter-accessor-reports:eip155:1:${addr('11')}`);
    const drift = comparePosture(a!, b!).find((e) => e.type === 'DEPENDENCY_CHANGED');
    expect(drift?.after).toContain(`token-minter-accessor-reports:eip155:1:${addr('12')}`);
  });

  it('leaves assessments without the adapter unchanged', async () => {
    const a = assessWallet(TENANT_A, { ...observation, code: RUNTIME });
    expect(ids(a).some((id) => id.startsWith('CV-TOKEN'))).toBe(false);
    expect(a.cbom.components.some((c) => c.domain === 'token-administration')).toBe(false);
  });
});

describe('EVM connector token-authority adapter', () => {
  const CHAIN = testConfig.chains[0]!;
  const chain: FakeChain = {
    code: { [ADDRESS]: RUNTIME },
    calls: { [ADDRESS]: { ...erc20(), ...enumerableRoles({ minter: [addr('11')] }) } },
  };

  it('collects token authority at the pinned block without running the ownable adapter', async () => {
    const o = await new EvmConnector(CHAIN, fakeChainTransport(chain)).observe(ADDRESS, {
      adapter: 'token-authority',
    });
    expect(o.token).toBeUndefined();
    expect(o.tokenAuthority?.roles.find((r) => r.role === 'minter')?.holders).toEqual([addr('11')]);
    expect(o.tokenAuthority?.authorities).toEqual([{ address: addr('11'), kind: 'no-code' }]);
  });

  it('refuses the adapter on an account without code', async () => {
    await expect(
      new EvmConnector(CHAIN, fakeChainTransport({})).observe(ADDRESS, {
        adapter: 'token-authority',
      }),
    ).rejects.toBeInstanceOf(RpcFailure);
  });
});
