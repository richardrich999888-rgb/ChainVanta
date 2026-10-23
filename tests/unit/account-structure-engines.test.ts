import { describe, expect, it } from 'vitest';
import {
  EIP1967_SLOTS,
  discoverAccountStructure,
} from '../../modules/01-wallet-intelligence/src/discovery/account-structure.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { comparePosture } from '../../core/cpm-engine/drift-detection/index.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { toCycloneDx } from '../../core/cbom-engine/exporters/cyclonedx.js';
import { ADDRESS, TENANT_A, observation } from '../../packages/test-fixtures/src/fixtures.js';
import {
  SENTINEL,
  addr,
  designator,
  encode,
  fakeReader,
  selector,
  word,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import type { Hex } from 'viem';

const RUNTIME = '0x6080604052' as const;
const OWNERS = [addr('44'), addr('55'), addr('66')];
const MODULE = addr('77');

async function assessed(code: Hex, chain: FakeChain = {}) {
  const structure = await discoverAccountStructure(fakeReader(chain), ADDRESS as Hex, code);
  return assessWallet(TENANT_A, { ...observation, code, ...(structure ? { structure } : {}) });
}
const safe = (modules: Hex[] = [], ownerCode: Record<string, Hex> = {}): FakeChain => ({
  code: ownerCode,
  calls: {
    [ADDRESS]: {
      [selector('getOwners')]: encode('getOwners', OWNERS),
      [selector('getThreshold')]: encode('getThreshold', 2n),
      [selector('getModulesPaginated')]: encode('getModulesPaginated', [modules, SENTINEL]),
    },
  },
});
const proxy = (implementation: Hex): FakeChain => ({
  code: { [implementation]: RUNTIME },
  storage: { [ADDRESS]: { [EIP1967_SLOTS.implementation]: word(implementation) } },
});
const ids = (a: Awaited<ReturnType<typeof assessed>>) => a.posture.findings.map((f) => f.ruleId);

describe('structure-aware intelligence', () => {
  it('leaves accounts without structure evidence unchanged', async () => {
    const plain = await assessed('0x');
    expect(ids(plain)).toEqual(['CV-WALLET-001']);
    expect(plain.qbom.status).toBe('unknown');
    expect(plain.cbom.components).toHaveLength(1);
  });

  it('treats an EIP-7702 designator as observed secp256k1 account authority', async () => {
    const a = await assessed(designator(addr('11')));
    const ecdsa = a.cbom.components.find((c) => c.domain === 'account-authorization');
    expect(ecdsa).toMatchObject({
      algorithm: 'ECDSA-secp256k1',
      confidence: 'observed',
      evidenceRefs: [a.evidenceHash],
    });
    expect(a.qbom).toMatchObject({
      status: 'classical-signature-observed',
      ruleVersion: 'quantum-exposure/1.1.0',
    });
    expect(a.qbom.reason).toContain('EIP-7702');
    expect(a.posture.findings.find((f) => f.ruleId === 'CV-WALLET-003')).toMatchObject({
      severity: 'medium',
      confidence: 'observed',
    });
    expect(a.trustGraph.edges).toContainEqual({
      from: `eip155:1:${ADDRESS}`,
      to: `eip155:1:${addr('11')}`,
      relation: 'eip7702-delegates-to',
    });
  });

  it('infers, not observes, Safe owner schemes and keeps contract owners unknown', async () => {
    const a = await assessed(RUNTIME, safe([MODULE], { [OWNERS[2]!]: RUNTIME }));
    const owners = a.cbom.components.filter((c) => c.purpose.startsWith('Safe owner'));
    expect(owners.map((c) => [c.algorithm, c.confidence])).toEqual([
      ['ECDSA-secp256k1', 'inferred'],
      ['unknown', 'unknown'],
    ]);
    // Inferred owner schemes do not change the quantum status.
    expect(a.qbom.status).toBe('unknown');
    expect(ids(a)).toEqual(['CV-WALLET-001', 'CV-WALLET-002', 'CV-SAFE-001', 'CV-SAFE-002']);
    expect(a.posture.findings.find((f) => f.ruleId === 'CV-SAFE-001')?.title).toContain('2-of-3');
    expect(
      a.trustGraph.edges.filter((e) => e.relation === 'safe-owner-accessor-reports'),
    ).toHaveLength(3);
  });

  it('flags Safe modules only when present or not fully enumerated', async () => {
    expect(ids(await assessed(RUNTIME, safe([])))).not.toContain('CV-SAFE-002');
    const unknownModules = safe([]);
    delete unknownModules.calls![ADDRESS]![selector('getModulesPaginated')];
    const a = await assessed(RUNTIME, unknownModules);
    expect(a.posture.findings.find((f) => f.ruleId === 'CV-SAFE-002')).toMatchObject({
      confidence: 'unknown',
      title: 'Safe module list is incomplete',
    });
  });

  it('deduplicates graph edges from hostile duplicate accessor data', async () => {
    const a = await assessed(RUNTIME, safe([MODULE, MODULE]));
    const modules = a.trustGraph.edges.filter((e) => e.relation === 'safe-module-accessor-reports');
    expect(modules).toHaveLength(1);
    const keys = a.trustGraph.edges.map((e) => `${e.from}|${e.to}|${e.relation}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('reports EIP-1967 proxies and drifts CPM dependencies when the implementation changes', async () => {
    const before = await assessed(RUNTIME, proxy(addr('11')));
    const after = await assessed(RUNTIME, proxy(addr('12')));
    expect(ids(before)).toContain('CV-PROXY-001');
    const [a, b] = [before, after].map((x) => evaluateCpm(x, defaultPolicy));
    expect(a!.dependencies).toContain(`eip1967-implementation-slot-reports:eip155:1:${addr('11')}`);
    const drift = comparePosture(a!, b!).find((e) => e.type === 'DEPENDENCY_CHANGED');
    expect(drift?.after).toContain(`eip1967-implementation-slot-reports:eip155:1:${addr('12')}`);
  });

  it('exports structure-derived components as a valid CycloneDX CBOM', async () => {
    const bom = toCycloneDx(await assessed(designator(addr('11'))));
    expect(bom.components.map((c) => c.cryptoProperties.algorithmProperties.primitive)).toEqual([
      'signature',
      'unknown',
    ]);
  });
});
