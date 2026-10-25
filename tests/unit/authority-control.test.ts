import { describe, expect, it } from 'vitest';
import { encodeFunctionResult, parseAbi, toFunctionSelector, type Hex } from 'viem';
import { discoverTokenAuthority } from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/token-authority.js';
import { READS_PER_HOLDER } from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/authority-control.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { evaluateCpm } from '../../core/cpm-engine/posture-evaluation/snapshot.js';
import { comparePosture } from '../../core/cpm-engine/drift-detection/index.js';
import { defaultPolicy } from '../../core/policy-engine/policies/web3.js';
import { TOKEN_AUTHORITY_LIMITS } from '../../packages/domain-models/src/index.js';
import { ADDRESS, TENANT_A, observation } from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  fakeReader,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import { erc20, ret, sel } from '../../packages/test-fixtures/src/token-authority.js';

const TOKEN = ADDRESS as Hex;
const RUNTIME = '0x6080604052' as Hex;
const HOLDER = addr('c1');
const controlAbi = parseAbi([
  'function getThreshold() view returns (uint256)',
  'function getOwners() view returns (address[])',
  'function getMinDelay() view returns (uint256)',
  'function delay() view returns (uint256)',
]);
type ControlFn = (typeof controlAbi)[number]['name'];
const answer = (functionName: ControlFn, result: unknown) => ({
  [toFunctionSelector(controlAbi.find((f) => f.name === functionName)!).toLowerCase()]:
    encodeFunctionResult({ abi: controlAbi, functionName, result } as never),
});
const safe = (threshold: bigint, owners: Hex[]) => ({
  ...answer('getThreshold', threshold),
  ...answer('getOwners', owners),
});
/** Token whose owner (a supply/logic role) is HOLDER, a contract answering `holderCalls`. */
const chain = (holderCalls: Record<string, Hex>, extra: FakeChain['calls'] = {}): FakeChain => ({
  code: { [HOLDER]: RUNTIME, [addr('c2')]: RUNTIME, [addr('c3')]: RUNTIME },
  calls: {
    [TOKEN]: { ...erc20(), [sel('owner')]: ret('owner', HOLDER) },
    [HOLDER]: holderCalls,
    ...extra,
  },
});
const discover = (c: FakeChain) => discoverTokenAuthority(fakeReader(c), TOKEN, undefined);
const controlOf = async (c: FakeChain) =>
  (await discover(c)).authorities.find((a) => a.address === HOLDER)?.control;
const assess = async (c: FakeChain) =>
  assessWallet(TENANT_A, { ...observation, code: RUNTIME, tokenAuthority: await discover(c) });
const ids = (a: Awaited<ReturnType<typeof assess>>) => a.posture.findings.map((f) => f.ruleId);

describe('authority control profiling', () => {
  it('profiles a Safe holder as m-of-n', async () => {
    expect(await controlOf(chain(safe(2n, [addr('d1'), addr('d2'), addr('d3')])))).toEqual({
      type: 'safe',
      threshold: 2,
      owners: [addr('d1'), addr('d2'), addr('d3')],
    });
  });

  it.each([
    ['threshold above owner count', safe(3n, [addr('d1'), addr('d2')])],
    ['duplicate owners', safe(1n, [addr('d1'), addr('d1')])],
    ['a zero-address owner', safe(1n, [addr('d1'), `0x${'0'.repeat(40)}` as Hex])],
    ['no owners accessor', answer('getThreshold', 1n)],
    ['a zero threshold', safe(0n, [addr('d1')])],
  ])('does not accept a Safe answer with %s', async (_, calls) => {
    expect(await controlOf(chain(calls))).toEqual({ type: 'unrecognized' });
  });

  it('profiles OpenZeppelin and Compound timelocks', async () => {
    expect(await controlOf(chain(answer('getMinDelay', 172_800n)))).toEqual({
      type: 'timelock',
      standard: 'openzeppelin-timelock-controller',
      minDelaySeconds: '172800',
    });
    expect(await controlOf(chain(answer('delay', 86_400n)))).toEqual({
      type: 'timelock',
      standard: 'compound-timelock',
      minDelaySeconds: '86400',
    });
  });

  it(`spends at most ${READS_PER_HOLDER} reads per holder`, async () => {
    const a = await discover(chain({}));
    expect(a.reads.filter((r) => r.target === HOLDER && r.method === 'eth_call')).toHaveLength(
      READS_PER_HOLDER,
    );
    expect(a.authorities.find((x) => x.address === HOLDER)?.control).toEqual({
      type: 'unrecognized',
    });
  });

  it('profiles only supply or logic holders, skips proxy admins, and caps the count', async () => {
    const a = await discover({
      code: {
        [HOLDER]: RUNTIME,
        [addr('c2')]: RUNTIME,
        [addr('c3')]: RUNTIME,
        [addr('c4')]: RUNTIME,
      },
      calls: {
        [TOKEN]: {
          ...erc20(),
          [sel('owner')]: ret('owner', HOLDER),
          [sel('defaultAdmin')]: ret('defaultAdmin', addr('c2')),
          [sel('masterMinter')]: ret('masterMinter', addr('c3')),
          // Blacklister cannot mint or upgrade: never profiled.
          [sel('blacklister')]: ret('blacklister', addr('c4')),
        },
      },
    });
    const profiled = a.authorities.filter((x) => x.control).map((x) => x.address);
    expect(profiled).toEqual([HOLDER, addr('c2')]);
    expect(profiled).toHaveLength(TOKEN_AUTHORITY_LIMITS.maxProfiledControls);
    // The third powerful contract holder is reported as unprofiled, never silently skipped.
    const assessed = assessWallet(TENANT_A, { ...observation, code: RUNTIME, tokenAuthority: a });
    expect(assessed.posture.findings.find((f) => f.ruleId === 'CV-TOKEN-004')?.rationale).toContain(
      '1 contract holder(s) of supply or logic roles were not profiled',
    );
  });

  it('never profiles holders of roles that cannot mint or upgrade', async () => {
    const a = await discover({
      code: { [addr('c4')]: RUNTIME },
      calls: { [TOKEN]: { ...erc20(), [sel('blacklister')]: ret('blacklister', addr('c4')) } },
    });
    expect(a.authorities).toEqual([{ address: addr('c4'), kind: 'contract' }]);
  });

  it('skips proxy admins, whose owner is already followed', async () => {
    const admin = addr('c5');
    const a = await discoverTokenAuthority(
      fakeReader({ code: { [admin]: RUNTIME }, calls: { [admin]: answer('getMinDelay', 1n) } }),
      TOKEN,
      { eip1967: { admin } } as never,
    );
    expect(a.authorities.find((x) => x.address === admin)).toEqual({
      address: admin,
      kind: 'contract',
    });
  });

  it('fails closed when a control read fails', async () => {
    const reader = fakeReader(chain({}));
    const failing = {
      ...reader,
      call: (target: Hex, data: Hex) =>
        target === HOLDER ? Promise.reject(new Error('rpc down')) : reader.call(target, data),
    };
    await expect(discoverTokenAuthority(failing, TOKEN, undefined)).rejects.toThrow('rpc down');
  });
});

describe('authority control intelligence', () => {
  it('flags a 1-of-N Safe with supply power as high severity', async () => {
    const a = await assess(chain(safe(1n, [addr('d1'), addr('d2')])));
    const finding = a.posture.findings.find((f) => f.ruleId === 'CV-TOKEN-006');
    expect(finding).toMatchObject({ severity: 'high', confidence: 'inferred' });
    expect(finding?.rationale).toContain('1-of-2 Safe');
    expect(ids(a)).not.toContain('CV-TOKEN-003');
  });

  it('does not flag a 2-of-3 Safe, and summarizes it', async () => {
    const a = await assess(chain(safe(2n, [addr('d1'), addr('d2'), addr('d3')])));
    expect(ids(a)).not.toContain('CV-TOKEN-006');
    expect(a.posture.findings.find((f) => f.ruleId === 'CV-TOKEN-002')?.rationale).toContain(
      `${HOLDER} is a 2-of-3 Safe`,
    );
  });

  it('flags a zero-delay timelock with supply power', async () => {
    const a = await assess(chain(answer('getMinDelay', 0n)));
    expect(a.posture.findings.find((f) => f.ruleId === 'CV-TOKEN-007')).toMatchObject({
      severity: 'medium',
    });
    expect(ids(await assess(chain(answer('getMinDelay', 3600n))))).not.toContain('CV-TOKEN-007');
  });

  it('drifts CPM dependencies on a Safe owner swap and on a timelock delay change', async () => {
    const snapshot = async (c: FakeChain) => evaluateCpm(await assess(c), defaultPolicy);
    const swap = comparePosture(
      await snapshot(chain(safe(2n, [addr('d1'), addr('d2')]))),
      await snapshot(chain(safe(2n, [addr('d1'), addr('d9')]))),
    ).find((e) => e.type === 'DEPENDENCY_CHANGED');
    expect(swap?.after).toContain(`authority-safe-owner-accessor-reports:eip155:1:${addr('d9')}`);
    const delay = comparePosture(
      await snapshot(chain(answer('getMinDelay', 172_800n))),
      await snapshot(chain(answer('getMinDelay', 60n))),
    ).find((e) => e.type === 'DEPENDENCY_CHANGED');
    expect(delay?.after).toContain(
      `authority-timelock-delay-reports:timelock-delay:1:${HOLDER}:60`,
    );
  });

  it('keeps graph edges unique when owners repeat across holders', async () => {
    const a = await assess(chain(safe(1n, [addr('d1')]), { [addr('c2')]: safe(1n, [addr('d1')]) }));
    const keys = a.trustGraph.edges.map((e) => `${e.from}|${e.to}|${e.relation}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
