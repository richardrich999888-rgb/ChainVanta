import { describe, expect, it } from 'vitest';
import {
  EIP1967_SLOTS,
  discoverAccountStructure,
  parseDelegation,
  parseMinimalProxy,
  slotAddress,
} from '../../modules/01-wallet-intelligence/src/discovery/account-structure.js';
import { STRUCTURE_LIMITS } from '../../packages/domain-models/src/index.js';
import {
  SENTINEL,
  addr,
  designator,
  encode,
  fakeReader,
  minimalProxy,
  selector,
  word,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';

const ACCOUNT = addr('aa');
const IMPL = addr('11');
const ADMIN = addr('22');
const BEACON = addr('33');
const OWNERS = [addr('44'), addr('55'), addr('66')];
const MODULE = addr('77');
const ENTRY = addr('88');
const SINGLETON = addr('99');
const RUNTIME = '0x6080604052' as const;

const discover = (code: `0x${string}`, chain: FakeChain = {}) =>
  discoverAccountStructure(fakeReader(chain), ACCOUNT, code);

/** A Safe proxy with `owners`, `threshold` and one page of modules ending at `next`. */
function safeChain(
  owners = OWNERS,
  threshold = 2n,
  modules: `0x${string}`[] = [],
  next = SENTINEL,
): FakeChain {
  return {
    storage: { [ACCOUNT]: { [word('0x00')]: word(SINGLETON) } },
    calls: {
      [ACCOUNT]: {
        [selector('getOwners')]: encode('getOwners', owners),
        [selector('getThreshold')]: encode('getThreshold', threshold),
        [selector('VERSION')]: encode('VERSION', '1.4.1'),
        [selector('getModulesPaginated')]: encode('getModulesPaginated', [modules, next]),
      },
    },
  };
}

describe('pure decoders', () => {
  it('derives the EIP-1967 slots published in the standard', () => {
    // Values from the EIP-1967 text; derived here as keccak256(label) - 1.
    expect(EIP1967_SLOTS).toEqual({
      implementation: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
      admin: '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
      beacon: '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
    });
  });

  it('accepts only an exact EIP-7702 designator', () => {
    expect(parseDelegation(designator(IMPL))).toBe(IMPL);
    expect(parseDelegation(designator(IMPL).toUpperCase().replace('0X', '0x'))).toBe(IMPL);
    for (const code of ['0xef0100', `${designator(IMPL)}00`, `0xef0101${IMPL.slice(2)}`, '0x'])
      expect(parseDelegation(code)).toBeNull();
  });

  it('accepts only the canonical EIP-1167 runtime', () => {
    expect(parseMinimalProxy(minimalProxy(IMPL))).toBe(IMPL);
    const tampered = minimalProxy(IMPL).replace(/f3$/, 'f4');
    expect(parseMinimalProxy(tampered)).toBeNull();
    expect(parseMinimalProxy(`${minimalProxy(IMPL)}00`)).toBeNull();
  });

  it('interprets storage words as addresses only when the upper 12 bytes are zero', () => {
    expect(slotAddress(word(IMPL))).toBe(IMPL);
    expect(slotAddress(`0x${'0'.repeat(64)}`)).toBe('empty');
    expect(slotAddress('0x0')).toBe('empty');
    expect(slotAddress(`0x01${'0'.repeat(22)}${IMPL.slice(2)}`)).toBe('malformed');
  });
});

describe('account structure discovery', () => {
  it('makes no reads for an account without code', async () => {
    const reader = fakeReader({});
    expect(await discoverAccountStructure(reader, ACCOUNT, '0x')).toBeNull();
    expect(reader.count()).toBe(0);
  });

  it('reports nothing for plain contract code whose probes revert', async () => {
    const result = await discover(RUNTIME);
    expect(result).toMatchObject({
      delegation: null,
      minimalProxy: null,
      eip1967: null,
      safe: null,
      erc4337: null,
    });
    expect(result!.reads.filter((r) => r.outcome === 'reverted')).toHaveLength(4);
  });

  it('detects an EIP-7702 delegated account', async () => {
    const result = await discover(designator(IMPL));
    expect(result?.delegation).toEqual({ standard: 'eip-7702', delegate: IMPL });
  });

  it('detects an EIP-1167 minimal proxy and hashes its implementation code', async () => {
    const result = await discover(minimalProxy(IMPL), { code: { [IMPL]: RUNTIME } });
    expect(result?.minimalProxy).toMatchObject({ standard: 'eip-1167', implementation: IMPL });
    expect(result?.minimalProxy?.implementationCodeHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('reads EIP-1967 implementation, admin and beacon slots', async () => {
    const result = await discover(RUNTIME, {
      code: { [IMPL]: RUNTIME },
      storage: {
        [ACCOUNT]: {
          [EIP1967_SLOTS.implementation]: word(IMPL),
          [EIP1967_SLOTS.admin]: word(ADMIN),
          [EIP1967_SLOTS.beacon]: word(BEACON),
        },
      },
      calls: { [BEACON]: { [selector('implementation')]: encode('implementation', SINGLETON) } },
    });
    expect(result?.eip1967).toMatchObject({
      implementation: IMPL,
      admin: ADMIN,
      beacon: BEACON,
      beaconImplementation: SINGLETON,
      malformedSlots: [],
    });
    expect(result?.eip1967?.implementationCodeHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('records an implementation without code and refuses to interpret malformed slots', async () => {
    const result = await discover(RUNTIME, {
      storage: {
        [ACCOUNT]: {
          [EIP1967_SLOTS.implementation]: word(IMPL),
          [EIP1967_SLOTS.admin]: `0x01${'0'.repeat(22)}${ADMIN.slice(2)}`,
        },
      },
    });
    expect(result?.eip1967).toMatchObject({
      implementation: IMPL,
      implementationCodeHash: null,
      admin: null,
      malformedSlots: ['admin'],
    });
  });

  it('records Safe owners, threshold, version, singleton, modules and owner code kinds', async () => {
    const chain = safeChain(OWNERS, 2n, [MODULE]);
    chain.code = { [OWNERS[1]!]: designator(IMPL), [OWNERS[2]!]: RUNTIME };
    const result = await discover(RUNTIME, chain);
    expect(result?.safe).toEqual({
      owners: OWNERS,
      threshold: 2,
      version: '1.4.1',
      singleton: SINGLETON,
      modules: [MODULE],
      modulesComplete: true,
      ownerCode: [
        { owner: OWNERS[0], kind: 'no-code' },
        { owner: OWNERS[1], kind: 'eip-7702-delegated' },
        { owner: OWNERS[2], kind: 'contract' },
      ],
    });
  });

  it('marks Safe modules incomplete when another page exists or the call reverts', async () => {
    const paged = await discover(RUNTIME, safeChain(OWNERS, 1n, [MODULE], MODULE));
    expect(paged?.safe).toMatchObject({ modules: [MODULE], modulesComplete: false });
    const legacy = safeChain();
    delete legacy.calls![ACCOUNT]![selector('getModulesPaginated')];
    const reverted = await discover(RUNTIME, legacy);
    expect(reverted?.safe).toMatchObject({ modules: [], modulesComplete: false });
    expect(reverted?.limitations.join(' ')).toContain('module list is incomplete');
  });

  it.each([
    ['threshold above owner count', safeChain(OWNERS, 4n)],
    ['zero threshold', safeChain(OWNERS, 0n)],
    ['duplicate owners', safeChain([OWNERS[0]!, OWNERS[0]!], 1n)],
    ['zero-address owner', safeChain([addr('00')], 1n)],
    ['sentinel owner', safeChain([SENTINEL], 1n)],
    ['empty owner list', safeChain([], 1n)],
  ])('rejects Safe-shaped data with %s', async (_, chain) => {
    expect((await discover(RUNTIME, chain))?.safe).toBeNull();
  });

  it('rejects undecodable accessor data instead of guessing', async () => {
    const result = await discover(RUNTIME, {
      calls: {
        [ACCOUNT]: {
          [selector('getOwners')]: '0xdeadbeef',
          [selector('getThreshold')]: encode('getThreshold', 1n),
          [selector('entryPoint')]: '0x01',
        },
      },
    });
    expect(result).toMatchObject({ safe: null, erc4337: null });
  });

  it('neither stores nor decodes oversized return data', async () => {
    const huge = `0x${'00'.repeat(STRUCTURE_LIMITS.maxReturnBytes + 1)}` as const;
    const result = await discover(RUNTIME, {
      calls: {
        [ACCOUNT]: { [selector('getOwners')]: huge, [selector('getThreshold')]: huge },
      },
    });
    expect(result?.safe).toBeNull();
    const oversized = result!.reads.filter((r) => r.resultSize !== undefined);
    expect(oversized).toHaveLength(2);
    for (const read of oversized) {
      expect(read.result).toBeUndefined();
      expect(read.resultHash).toMatch(/^0x[0-9a-f]{64}$/);
    }
    expect(JSON.stringify(result).length).toBeLessThan(STRUCTURE_LIMITS.maxReturnBytes * 4);
  });

  it('does not record oversized owner lists', async () => {
    const owners = Array.from({ length: STRUCTURE_LIMITS.maxSafeOwners + 1 }, (_, i) =>
      addr((i + 16).toString(16).padStart(2, '0')),
    );
    const result = await discover(RUNTIME, safeChain(owners, 1n));
    expect(result?.safe).toBeNull();
    expect(result?.limitations.join(' ')).toContain(`${owners.length} owners`);
  });

  it('bounds owner code reads and total reads for the largest supported Safe', async () => {
    const owners = Array.from({ length: STRUCTURE_LIMITS.maxSafeOwners }, (_, i) =>
      addr((i + 16).toString(16).padStart(2, '0')),
    );
    const chain = safeChain(owners, 1n);
    chain.storage![ACCOUNT]![EIP1967_SLOTS.implementation] = word(IMPL);
    chain.storage![ACCOUNT]![EIP1967_SLOTS.beacon] = word(BEACON);
    chain.calls![ACCOUNT]![selector('entryPoint')] = encode('entryPoint', ENTRY);
    const reader = fakeReader(chain);
    const result = await discoverAccountStructure(reader, ACCOUNT, minimalProxy(IMPL));
    const kinds = result!.safe!.ownerCode.map((o) => o.kind);
    expect(kinds.filter((k) => k === 'not-checked')).toHaveLength(
      STRUCTURE_LIMITS.maxSafeOwners - STRUCTURE_LIMITS.maxOwnerCodeReads,
    );
    expect(reader.count()).toBe(result!.reads.length);
    expect(reader.count()).toBeLessThanOrEqual(STRUCTURE_LIMITS.maxReads);
  });

  it('reports an ERC-4337 entry point and whether it has code', async () => {
    const chain = (code: boolean): FakeChain => ({
      ...(code ? { code: { [ENTRY]: RUNTIME } } : {}),
      calls: { [ACCOUNT]: { [selector('entryPoint')]: encode('entryPoint', ENTRY) } },
    });
    expect((await discover(RUNTIME, chain(true)))?.erc4337).toEqual({
      entryPoint: ENTRY,
      entryPointHasCode: true,
    });
    expect((await discover(RUNTIME, chain(false)))?.erc4337?.entryPointHasCode).toBe(false);
  });

  it('records reads in invocation order regardless of completion order', async () => {
    const chain = safeChain(OWNERS, 2n, [MODULE]);
    const forward = await discoverAccountStructure(fakeReader(chain), ACCOUNT, RUNTIME);
    // Later reads complete first.
    const reversed = await discoverAccountStructure(
      fakeReader(chain, (n) => 20 - n),
      ACCOUNT,
      RUNTIME,
    );
    expect(reversed).toEqual(forward);
  });
});
