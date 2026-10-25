import { describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import {
  ZEPPELINOS_ADMIN_SLOT,
  discoverTokenAuthority,
} from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/token-authority.js';
import { TOKEN_AUTHORITY_LIMITS } from '../../packages/domain-models/src/index.js';
import { CONTROL_READ_RESERVE } from '../../modules/09-stablecoin-assurance/src/mint-burn-authorities/authority-control.js';
import { ADDRESS } from '../../packages/test-fixtures/src/fixtures.js';
import {
  addr,
  designator,
  fakeReader,
  word,
  type FakeChain,
} from '../../packages/test-fixtures/src/account-structure.js';
import {
  accessControlOnly,
  enumerableRoles,
  erc20,
  ret,
  sel,
} from '../../packages/test-fixtures/src/token-authority.js';

const TOKEN = ADDRESS as Hex;
const RUNTIME = '0x6080604052' as Hex;
const ZERO = '0x0000000000000000000000000000000000000000' as Hex;
const discover = (chain: FakeChain, structure?: Parameters<typeof discoverTokenAuthority>[2]) =>
  discoverTokenAuthority(fakeReader(chain), TOKEN, structure);
const role = (a: Awaited<ReturnType<typeof discover>>, name: string, source?: string) =>
  a.roles.find((r) => r.role === name && (!source || r.source === source));

describe('token authority discovery', () => {
  it('lists AccessControlEnumerable holders and classifies each by code', async () => {
    const multisig = addr('22');
    const a = await discover({
      code: { [TOKEN]: RUNTIME, [multisig]: RUNTIME, [addr('33')]: designator(addr('99')) },
      calls: {
        [TOKEN]: {
          ...erc20('USDX', 6, 5_000n),
          ...enumerableRoles({
            'default-admin': [multisig],
            minter: [addr('11'), addr('33')],
            pauser: [addr('11')],
          }),
        },
      },
    });
    expect(a).toMatchObject({ symbol: 'USDX', decimals: 6, totalSupply: '5000', paused: null });
    expect(a.accessControl).toBe('enumerable');
    expect(role(a, 'minter')).toEqual({
      role: 'minter',
      source: 'access-control-enumerable',
      holders: [addr('11'), addr('33')],
      holdersComplete: true,
    });
    expect(role(a, 'burner')?.holders).toEqual([]);
    expect(a.authorities).toEqual([
      { address: multisig, kind: 'contract', control: { type: 'unrecognized' } },
      { address: addr('11'), kind: 'no-code' },
      { address: addr('33'), kind: 'eip-7702-delegated' },
    ]);
    expect(a.reads.length).toBeLessThanOrEqual(TOKEN_AUTHORITY_LIMITS.maxReads);
  });

  it('reads Ownable2Step, FiatToken roles and pause state; zero holders mean renounced', async () => {
    const a = await discover({
      calls: {
        [TOKEN]: {
          ...erc20(),
          [sel('owner')]: ret('owner', ZERO),
          [sel('pendingOwner')]: ret('pendingOwner', addr('44')),
          [sel('masterMinter')]: ret('masterMinter', addr('55')),
          [sel('pauser')]: ret('pauser', addr('55')),
          [sel('blacklister')]: ret('blacklister', addr('66')),
          [sel('paused')]: ret('paused', true),
        },
      },
    });
    expect(role(a, 'owner')).toMatchObject({ source: 'ownable', holders: [] });
    expect(role(a, 'pending-owner')).toMatchObject({
      source: 'ownable2step',
      holders: [addr('44')],
    });
    expect(role(a, 'master-minter')).toMatchObject({ source: 'fiat-token', holders: [addr('55')] });
    expect(role(a, 'rescuer')).toBeUndefined();
    expect(a.paused).toBe(true);
    expect(a.accessControl).toBe('absent');
    // One holder appearing in two roles is classified once.
    expect(a.authorities.map((x) => x.address)).toEqual([addr('44'), addr('55'), addr('66')]);
  });

  it('reports EIP-1967 and ZeppelinOS proxy admins and follows the ProxyAdmin owner', async () => {
    const proxyAdmin = addr('77');
    const zosAdmin = addr('78');
    const a = await discover(
      {
        code: { [proxyAdmin]: RUNTIME },
        storage: { [TOKEN]: { [ZEPPELINOS_ADMIN_SLOT]: word(zosAdmin) } },
        calls: { [proxyAdmin]: { [sel('owner')]: ret('owner', addr('88')) } },
      },
      { eip1967: { admin: proxyAdmin } } as never,
    );
    expect(role(a, 'proxy-admin', 'eip1967-admin-slot')?.holders).toEqual([proxyAdmin]);
    expect(role(a, 'proxy-admin', 'zeppelinos-admin-slot')?.holders).toEqual([zosAdmin]);
    expect(role(a, 'upgrader', 'proxy-admin-owner')?.holders).toEqual([addr('88')]);
    expect(a.authorities).toContainEqual({ address: zosAdmin, kind: 'no-code' });
  });

  it('marks non-enumerable AccessControl and truncated roles as incomplete', async () => {
    const plain = await discover({ calls: { [TOKEN]: accessControlOnly() } });
    expect(plain.accessControl).toBe('non-enumerable');
    expect(plain.limitations.join(' ')).toMatch(/not enumerable/);

    const many = Array.from({ length: 7 }, (_, i) => addr((0x10 + i).toString(16)));
    const big = await discover({ calls: { [TOKEN]: enumerableRoles({ minter: many }) } });
    const minter = role(big, 'minter')!;
    expect(minter.holdersComplete).toBe(false);
    expect(minter.holders.length).toBeLessThanOrEqual(TOKEN_AUTHORITY_LIMITS.maxHoldersPerRole);
    expect(minter.holders).toEqual(many.slice(0, minter.holders.length));
  });

  it('never exceeds the read budget and leaves surplus holders unclassified', async () => {
    const members = (seed: number) =>
      Array.from({ length: 5 }, (_, i) => addr((seed + i).toString(16)));
    const a = await discover({
      calls: {
        [TOKEN]: {
          ...erc20(),
          [sel('masterMinter')]: ret('masterMinter', addr('a1')),
          [sel('pauser')]: ret('pauser', addr('a2')),
          [sel('blacklister')]: ret('blacklister', addr('a3')),
          [sel('rescuer')]: ret('rescuer', addr('a4')),
          [sel('owner')]: ret('owner', addr('a5')),
          [sel('pendingOwner')]: ret('pendingOwner', addr('a6')),
          [sel('defaultAdmin')]: ret('defaultAdmin', addr('a7')),
          ...enumerableRoles({
            'default-admin': members(0x10),
            minter: members(0x20),
            burner: members(0x30),
            pauser: members(0x40),
            upgrader: members(0x50),
          }),
        },
      },
    });
    // Every holder here has no code, so the control-profiling reserve stays unspent.
    expect(a.reads).toHaveLength(TOKEN_AUTHORITY_LIMITS.maxReads - CONTROL_READ_RESERVE);
    const checked = a.authorities.filter((x) => x.kind !== 'not-checked');
    expect(checked).toHaveLength(TOKEN_AUTHORITY_LIMITS.maxClassifiedAuthorities);
    expect(a.limitations.join(' ')).toMatch(/not classified/);
    expect(
      a.roles
        .filter((r) => r.source === 'access-control-enumerable')
        .some((r) => !r.holdersComplete),
    ).toBe(true);
  });

  it('is deterministic under any completion order', async () => {
    const chain: FakeChain = {
      calls: {
        [TOKEN]: { ...erc20(), ...enumerableRoles({ minter: [addr('11'), addr('12')] }) },
      },
    };
    const forward = await discoverTokenAuthority(
      fakeReader(chain, (n) => n % 3),
      TOKEN,
      undefined,
    );
    const reverse = await discoverTokenAuthority(
      fakeReader(chain, (n) => 5 - (n % 5)),
      TOKEN,
      undefined,
    );
    expect(reverse).toEqual(forward);
  });

  it('treats malformed and oversized returns as absent, recording a fingerprint', async () => {
    const a = await discover({
      calls: {
        [TOKEN]: {
          [sel('owner')]: '0x1234',
          [sel('decimals')]: ret('totalSupply', 300n),
          [sel('symbol')]: ret('symbol', 'x'.repeat(5000)),
        },
      },
    });
    expect(role(a, 'owner')).toBeUndefined();
    expect(a.decimals).toBeNull();
    expect(a.symbol).toBeNull();
    expect(a.reads.find((r) => r.input === sel('symbol'))).toMatchObject({
      resultSize: expect.any(Number),
      resultHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
    });
  });

  it('fails closed when the reader fails', async () => {
    const reader = { ...fakeReader({}), code: () => Promise.reject(new Error('rpc down')) };
    await expect(
      discoverTokenAuthority(
        {
          ...reader,
          call: async () => ({ outcome: 'returned', data: ret('owner', addr('11')) }),
        },
        TOKEN,
        undefined,
      ),
    ).rejects.toThrow('rpc down');
  });
});
