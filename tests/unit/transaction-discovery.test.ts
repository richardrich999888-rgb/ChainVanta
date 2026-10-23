import { describe, expect, it } from 'vitest';
import { toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  InconsistentChainState,
  discoverLatestTransaction,
  type DiscoveryReader,
} from '../../modules/01-wallet-intelligence/src/discovery/transaction-discovery.js';

// TEST ONLY keys; authorizations are signed locally and never broadcast.
const SIGNER = privateKeyToAccount(`0x${'61'.repeat(32)}`);
const STRANGER = privateKeyToAccount(`0x${'62'.repeat(32)}`);
const ACCOUNT = SIGNER.address.toLowerCase();
const DELEGATE = `0x${'cc'.repeat(20)}` as const;
/** A real EIP-7702 authorization in JSON-RPC form, as it appears inside a type-4 transaction. */
async function rpcAuthorization(signer: typeof SIGNER, nonce: number, chainId = 1) {
  const a = await signer.signAuthorization({ contractAddress: DELEGATE, chainId, nonce });
  return {
    chainId: toHex(a.chainId),
    address: a.address,
    nonce: toHex(a.nonce),
    yParity: toHex(a.yParity ?? 0),
    r: a.r,
    s: a.s,
  };
}
const OTHER = `0x${'bb'.repeat(20)}`;
const hash = (n: number) => `0x${n.toString(16).padStart(64, '0')}`;

type Tx = { hash: string; from: string; nonce: string; type?: string };

/**
 * Simulated chain: `sent[i]` is the block of the account's i-th transaction (nonce i).
 * Post-state nonce at block b = number of transactions in blocks <= b.
 */
function chain(sent: number[], extra: Record<number, Tx[]> = {}, type = '0x2') {
  let reads = 0;
  const reader: DiscoveryReader = {
    nonceAt: async (b) => {
      reads++;
      return BigInt(sent.filter((block) => block <= Number(b)).length);
    },
    blockTransactions: async (b) => [
      ...(extra[Number(b)] ?? []),
      ...sent.flatMap((block, nonce) =>
        block === Number(b)
          ? [{ hash: hash(nonce + 1), from: ACCOUNT, nonce: `0x${nonce.toString(16)}`, type }]
          : [],
      ),
    ],
  };
  return { reader, reads: () => reads };
}
const discover = (
  reader: DiscoveryReader,
  accountNonce: number,
  snapshotBlock: number,
  canSendTransactions = true,
  isDelegated = false,
) =>
  discoverLatestTransaction(reader, {
    address: ACCOUNT,
    accountNonce: BigInt(accountNonce),
    snapshotBlock: BigInt(snapshotBlock),
    chainId: 1,
    canSendTransactions,
    isDelegated,
  });

describe('nonce bisection', () => {
  it('finds the latest transaction at every possible block, within the read bound', async () => {
    for (let snapshot = 0; snapshot <= 40; snapshot++)
      for (let block = 0; block <= snapshot; block++) {
        const sim = chain([block]);
        const result = await discover(sim.reader, 1, snapshot);
        expect(result.outcome).toBe('found');
        expect(result.blockNumber).toBe(`0x${block.toString(16)}`);
        expect(sim.reads()).toBeLessThanOrEqual(Math.ceil(Math.log2(snapshot + 1)));
        expect(result.probes).toHaveLength(sim.reads());
      }
  });

  it('targets nonce N-1 when several transactions share or precede the block', async () => {
    const result = await discover(chain([3, 9, 9, 17]).reader, 4, 30);
    expect(result).toMatchObject({
      outcome: 'found',
      blockNumber: '0x11',
      transactionHash: hash(4),
    });
    const sameBlock = await discover(chain([3, 9, 9]).reader, 3, 30);
    expect(sameBlock).toMatchObject({ blockNumber: '0x9', transactionHash: hash(3) });
  });

  it('uses about 25 reads at mainnet height', async () => {
    const sim = chain([1_234_567, 20_999_999]);
    const result = await discover(sim.reader, 2, 21_000_000);
    expect(result.blockNumber).toBe(`0x${(20_999_999).toString(16)}`);
    // Bisection over [0, F] takes floor or ceil of log2(F + 1) reads: 24 or 25 at this height.
    expect(sim.reads()).toBeGreaterThanOrEqual(Math.floor(Math.log2(21_000_001)));
    expect(sim.reads()).toBeLessThanOrEqual(Math.ceil(Math.log2(21_000_001)));
  });

  it('reports no sent transactions for nonce 0 without reading history', async () => {
    const sim = chain([]);
    expect(await discover(sim.reader, 0, 1000)).toMatchObject({
      outcome: 'no-sent-transactions',
      blockNumber: null,
      probes: [],
    });
    expect(sim.reads()).toBe(0);
  });

  it('does not search for accounts that cannot send transactions', async () => {
    const sim = chain([5]);
    expect((await discover(sim.reader, 1, 10, false)).outcome).toBe('not-applicable');
    expect(sim.reads()).toBe(0);
  });

  it('records unsupported transaction types instead of failing', async () => {
    for (const type of ['0x3', '0x4'])
      expect(await discover(chain([5], {}, type).reader, 1, 10)).toMatchObject({
        outcome: 'unsupported-transaction-type',
        transactionType: type,
        transactionHash: hash(1),
      });
  });

  it('treats a missing type field as a legacy transaction', async () => {
    const reader: DiscoveryReader = {
      nonceAt: async (b) => (b >= 4n ? 1n : 0n),
      blockTransactions: async () => [{ hash: hash(1), from: ACCOUNT, nonce: '0x0' }],
    };
    expect(await discover(reader, 1, 10)).toMatchObject({
      outcome: 'found',
      transactionType: '0x0',
    });
  });

  /** Nonce reaches N at block 6; block 6 holds `transactions`. */
  const atBlock6 = (transactions: unknown[]): DiscoveryReader => ({
    nonceAt: async (b) => (b >= 6n ? 1n : 0n),
    blockTransactions: async () => transactions,
  });
  const relayed = async (authorizations: unknown[]) => ({
    hash: hash(9),
    from: OTHER,
    nonce: '0x0',
    type: '0x4',
    authorizationList: authorizations,
  });

  it('verifies a relayed EIP-7702 authorization by recovering its signer', async () => {
    const tx = await relayed([await rpcAuthorization(SIGNER, 0)]);
    expect(await discover(atBlock6([tx]), 1, 10)).toMatchObject({
      outcome: 'authorization-signature',
      blockNumber: '0x6',
      transactionHash: null,
      authorization: {
        transactionHash: hash(9),
        nonce: '0',
        chainId: '1',
        delegate: DELEGATE,
        authority: ACCOUNT,
      },
    });
  });

  it('ignores authorizations signed by other keys or for other chains', async () => {
    for (const authorization of [
      await rpcAuthorization(STRANGER, 0),
      await rpcAuthorization(SIGNER, 0, 5),
    ])
      await expect(
        discover(atBlock6([await relayed([authorization])]), 1, 10),
      ).rejects.toBeInstanceOf(InconsistentChainState);
  });

  it('accepts chain-agnostic (chain ID 0) authorizations', async () => {
    const tx = await relayed([await rpcAuthorization(SIGNER, 0, 0)]);
    expect((await discover(atBlock6([tx]), 1, 10)).authorization?.chainId).toBe('0');
  });

  it('prefers the verifiable authorization over its own unsupported set-code transaction', async () => {
    // Self-sponsored: the type-4 transaction uses nonce 0, its own authorization nonce 1.
    const reader: DiscoveryReader = {
      nonceAt: async (b) => (b >= 6n ? 2n : 0n),
      blockTransactions: async () => [
        {
          hash: hash(7),
          from: ACCOUNT,
          nonce: '0x0',
          type: '0x4',
          authorizationList: [await rpcAuthorization(SIGNER, 1)],
        },
      ],
    };
    expect(await discover(reader, 2, 10)).toMatchObject({
      outcome: 'authorization-signature',
      authorization: { transactionHash: hash(7), nonce: '1' },
    });
  });

  it('prefers a supported sent transaction over an authorization in the same block', async () => {
    const reader: DiscoveryReader = {
      nonceAt: async (b) => (b >= 6n ? 2n : 0n),
      blockTransactions: async () => [
        await relayed([await rpcAuthorization(SIGNER, 0)]),
        { hash: hash(8), from: ACCOUNT, nonce: '0x1', type: '0x2' },
      ],
    };
    expect(await discover(reader, 2, 10)).toMatchObject({
      outcome: 'found',
      transactionHash: hash(8),
    });
  });

  it('allows an unexplained nonce change only for delegated accounts (CREATE by delegated code)', async () => {
    const unrelated = { hash: hash(9), from: OTHER, nonce: '0x0', type: '0x2' };
    await expect(discover(atBlock6([unrelated]), 1, 10)).rejects.toBeInstanceOf(
      InconsistentChainState,
    );
    expect(await discover(atBlock6([unrelated]), 1, 10, true, true)).toMatchObject({
      outcome: 'no-matching-transaction',
      blockNumber: '0x6',
    });
  });

  it('fails closed when the provider contradicts nonce monotonicity', async () => {
    const reader: DiscoveryReader = {
      nonceAt: async () => 5n,
      blockTransactions: async () => [],
    };
    await expect(discover(reader, 1, 10)).rejects.toBeInstanceOf(InconsistentChainState);
  });

  it('fails closed when a higher block reports a lower nonce than an earlier probe', async () => {
    // Models lazily materialized dev-chain blocks: block 500 reports 2, later gap blocks report 1.
    const nonceAt = async (b: bigint) =>
      b === 500n ? 2n : b > 500n && b < 1000n ? 1n : b >= 1000n ? 3n : 0n;
    const probed: bigint[] = [];
    const reader: DiscoveryReader = {
      nonceAt: async (b) => (probed.push(b), nonceAt(b)),
      blockTransactions: async () => [],
    };
    await expect(discover(reader, 3, 1000)).rejects.toBeInstanceOf(InconsistentChainState);
    // The contradiction is detected on the first probe that disagrees, not after the search.
    expect(probed).toEqual([500n, 750n]);
  });

  it('fails closed on malformed block transactions instead of reporting no match', async () => {
    const reader: DiscoveryReader = {
      nonceAt: async (b) => (b >= 2n ? 1n : 0n),
      blockTransactions: async () => [{ hash: 'not-a-hash', from: ACCOUNT, nonce: '0x0' }],
    };
    await expect(discover(reader, 1, 10)).rejects.toBeInstanceOf(InconsistentChainState);
  });

  it('is deterministic: identical chains give identical evidence', async () => {
    const a = await discover(chain([7, 300]).reader, 2, 1000);
    const b = await discover(chain([7, 300]).reader, 2, 1000);
    expect(a).toEqual(b);
  });
});
