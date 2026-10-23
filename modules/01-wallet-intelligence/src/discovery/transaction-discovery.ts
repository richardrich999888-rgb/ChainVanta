import { z } from 'zod';
import { recoverAuthorizationAddress } from 'viem/utils';
import type { Hex } from 'viem';
import {
  Address,
  Hash,
  HexQuantity,
  MAX_DISCOVERY_PROBES,
  TransactionDiscovery,
} from '../../../../packages/domain-models/src/index.js';

/**
 * Locates an account's latest sent transaction using only standard JSON-RPC.
 *
 * Method (nonce bisection):
 *   N = nonce at the snapshot block F. An account nonce never decreases, so the predicate
 *   P(b) = "post-state nonce at block b >= N" is monotone over b in [0, F], false before the
 *   transaction with nonce N - 1 executes and true from its block onward, with P(F) true.
 *   Binary search finds the lowest b with P(b): block B. The account's last nonce use is in B,
 *   either a transaction it sent or an EIP-7702 authorization it signed (a self-sponsored
 *   set-code transaction uses nonce k for the transaction and k + 1 for its own authorization).
 *   Reads: ceil(log2(F + 1)) historical nonce reads plus one block read, independent of
 *   account activity. Historical state requires an archive-capable provider.
 *
 * Every probe is recorded so a reviewer can replay the search at the same blocks.
 */

/** Port implemented by the connector. */
export interface DiscoveryReader {
  /** Post-state nonce of `address` after block `blockNumber`. */
  nonceAt(blockNumber: bigint): Promise<bigint>;
  /** Transactions in block `blockNumber` with at least sender, nonce, hash and type. */
  blockTransactions(blockNumber: bigint): Promise<unknown[]>;
}

/** Transaction types the signature verifier reconstructs: legacy, EIP-2930, EIP-1559. */
export const VERIFIABLE_TYPES: readonly string[] = ['0x0', '0x1', '0x2'];

const SignedAuthorization = z.object({
  chainId: HexQuantity,
  address: Address,
  nonce: HexQuantity,
  yParity: HexQuantity,
  r: HexQuantity,
  s: HexQuantity,
});
const BlockTransaction = z.object({
  hash: Hash,
  from: Address,
  nonce: HexQuantity,
  // Pre-EIP-2718 providers may omit `type` for legacy transactions.
  type: HexQuantity.optional(),
  authorizationList: z.array(SignedAuthorization).optional(),
});
type BlockTransaction = z.infer<typeof BlockTransaction>;
/** Signature recoveries per block; a block above this is not interpreted (fail closed). */
export const MAX_AUTHORIZATION_RECOVERIES = 1024;

const hex = (value: bigint) => `0x${value.toString(16)}`;
/** Descending comparator on hex nonces. */
const byNonceDesc = (x: { nonce: string }, y: { nonce: string }) => {
  const [a, b] = [BigInt(x.nonce), BigInt(y.nonce)];
  return a === b ? 0 : a < b ? 1 : -1;
};

/** Thrown when provider answers contradict nonce monotonicity; never guessed around. */
export class InconsistentChainState extends Error {}

export interface DiscoveryInput {
  address: string;
  /** Nonce at the snapshot block. */
  accountNonce: bigint;
  snapshotBlock: bigint;
  chainId: number;
  /** False for code-bearing accounts without an EIP-7702 designator. */
  canSendTransactions: boolean;
  /** EIP-7702 delegated at the snapshot: delegated code can consume nonces through CREATE. */
  isDelegated: boolean;
}

/**
 * EIP-7702 authorizations in the block signed by `account`, with the nonce each consumed.
 * Only chain ID 0 (any chain) or this chain can apply. Signers are recovered, never trusted.
 */
async function accountAuthorizations(
  transactions: BlockTransaction[],
  account: string,
  chainId: number,
  below: bigint,
) {
  const candidates = transactions.flatMap((t) =>
    (t.authorizationList ?? []).map((a) => ({ transactionHash: t.hash, a })),
  );
  if (candidates.length > MAX_AUTHORIZATION_RECOVERIES)
    throw new InconsistentChainState('Block authorization count exceeds recovery bound');
  const recovered = await Promise.all(
    candidates
      .filter(({ a }) => BigInt(a.chainId) === 0n || BigInt(a.chainId) === BigInt(chainId))
      .filter(({ a }) => BigInt(a.nonce) < below)
      .map(async ({ transactionHash, a }) => {
        const authority = await recoverAuthorizationAddress({
          authorization: {
            address: a.address as Hex,
            chainId: Number(BigInt(a.chainId)),
            nonce: Number(BigInt(a.nonce)),
            r: `0x${a.r.slice(2).padStart(64, '0')}` as Hex,
            s: `0x${a.s.slice(2).padStart(64, '0')}` as Hex,
            yParity: Number(BigInt(a.yParity)),
          },
        }).catch(() => null); // An invalid signature is simply not this account's authorization.
        return { transactionHash, a, authority: authority?.toLowerCase() ?? null };
      }),
  );
  return recovered.filter((r) => r.authority === account).sort((x, y) => byNonceDesc(x.a, y.a));
}

/** Runs nonce bisection. Pure apart from the injected reader. */
export async function discoverLatestTransaction(
  reader: DiscoveryReader,
  input: DiscoveryInput,
): Promise<TransactionDiscovery> {
  const address = Address.parse(input.address);
  const base = {
    method: 'nonce-bisection/1.0.0' as const,
    accountNonce: input.accountNonce.toString(),
    blockNumber: null,
    transactionHash: null,
    transactionType: null,
    authorization: null,
    probes: [] as { blockNumber: string; nonce: string }[],
  };
  if (!input.canSendTransactions)
    return TransactionDiscovery.parse({ ...base, outcome: 'not-applicable' });
  if (input.accountNonce === 0n)
    return TransactionDiscovery.parse({ ...base, outcome: 'no-sent-transactions' });

  // Invariant: P(hi) holds; every block below lo fails P.
  let lo = 0n;
  let hi = input.snapshotBlock;
  while (lo < hi) {
    if (base.probes.length >= MAX_DISCOVERY_PROBES)
      throw new InconsistentChainState('Bisection exceeded its bound');
    const mid = (lo + hi) / 2n; // bigint division floors
    const nonce = await reader.nonceAt(mid);
    // Nonces never decrease: each probe must agree with every earlier probe and with the
    // snapshot. Disagreement means the provider's historical state is inconsistent.
    const contradicts = base.probes.some((p) => {
      const block = BigInt(p.blockNumber);
      const seen = BigInt(p.nonce);
      return (block < mid && seen > nonce) || (block > mid && seen < nonce);
    });
    base.probes.push({ blockNumber: hex(mid), nonce: nonce.toString() });
    if (nonce > input.accountNonce || contradicts)
      throw new InconsistentChainState('Historical nonces are not monotone');
    if (nonce >= input.accountNonce) hi = mid;
    else lo = mid + 1n;
  }
  // Fail closed: a dropped malformed entry could hide the match and misreport "no transaction".
  const parsed = (await reader.blockTransactions(lo)).map((t) => BlockTransaction.safeParse(t));
  if (parsed.some((r) => !r.success))
    throw new InconsistentChainState('Block contains a malformed transaction');
  const transactions = parsed.flatMap((r) => (r.success ? [r.data] : []));
  const block = { ...base, blockNumber: hex(lo) };
  // The account's latest sent transaction is its highest-nonce transaction in block B.
  const sent = transactions
    .filter((t) => t.from === address && BigInt(t.nonce) < input.accountNonce)
    .sort(byNonceDesc)[0];
  const sentType = sent ? (sent.type ?? '0x0') : null;
  const sentEvidence = sent
    ? { transactionHash: sent.hash.toLowerCase(), transactionType: sentType }
    : {};
  // Prefer verifiable evidence: a supported sent transaction, then a recovered authorization
  // signature, then an unverifiable sent transaction.
  if (sent && VERIFIABLE_TYPES.includes(sentType!))
    return TransactionDiscovery.parse({ ...block, ...sentEvidence, outcome: 'found' });
  const [authorization] = await accountAuthorizations(
    transactions,
    address,
    input.chainId,
    input.accountNonce,
  );
  if (authorization)
    return TransactionDiscovery.parse({
      ...block,
      outcome: 'authorization-signature',
      authorization: {
        transactionHash: authorization.transactionHash.toLowerCase(),
        nonce: BigInt(authorization.a.nonce).toString(),
        chainId: BigInt(authorization.a.chainId).toString(),
        delegate: authorization.a.address,
        authority: authorization.authority,
      },
    });
  if (sent)
    return TransactionDiscovery.parse({
      ...block,
      ...sentEvidence,
      outcome: 'unsupported-transaction-type',
    });
  // Only delegated code can consume a nonce without a sent transaction or authorization.
  if (!input.isDelegated)
    throw new InconsistentChainState('Nonce changed without a transaction or authorization');
  return TransactionDiscovery.parse({ ...block, outcome: 'no-matching-transaction' });
}
