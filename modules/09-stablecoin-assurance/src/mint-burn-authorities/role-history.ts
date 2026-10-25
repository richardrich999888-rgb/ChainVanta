import { decodeFunctionResult, encodeFunctionData, parseAbi, type Hex } from 'viem';
import { z } from 'zod';
import {
  Address,
  Hash,
  HexQuantity,
  ROLE_HISTORY_LIMITS,
  SUPPLY_OR_LOGIC_ROLES,
  TOKEN_AUTHORITY_LIMITS,
  type RoleHistory,
  type TokenAuthority,
} from '../../../../packages/domain-models/src/index.js';
import {
  decoded,
  recording,
  type ChainReader,
} from '../../../../core/evidence-engine/evidence-collection/read-recorder.js';
import {
  ROLE_GRANTED,
  ROLE_IDS,
  ROLE_REVOKED,
  roleName,
  type AccessControlRole,
} from './access-control.js';

/**
 * Reconstructs AccessControl role holders for contracts that cannot enumerate them.
 *
 * Method:
 *   1. Candidates: RoleGranted/RoleRevoked logs emitted by the token over [0, snapshot block].
 *      A rejected range (provider block-range or result limits) is bisected; requests are capped,
 *      and uncovered ranges are reported as gaps.
 *   2. Holders: each (role, account) whose latest event is a grant is checked with hasRole at the
 *      pinned block hash. Only `true` answers become holders, so a holder is never invented from
 *      logs alone; logs only bound which accounts are asked.
 * Completeness ("no other holder exists") additionally requires: no gaps, every candidate checked,
 * an operator attestation that the provider serves full log history (pruned history can return
 * empty results), and a contract that emits the standard events for every change, as OpenZeppelin
 * AccessControl does. Without all of these, `holdersComplete` is false.
 */

/** Port implemented by the connector. Ranges are inclusive block numbers at or below a finalized block. */
export interface HistoryReader {
  logs(
    address: Hex,
    topic0: readonly Hex[],
    fromBlock: bigint,
    toBlock: bigint,
  ): Promise<LogsResult>;
}
export type LogsResult =
  | { outcome: 'returned'; logs: unknown[] }
  /** Provider refused the range size or result count; a smaller range may succeed. */
  | { outcome: 'range-limited' }
  /** Provider reports the history as pruned or unavailable; splitting will not help. */
  | { outcome: 'unavailable' };

/** Provider data contradicts the requested filter; never interpreted. */
export class InconsistentHistory extends Error {}

const TOPICS = [ROLE_GRANTED, ROLE_REVOKED] as const;
const MAX_HOLDERS = TOKEN_AUTHORITY_LIMITS.maxHoldersPerRole;
/** hasRole returns one ABI word. */
const BOOL_RETURN_BYTES = 32;
const abi = parseAbi(['function hasRole(bytes32 role, address account) view returns (bool)']);
const Word = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const RawLog = z.object({
  address: Address,
  topics: z.array(Word),
  blockNumber: HexQuantity,
  transactionHash: Hash,
  logIndex: HexQuantity,
  removed: z.boolean().optional(),
});
type Event = RoleHistory['events'][number];
type Role = TokenAuthority['roles'][number];

/** Topic word to address; the upper 12 bytes of an indexed address topic must be zero. */
function topicAddress(word: string): Hex {
  if (!/^0x0{24}/i.test(word)) throw new InconsistentHistory('Indexed account is not an address');
  return `0x${word.slice(26).toLowerCase()}` as Hex;
}

/** Validates one provider log against the filter and decodes it. */
function decodeLog(raw: unknown, token: Hex, fromBlock: bigint, toBlock: bigint): Event {
  const log = RawLog.safeParse(raw);
  if (!log.success) throw new InconsistentHistory('Malformed log');
  const { address, topics, blockNumber, transactionHash, logIndex, removed } = log.data;
  const block = BigInt(blockNumber);
  const topic0 = topics[0]?.toLowerCase();
  if (
    address.toLowerCase() !== token.toLowerCase() ||
    removed === true ||
    topics.length !== 4 ||
    !TOPICS.includes(topic0 as Hex) ||
    block < fromBlock ||
    block > toBlock
  )
    throw new InconsistentHistory('Log outside the requested filter');
  const roleId = topics[1]!.toLowerCase() as Hex;
  return {
    roleId,
    role: roleName(roleId),
    account: topicAddress(topics[2]!),
    kind: topic0 === ROLE_GRANTED ? 'granted' : 'revoked',
    blockNumber: block.toString(),
    transactionHash: transactionHash.toLowerCase(),
    logIndex: Number(BigInt(logIndex)),
  };
}

/** Chain order: block, then log index. */
const chainOrder = (a: Event, b: Event) => {
  const [x, y] = [BigInt(a.blockNumber), BigInt(b.blockNumber)];
  return x === y ? a.logIndex - b.logIndex : x < y ? -1 : 1;
};

interface Coverage {
  requests: RoleHistory['requests'];
  gaps: RoleHistory['gaps'];
  events: Event[];
}

/**
 * Covers [0, snapshot] with at most maxLogRequests requests. Ranges are processed newest-first
 * (recent grants matter most when coverage runs out); a rejected range splits at its midpoint.
 */
async function scan(history: HistoryReader, token: Hex, snapshotBlock: bigint): Promise<Coverage> {
  const coverage: Coverage = { requests: [], gaps: [], events: [] };
  const pending: [bigint, bigint][] = [[0n, snapshotBlock]];
  const gap = (from: bigint, to: bigint) =>
    coverage.gaps.push({ fromBlock: from.toString(), toBlock: to.toString() });
  while (pending.length && coverage.requests.length < ROLE_HISTORY_LIMITS.maxLogRequests) {
    const [from, to] = pending.pop()!;
    const result = await history.logs(token, TOPICS, from, to);
    const room = ROLE_HISTORY_LIMITS.maxEvents - coverage.events.length;
    // Too many events for the remaining room is handled like a provider result limit.
    const outcome =
      result.outcome === 'returned' && result.logs.length > room ? 'range-limited' : result.outcome;
    coverage.requests.push({
      fromBlock: from.toString(),
      toBlock: to.toString(),
      outcome,
      logCount: result.outcome === 'returned' ? result.logs.length : 0,
    });
    if (outcome === 'returned' && result.outcome === 'returned')
      coverage.events.push(...result.logs.map((log) => decodeLog(log, token, from, to)));
    else if (outcome === 'range-limited' && from < to) {
      const mid = from + (to - from) / 2n;
      pending.push([from, mid], [mid + 1n, to]); // Upper half pops first.
    } else gap(from, to);
  }
  for (const [from, to] of pending) gap(from, to);
  coverage.gaps.sort((a, b) => (BigInt(a.fromBlock) < BigInt(b.fromBlock) ? -1 : 1));
  coverage.events.sort(chainOrder);
  return coverage;
}

/** (role, account) pairs whose latest event is a grant, most important first. */
function candidates(events: Event[]): { role: AccessControlRole; account: Hex }[] {
  const latest = new Map<string, Event>();
  for (const event of events) if (event.role) latest.set(`${event.role}:${event.account}`, event);
  const granted = [...latest.values()].filter((e) => e.kind === 'granted');
  const rank = (e: Event) => (SUPPLY_OR_LOGIC_ROLES.includes(e.role!) ? 0 : 1);
  return granted
    .sort((a, b) => rank(a) - rank(b) || -chainOrder(a, b) || a.account.localeCompare(b.account))
    .map((e) => ({ role: e.role as AccessControlRole, account: e.account as Hex }));
}

export interface RoleHistoryResult {
  history: RoleHistory;
  roles: Role[];
}

/** Runs the scan and verification. Pure apart from the injected ports. */
export async function discoverRoleHistory(
  history: HistoryReader,
  reader: ChainReader,
  token: Hex,
  snapshotBlock: bigint,
  attested: boolean,
): Promise<RoleHistoryResult> {
  const coverage = await scan(history, token, snapshotBlock);
  const all = candidates(coverage.events);
  const checked = all.slice(0, ROLE_HISTORY_LIMITS.maxVerifications);
  const r = recording(reader, {
    maxReads: ROLE_HISTORY_LIMITS.maxVerifications,
    maxReturnBytes: BOOL_RETURN_BYTES,
  });
  const answers = await Promise.all(
    checked.map(({ role, account }) =>
      r.call(
        token,
        encodeFunctionData({ abi, functionName: 'hasRole', args: [ROLE_IDS[role], account] }),
      ),
    ),
  );
  const holds = answers.map((a) =>
    decoded(a, (data) => decodeFunctionResult({ abi, functionName: 'hasRole', data })),
  );
  const complete = coverage.gaps.length === 0 && attested;
  const roles = (Object.keys(ROLE_IDS) as AccessControlRole[]).map((role): Role => {
    const indexes = checked.flatMap((c, i) => (c.role === role ? [i] : []));
    const holders = indexes.filter((i) => holds[i] === true).map((i) => checked[i]!.account);
    return {
      role,
      source: 'access-control-events',
      holders: holders.slice(0, MAX_HOLDERS),
      holdersComplete:
        complete &&
        // Every candidate for this role was asked, and each answer decoded.
        all.filter((c) => c.role === role).length === indexes.length &&
        indexes.every((i) => holds[i] !== null) &&
        holders.length <= MAX_HOLDERS,
    };
  });
  const unrecognized = [
    ...new Set(coverage.events.filter((e) => e.role === null).map((e) => e.roleId)),
  ].slice(0, ROLE_HISTORY_LIMITS.maxUnrecognizedRoles);
  return {
    roles,
    history: {
      method: 'access-control-events/1.0.0',
      fromBlock: '0',
      toBlock: snapshotBlock.toString(),
      historyAttested: attested,
      requests: coverage.requests,
      gaps: coverage.gaps,
      events: coverage.events,
      unrecognizedRoleIds: unrecognized,
      reads: r.reads,
      complete,
    },
  };
}
