import {
  decodeFunctionResult,
  encodeFunctionData,
  hexToBigInt,
  keccak256,
  parseAbi,
  toHex,
  type Hex,
} from 'viem';
import {
  AccountStructure,
  STRUCTURE_LIMITS,
  type StructureRead,
} from '../../../../packages/domain-models/src/index.js';

/**
 * Discovers EVM account structure: EIP-7702 delegation, EIP-1167 minimal proxies, EIP-1967 proxy
 * slots, Safe multisig accessors and the ERC-4337 `entryPoint()` accessor.
 *
 * Chain access goes through the `StructureReader` port, which the connector pins to one finalized
 * block hash. Everything else here is deterministic decoding of the returned bytes.
 */

/** A read-only call outcome. A revert is an answer ("not this interface"), not a failure. */
export type ProbeResult = { outcome: 'returned'; data: Hex } | { outcome: 'reverted' };

/** Port implemented by the connector. Every method reads state at the same pinned block. */
export interface StructureReader {
  /** Returns the 32-byte storage word, left-padded. */
  storage(target: Hex, slot: Hex): Promise<Hex>;
  code(target: Hex): Promise<Hex>;
  call(target: Hex, data: Hex): Promise<ProbeResult>;
}

// EIP-7702 delegation designator: 0xef0100 followed by the 20-byte delegate address.
const DELEGATION_PREFIX = '0xef0100';
const DELEGATION_LENGTH = 2 + 2 * 23;

// EIP-1167 canonical runtime code: prefix || implementation (20 bytes) || suffix.
const MINIMAL_PROXY_PREFIX = '0x363d3d373d3d3d363d73';
const MINIMAL_PROXY_SUFFIX = '5af43d82803e903d91602b57fd5bf3';
const MINIMAL_PROXY_LENGTH = MINIMAL_PROXY_PREFIX.length + 40 + MINIMAL_PROXY_SUFFIX.length;

/** EIP-1967 slot = keccak256(label) - 1, so the slot has no known storage-layout preimage. */
const eip1967Slot = (label: string): Hex =>
  toHex(hexToBigInt(keccak256(toHex(label))) - 1n, { size: 32 });
export const EIP1967_SLOTS = {
  implementation: eip1967Slot('eip1967.proxy.implementation'),
  admin: eip1967Slot('eip1967.proxy.admin'),
  beacon: eip1967Slot('eip1967.proxy.beacon'),
} as const;
/** Safe proxies keep the singleton address in storage slot 0. */
const SAFE_SINGLETON_SLOT = toHex(0n, { size: 32 });
/** Safe linked-list sentinel; also marks the end of `getModulesPaginated`. */
const SAFE_SENTINEL: Hex = '0x0000000000000000000000000000000000000001';
const ZERO_ADDRESS: Hex = '0x0000000000000000000000000000000000000000';
const MAX_VERSION_LENGTH = 32;

const abi = parseAbi([
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function VERSION() view returns (string)',
  'function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)',
  'function entryPoint() view returns (address)',
  'function implementation() view returns (address)',
]);

const lower = (value: string) => value.toLowerCase() as Hex;

/** Returns the delegate when `code` is exactly an EIP-7702 delegation designator. */
export function parseDelegation(code: string): Hex | null {
  const c = lower(code);
  return c.length === DELEGATION_LENGTH && c.startsWith(DELEGATION_PREFIX)
    ? (`0x${c.slice(DELEGATION_PREFIX.length)}` as Hex)
    : null;
}

/** Returns the implementation when `code` is exactly the canonical EIP-1167 runtime. */
export function parseMinimalProxy(code: string): Hex | null {
  const c = lower(code);
  if (
    c.length !== MINIMAL_PROXY_LENGTH ||
    !c.startsWith(MINIMAL_PROXY_PREFIX) ||
    !c.endsWith(MINIMAL_PROXY_SUFFIX)
  )
    return null;
  return `0x${c.slice(MINIMAL_PROXY_PREFIX.length, MINIMAL_PROXY_PREFIX.length + 40)}` as Hex;
}

/**
 * Interprets a 32-byte storage word as an address.
 * `empty`: all zero. `malformed`: upper 12 bytes non-zero, so the word is not an address.
 */
export function slotAddress(word: Hex): Hex | 'empty' | 'malformed' {
  const w = lower(word).slice(2).padStart(64, '0');
  if (/^0+$/.test(w)) return 'empty';
  if (!/^0{24}/.test(w)) return 'malformed';
  return `0x${w.slice(24)}` as Hex;
}

const codeHash = (code: Hex) => (code === '0x' ? null : keccak256(code));

/** Wraps the port and records every read in invocation order, independent of completion order. */
function recording(reader: StructureReader) {
  const reads: StructureRead[] = [];
  const reserve = () => {
    if (reads.length >= STRUCTURE_LIMITS.maxReads)
      throw new Error('Account structure read budget exceeded');
    reads.push(undefined as unknown as StructureRead);
    return reads.length - 1;
  };
  return {
    reads,
    async storage(target: Hex, slot: Hex) {
      const at = reserve();
      const result = await reader.storage(target, slot);
      reads[at] = { method: 'eth_getStorageAt', target, input: slot, outcome: 'returned', result };
      return result;
    },
    async code(target: Hex) {
      const at = reserve();
      const code = lower(await reader.code(target));
      const hash = codeHash(code);
      reads[at] = {
        method: 'eth_getCode',
        target,
        input: '0x',
        outcome: 'returned',
        ...(hash ? { codeHash: hash } : {}),
        codeSize: (code.length - 2) / 2,
      };
      return code;
    },
    async call(target: Hex, data: Hex): Promise<ProbeResult> {
      const at = reserve();
      const result = await reader.call(target, data);
      if (result.outcome === 'reverted') {
        reads[at] = { method: 'eth_call', target, input: data, outcome: 'reverted' };
        return result;
      }
      const size = (result.data.length - 2) / 2;
      if (size <= STRUCTURE_LIMITS.maxReturnBytes) {
        reads[at] = {
          method: 'eth_call',
          target,
          input: data,
          outcome: 'returned',
          result: result.data,
        };
        return result;
      }
      // Oversized: keep a verifiable fingerprint, store and decode nothing.
      reads[at] = {
        method: 'eth_call',
        target,
        input: data,
        outcome: 'returned',
        resultHash: keccak256(result.data),
        resultSize: size,
      };
      return { outcome: 'returned', data: '0x' };
    },
  };
}
type Recorder = ReturnType<typeof recording>;

/** Decodes a probe result; reverts and undecodable data both mean "interface not present". */
function decoded<T>(result: ProbeResult, decode: (data: Hex) => T): T | null {
  if (result.outcome !== 'returned' || result.data === '0x') return null;
  try {
    return decode(result.data);
  } catch {
    return null;
  }
}

async function readEip1967(r: Recorder, words: Record<string, Hex>) {
  const slots = {
    implementation: slotAddress(words.implementation!),
    admin: slotAddress(words.admin!),
    beacon: slotAddress(words.beacon!),
  };
  if (Object.values(slots).every((v) => v === 'empty')) return null;
  const address = (v: (typeof slots)[keyof typeof slots]) =>
    v === 'empty' || v === 'malformed' ? null : v;
  const implementation = address(slots.implementation);
  const beacon = address(slots.beacon);
  const [implementationCode, beaconResult] = await Promise.all([
    implementation ? r.code(implementation) : Promise.resolve(null),
    beacon
      ? r.call(beacon, encodeFunctionData({ abi, functionName: 'implementation' }))
      : Promise.resolve(null),
  ]);
  const beaconImplementation = beaconResult
    ? decoded(beaconResult, (data) =>
        decodeFunctionResult({ abi, functionName: 'implementation', data }),
      )
    : null;
  return {
    implementation,
    implementationCodeHash: implementationCode ? codeHash(implementationCode) : null,
    admin: address(slots.admin),
    beacon,
    beaconImplementation:
      beaconImplementation && lower(beaconImplementation) !== ZERO_ADDRESS
        ? lower(beaconImplementation)
        : null,
    malformedSlots: (['implementation', 'admin', 'beacon'] as const).filter(
      (k) => slots[k] === 'malformed',
    ),
  };
}

type SafeProbe = { owners: Hex[]; threshold: number; version: string | null };

/** Accepts Safe accessor data only when it is internally consistent. */
function validSafe(
  ownersResult: ProbeResult,
  thresholdResult: ProbeResult,
  versionResult: ProbeResult,
  limitations: string[],
): SafeProbe | null {
  const owners = decoded(ownersResult, (data) =>
    decodeFunctionResult({ abi, functionName: 'getOwners', data }),
  );
  const threshold = decoded(thresholdResult, (data) =>
    decodeFunctionResult({ abi, functionName: 'getThreshold', data }),
  );
  if (!owners || threshold === null || owners.length === 0) return null;
  const normalized = owners.map(lower);
  if (normalized.length > STRUCTURE_LIMITS.maxSafeOwners) {
    limitations.push(
      `Safe-compatible accessors report ${normalized.length} owners, above the supported ${STRUCTURE_LIMITS.maxSafeOwners}; owners were not recorded.`,
    );
    return null;
  }
  const distinct = new Set(normalized).size === normalized.length;
  const invalidOwner = normalized.some((o) => o === ZERO_ADDRESS || o === SAFE_SENTINEL);
  // Safe enforces 1 <= threshold <= owner count; anything else is not Safe-consistent data.
  if (!distinct || invalidOwner || threshold < 1n || threshold > BigInt(normalized.length))
    return null;
  const version = decoded(versionResult, (data) =>
    decodeFunctionResult({ abi, functionName: 'VERSION', data }),
  );
  return {
    owners: normalized,
    threshold: Number(threshold),
    version: version && version.length <= MAX_VERSION_LENGTH ? version : null,
  };
}

async function readSafeDetails(r: Recorder, account: Hex, probe: SafeProbe) {
  const checked = probe.owners.slice(0, STRUCTURE_LIMITS.maxOwnerCodeReads);
  const [modulesResult, singletonWord, ...ownerCodes] = await Promise.all([
    r.call(
      account,
      encodeFunctionData({
        abi,
        functionName: 'getModulesPaginated',
        args: [SAFE_SENTINEL, BigInt(STRUCTURE_LIMITS.safeModulePageSize)],
      }),
    ),
    r.storage(account, SAFE_SINGLETON_SLOT),
    ...checked.map((owner) => r.code(owner)),
  ]);
  const page = decoded(modulesResult, (data) =>
    decodeFunctionResult({ abi, functionName: 'getModulesPaginated', data }),
  );
  const singleton = slotAddress(singletonWord);
  return {
    ...probe,
    singleton: singleton === 'empty' || singleton === 'malformed' ? null : singleton,
    modules: page ? page[0].map(lower) : [],
    // Complete only when the page ends at the sentinel; a revert leaves modules unknown.
    modulesComplete: page !== null && lower(page[1]) === SAFE_SENTINEL,
    ownerCode: probe.owners.map((owner, i) => {
      const code = ownerCodes[i];
      if (code === undefined) return { owner, kind: 'not-checked' as const };
      if (code === '0x') return { owner, kind: 'no-code' as const };
      return {
        owner,
        kind: parseDelegation(code) ? ('eip-7702-delegated' as const) : ('contract' as const),
      };
    }),
  };
}

async function readEntryPoint(r: Recorder, result: ProbeResult) {
  const entryPoint = decoded(result, (data) =>
    decodeFunctionResult({ abi, functionName: 'entryPoint', data }),
  );
  if (!entryPoint || lower(entryPoint) === ZERO_ADDRESS) return null;
  const code = await r.code(lower(entryPoint));
  return { entryPoint: lower(entryPoint), entryPointHasCode: code !== '0x' };
}

const BASE_LIMITATIONS = [
  'Recognizes only EIP-7702 designators, canonical EIP-1167 runtime code, EIP-1967 slots, Safe-compatible accessors and the ERC-4337 entryPoint() accessor; other proxy and account patterns are not detected.',
  'Delegate, implementation and module code is not analyzed for its own authorization logic.',
];

/**
 * Discovers account structure for code-bearing accounts. Returns null for accounts without code.
 * Bounded: at most `STRUCTURE_LIMITS.maxReads` chain reads, independent of contract behavior.
 */
export async function discoverAccountStructure(
  reader: StructureReader,
  account: Hex,
  code: Hex,
): Promise<AccountStructure | null> {
  if (code === '0x') return null;
  const r = recording(reader);
  const limitations = [...BASE_LIMITATIONS];
  const delegate = parseDelegation(code);
  const minimal = parseMinimalProxy(code);
  const call = (functionName: 'getOwners' | 'getThreshold' | 'VERSION' | 'entryPoint') =>
    r.call(account, encodeFunctionData({ abi, functionName }));
  const [implementationWord, adminWord, beaconWord, owners, threshold, version, entryPoint] =
    await Promise.all([
      r.storage(account, EIP1967_SLOTS.implementation),
      r.storage(account, EIP1967_SLOTS.admin),
      r.storage(account, EIP1967_SLOTS.beacon),
      call('getOwners'),
      call('getThreshold'),
      call('VERSION'),
      call('entryPoint'),
    ]);
  const safeProbe = validSafe(owners, threshold, version, limitations);
  const [eip1967, minimalCode, safe, erc4337] = await Promise.all([
    readEip1967(r, {
      implementation: implementationWord,
      admin: adminWord,
      beacon: beaconWord,
    }),
    minimal ? r.code(minimal) : Promise.resolve(null),
    safeProbe ? readSafeDetails(r, account, safeProbe) : Promise.resolve(null),
    readEntryPoint(r, entryPoint),
  ]);
  if (safe || erc4337)
    limitations.push(
      'Safe and ERC-4337 data are accessor responses from contract code; a lookalike contract can return the same shape.',
    );
  if (safe && !safe.modulesComplete)
    limitations.push(
      'The Safe module list is incomplete or unavailable; modules can execute transactions without owner signatures.',
    );
  return AccountStructure.parse({
    parserVersion: 'evm-account-structure/1.0.0',
    delegation: delegate ? { standard: 'eip-7702', delegate } : null,
    minimalProxy: minimal
      ? {
          standard: 'eip-1167',
          implementation: minimal,
          implementationCodeHash: minimalCode ? codeHash(minimalCode) : null,
        }
      : null,
    eip1967,
    safe,
    erc4337,
    reads: r.reads,
    limitations,
  });
}
