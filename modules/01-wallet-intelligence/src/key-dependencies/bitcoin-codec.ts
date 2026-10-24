import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bech32, bech32m, createBase58check } from '@scure/base';
import {
  BITCOIN_NETWORKS,
  type BitcoinNetwork,
  type ScriptType,
} from '../../../../packages/domain-models/src/bitcoin.js';

/**
 * Bitcoin address and script codec. Pure: bytes in, classifications out.
 * Standards: BIP-13/BIP-16 (base58 P2PKH/P2SH), BIP-141 (witness programs), BIP-173 (bech32,
 * witness v0), BIP-350 (bech32m, witness v1+), BIP-341 (P2TR output keys).
 */

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const bytes = (value: string) => {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) throw new Error('Invalid hex');
  return new Uint8Array(Buffer.from(value, 'hex'));
};
/** HASH160 = RIPEMD-160(SHA-256(x)): the commitment in P2PKH, P2WPKH and P2SH. */
export const hash160 = (data: Uint8Array) => ripemd160(sha256(data));
export const sha256Hex = (data: Uint8Array) => hex(sha256(data));

const base58check = createBase58check(sha256);

// Script opcodes used by standard templates (Bitcoin Core script/script.h).
const OP = {
  0: 0x00,
  PUSHDATA1: 0x4c,
  PUSHDATA2: 0x4d,
  PUSHDATA4: 0x4e,
  1: 0x51,
  16: 0x60,
  DUP: 0x76,
  EQUAL: 0x87,
  EQUALVERIFY: 0x88,
  HASH160: 0xa9,
  CHECKSIG: 0xac,
  CHECKMULTISIG: 0xae,
} as const;
const COMPRESSED_KEY = 33;
const UNCOMPRESSED_KEY = 65;
const HASH160_BYTES = 20;
const SHA256_BYTES = 32;
const TAPROOT_KEY = 32;
/** Bare multisig and P2SH/P2WSH multisig are standard up to 3 and 20 keys; accept up to 20. */
const MAX_MULTISIG_KEYS = 20;

export interface DecodedTarget {
  scriptType: Extract<ScriptType, 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2wsh' | 'p2tr'>;
  /** Hash or witness program (P2TR: the x-only output key), lowercase hex. */
  program: string;
  scriptPubKey: string;
}

export class InvalidAddress extends Error {}

function scriptFor(scriptType: DecodedTarget['scriptType'], program: string): string {
  switch (scriptType) {
    case 'p2pkh':
      return `76a914${program}88ac`;
    case 'p2sh':
      return `a914${program}87`;
    case 'p2wpkh':
      return `0014${program}`;
    case 'p2wsh':
      return `0020${program}`;
    case 'p2tr':
      return `5120${program}`;
  }
}

function decodeSegwit(network: BitcoinNetwork, address: string): DecodedTarget {
  const lower = address.toLowerCase();
  // BIP-173: an address must not mix upper and lower case.
  if (address !== lower && address !== address.toUpperCase())
    throw new InvalidAddress('Mixed-case bech32 address');
  let decoded: { prefix: string; words: number[] };
  let encoding: 'bech32' | 'bech32m';
  try {
    decoded = bech32.decode(lower as `${string}1${string}`);
    encoding = 'bech32';
  } catch {
    try {
      decoded = bech32m.decode(lower as `${string}1${string}`);
      encoding = 'bech32m';
    } catch {
      throw new InvalidAddress('Invalid bech32 checksum');
    }
  }
  if (decoded.prefix !== BITCOIN_NETWORKS[network].hrp)
    throw new InvalidAddress('Address belongs to another network');
  const [version, ...data] = decoded.words;
  const program = hex(bech32.fromWords(data));
  const length = program.length / 2;
  // BIP-350: witness v0 uses bech32, v1+ uses bech32m.
  if (version === 0 && encoding === 'bech32' && length === HASH160_BYTES)
    return { scriptType: 'p2wpkh', program, scriptPubKey: scriptFor('p2wpkh', program) };
  if (version === 0 && encoding === 'bech32' && length === SHA256_BYTES)
    return { scriptType: 'p2wsh', program, scriptPubKey: scriptFor('p2wsh', program) };
  if (version === 1 && encoding === 'bech32m' && length === TAPROOT_KEY)
    return { scriptType: 'p2tr', program, scriptPubKey: scriptFor('p2tr', program) };
  throw new InvalidAddress('Unsupported witness version, program length or encoding');
}

function decodeBase58(network: BitcoinNetwork, address: string): DecodedTarget {
  let payload: Uint8Array;
  try {
    payload = base58check.decode(address);
  } catch {
    throw new InvalidAddress('Invalid base58check address');
  }
  if (payload.length !== 1 + HASH160_BYTES) throw new InvalidAddress('Invalid payload length');
  const params = BITCOIN_NETWORKS[network];
  const program = hex(payload.subarray(1));
  if (payload[0] === params.p2pkhVersion)
    return { scriptType: 'p2pkh', program, scriptPubKey: scriptFor('p2pkh', program) };
  if (payload[0] === params.p2shVersion)
    return { scriptType: 'p2sh', program, scriptPubKey: scriptFor('p2sh', program) };
  throw new InvalidAddress('Address belongs to another network');
}

/** Decodes and validates an address for `network`, including checksum and witness rules. */
export function decodeAddress(network: BitcoinNetwork, address: string): DecodedTarget {
  const hrp = BITCOIN_NETWORKS[network].hrp;
  return address.toLowerCase().startsWith(`${hrp}1`)
    ? decodeSegwit(network, address)
    : decodeBase58(network, address);
}

/** True when `key` is a valid SEC1 secp256k1 point (rejects off-curve or malformed bytes). */
export function isValidPublicKey(key: Uint8Array): boolean {
  if (key.length !== COMPRESSED_KEY && key.length !== UNCOMPRESSED_KEY) return false;
  try {
    secp256k1.ProjectivePoint.fromHex(key).assertValidity();
    return true;
  } catch {
    return false;
  }
}

/** Data pushes of a script, or null when it contains any non-push opcode (OP_n excluded). */
export function pushes(script: Uint8Array): Uint8Array[] | null {
  const out: Uint8Array[] = [];
  for (let i = 0; i < script.length;) {
    const op = script[i++]!;
    let size: number;
    if (op === OP[0]) size = 0;
    else if (op < OP.PUSHDATA1) size = op;
    else if (op === OP.PUSHDATA1) size = script[i++] ?? -1;
    else if (op === OP.PUSHDATA2) {
      size = i + 2 <= script.length ? script[i]! | (script[i + 1]! << 8) : -1;
      i += 2;
    } else if (op === OP.PUSHDATA4) {
      size =
        i + 4 <= script.length
          ? (script[i]! |
              (script[i + 1]! << 8) |
              (script[i + 2]! << 16) |
              (script[i + 3]! << 24)) >>>
            0
          : -1;
      i += 4;
    } else return null;
    if (size < 0 || i + size > script.length) return null;
    out.push(script.subarray(i, i + size));
    i += size;
  }
  return out;
}

/** Standard m-of-n CHECKMULTISIG script: OP_m <key>... OP_n OP_CHECKMULTISIG. */
export function parseMultisig(
  script: Uint8Array,
): { threshold: number; keys: Uint8Array[] } | null {
  if (script.length < 3 || script[script.length - 1] !== OP.CHECKMULTISIG) return null;
  const m = script[0]!;
  const n = script[script.length - 2]!;
  if (m < OP[1] || m > OP[16] || n < OP[1] || n > OP[16]) return null;
  const body = pushes(script.subarray(1, script.length - 2));
  const threshold = m - OP[1] + 1;
  const count = n - OP[1] + 1;
  if (!body || body.length !== count || count > MAX_MULTISIG_KEYS || threshold > count) return null;
  if (!body.every(isValidPublicKey)) return null;
  return { threshold, keys: body };
}

export interface ClassifiedScript {
  scriptType: ScriptType;
  /** Keys present in the script itself (P2PK, bare multisig; P2TR x-only output key). */
  keys: string[];
}

/** Classifies a scriptPubKey from its bytes. Node-supplied type labels are never trusted. */
export function classifyScript(scriptHex: string): ClassifiedScript {
  const s = bytes(scriptHex);
  const keyAt = (offset: number, size: number) => hex(s.subarray(offset, offset + size));
  // P2PK: <33|65-byte key> OP_CHECKSIG
  for (const size of [COMPRESSED_KEY, UNCOMPRESSED_KEY])
    if (s.length === size + 2 && s[0] === size && s[size + 1] === OP.CHECKSIG) {
      const key = s.subarray(1, size + 1);
      return isValidPublicKey(key)
        ? { scriptType: 'p2pk', keys: [hex(key)] }
        : { scriptType: 'unknown', keys: [] };
    }
  if (
    s.length === 25 &&
    s[0] === OP.DUP &&
    s[1] === OP.HASH160 &&
    s[2] === HASH160_BYTES &&
    s[23] === OP.EQUALVERIFY &&
    s[24] === OP.CHECKSIG
  )
    return { scriptType: 'p2pkh', keys: [] };
  if (s.length === 23 && s[0] === OP.HASH160 && s[1] === HASH160_BYTES && s[22] === OP.EQUAL)
    return { scriptType: 'p2sh', keys: [] };
  if (s.length === 22 && s[0] === OP[0] && s[1] === HASH160_BYTES)
    return { scriptType: 'p2wpkh', keys: [] };
  if (s.length === 34 && s[0] === OP[0] && s[1] === SHA256_BYTES)
    return { scriptType: 'p2wsh', keys: [] };
  if (s.length === 34 && s[0] === OP[1] && s[1] === TAPROOT_KEY)
    return { scriptType: 'p2tr', keys: [keyAt(2, TAPROOT_KEY)] };
  const multisig = parseMultisig(s);
  if (multisig) return { scriptType: 'bare-multisig', keys: multisig.keys.map(hex) };
  return { scriptType: 'unknown', keys: [] };
}

/** Whether an output's own script reveals its key now, or only a hash until spent. */
export function keyExposure(scriptType: ScriptType) {
  if (scriptType === 'p2pk' || scriptType === 'bare-multisig' || scriptType === 'p2tr')
    return 'public-key-in-script' as const;
  if (scriptType === 'unknown') return 'unknown' as const;
  return 'hash-locked' as const;
}

export { bytes as fromHex, hex as toHex };
