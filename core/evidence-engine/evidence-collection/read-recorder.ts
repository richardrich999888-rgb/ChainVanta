import { keccak256, type Hex } from 'viem';
import type { StructureRead } from '../../../packages/domain-models/src/index.js';

/**
 * Shared, pinned on-chain read port and recorder used by evidence collectors (account structure,
 * token authority). The connector implements the port against one block hash; collectors record
 * every read so a reviewer can replay a classification at the same block.
 */

/** A read-only call outcome. A revert or halt is an answer ("not this interface"), not a failure. */
export type ProbeResult = { outcome: 'returned'; data: Hex } | { outcome: 'reverted' };

/** Port implemented by the connector. Every method reads state at the same pinned block. */
export interface ChainReader {
  /** Returns the 32-byte storage word, left-padded. */
  storage(target: Hex, slot: Hex): Promise<Hex>;
  code(target: Hex): Promise<Hex>;
  call(target: Hex, data: Hex): Promise<ProbeResult>;
}

export interface RecorderLimits {
  /** Reads allowed through this recorder; exceeding it is a programming error, not data. */
  maxReads: number;
  /** Return data above this size is fingerprinted (hash and size) and decoded as empty. */
  maxReturnBytes: number;
}

const lower = (value: string) => value.toLowerCase() as Hex;
export const codeHash = (code: Hex) => (code === '0x' ? null : keccak256(code));

/** Wraps the port and records every read in invocation order, independent of completion order. */
export function recording(reader: ChainReader, limits: RecorderLimits) {
  const reads: StructureRead[] = [];
  const reserve = () => {
    if (reads.length >= limits.maxReads) throw new Error('Evidence read budget exceeded');
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
      if (size <= limits.maxReturnBytes) {
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
export type Recorder = ReturnType<typeof recording>;

/** Decodes a probe result; reverts and undecodable data both mean "interface not present". */
export function decoded<T>(result: ProbeResult, decode: (data: Hex) => T): T | null {
  if (result.outcome !== 'returned' || result.data === '0x') return null;
  try {
    return decode(result.data);
  } catch {
    return null;
  }
}
