import { z } from 'zod';
import {
  RevealedSpend,
  type RevealedSpend as RevealedSpendType,
} from '../../../../packages/domain-models/src/bitcoin.js';
import {
  fromHex,
  hash160,
  isValidPublicKey,
  parseMultisig,
  pushes,
  sha256Hex,
  toHex,
  type DecodedTarget,
} from '../key-dependencies/bitcoin-codec.js';

/**
 * Extracts key material a confirmed transaction revealed for a target.
 *
 * Exposure does not depend on signature validity: once a key or script is published in a block
 * on the active chain, it is public. So instead of re-deriving sighashes, every revealed key must
 * match the target's on-chain commitment exactly (HASH160 for P2PKH/P2WPKH/P2SH, SHA-256 for
 * P2WSH) and be a valid secp256k1 point. Block inclusion is checked from the node's verbose fields.
 */

const Hex = z.string().regex(/^(?:[0-9a-fA-F]{2})*$/);
const VerboseTransaction = z.object({
  txid: z.string().regex(/^[0-9a-f]{64}$/),
  blockhash: z.string().regex(/^[0-9a-f]{64}$/),
  confirmations: z.number().int(),
  in_active_chain: z.literal(true),
  vin: z
    .array(
      z.object({
        coinbase: Hex.optional(),
        scriptSig: z.object({ hex: Hex }).optional(),
        txinwitness: z.array(Hex).optional(),
      }),
    )
    .min(1)
    .max(10_000),
});

export class InvalidSpendEvidence extends Error {}

export type SpendTarget =
  { kind: 'address'; decoded: DecodedTarget } | { kind: 'public-key'; key: string };

type Input = { scriptSig: Uint8Array[] | null; witness: Uint8Array[] };
type Match = Omit<RevealedSpendType, 'txid' | 'blockHash' | 'confirmations' | 'inputIndex'>;

const equalHex = (a: Uint8Array, b: string) => toHex(a) === b;

/** Script-hash targets reveal a script; standard multisig scripts yield their keys. */
function multisigMatch(script: Uint8Array, source: Match['source']): Match | null {
  const multisig = parseMultisig(script);
  return multisig
    ? { source, publicKeys: multisig.keys.map(toHex), threshold: multisig.threshold }
    : null;
}

function matchAddress(target: DecodedTarget, input: Input): Match | null {
  const { program } = target;
  const lastWitness = input.witness.at(-1);
  const lastPush = input.scriptSig?.at(-1);
  switch (target.scriptType) {
    case 'p2pkh': {
      // scriptSig: <sig> <pubkey>
      const key = input.scriptSig?.length === 2 ? input.scriptSig[1]! : null;
      return key && isValidPublicKey(key) && equalHex(hash160(key), program)
        ? { source: 'p2pkh-scriptsig', publicKeys: [toHex(key)], threshold: null }
        : null;
    }
    case 'p2wpkh': {
      // witness: <sig> <pubkey>
      const key = input.witness.length === 2 ? input.witness[1]! : null;
      return key && isValidPublicKey(key) && equalHex(hash160(key), program)
        ? { source: 'p2wpkh-witness', publicKeys: [toHex(key)], threshold: null }
        : null;
    }
    case 'p2sh': {
      if (!lastPush || !equalHex(hash160(lastPush), program)) return null;
      // Nested P2WPKH: redeemScript = OP_0 <20-byte key hash>; key in witness.
      if (lastPush.length === 22 && lastPush[0] === 0x00 && lastPush[1] === 0x14) {
        const key = input.witness.length === 2 ? input.witness[1]! : null;
        return key && isValidPublicKey(key) && equalHex(hash160(key), toHex(lastPush.subarray(2)))
          ? { source: 'p2sh-p2wpkh-witness', publicKeys: [toHex(key)], threshold: null }
          : null;
      }
      // Nested P2WSH: redeemScript = OP_0 <32-byte script hash>; witnessScript is the last item.
      if (lastPush.length === 34 && lastPush[0] === 0x00 && lastPush[1] === 0x20)
        return lastWitness && sha256Hex(lastWitness) === toHex(lastPush.subarray(2))
          ? multisigMatch(lastWitness, 'p2wsh-witness-script')
          : null;
      return multisigMatch(lastPush, 'p2sh-redeem-script');
    }
    case 'p2wsh':
      return lastWitness && sha256Hex(lastWitness) === program
        ? multisigMatch(lastWitness, 'p2wsh-witness-script')
        : null;
    case 'p2tr':
      // The address already is the output key; a key-path spend reveals nothing more.
      return null;
  }
}

/** A public-key target is revealed when an input pushes exactly that key. */
function matchKey(key: string, input: Input): Match | null {
  const items = [...(input.scriptSig ?? []), ...input.witness];
  const hit = items.find((item) => equalHex(item, key) && isValidPublicKey(item));
  return hit
    ? {
        source: input.witness.some((w) => equalHex(w, key)) ? 'p2wpkh-witness' : 'p2pkh-scriptsig',
        publicKeys: [key],
        threshold: null,
      }
    : null;
}

/**
 * Returns the first input of `raw` (a `getrawtransaction <txid> true <blockhash>` result) that
 * reveals key material for `target`, or null. Throws InvalidSpendEvidence when the transaction is
 * not the requested one, not in the requested block, or not on the active chain.
 */
export function extractRevealedSpend(
  raw: unknown,
  requested: { txid: string; blockHash: string },
  target: SpendTarget,
): RevealedSpendType | null {
  const parsed = VerboseTransaction.safeParse(raw);
  if (!parsed.success) throw new InvalidSpendEvidence('Malformed or unconfirmed transaction');
  const tx = parsed.data;
  if (tx.txid !== requested.txid || tx.blockhash !== requested.blockHash)
    throw new InvalidSpendEvidence('Transaction or block does not match the request');
  if (tx.confirmations < 1) throw new InvalidSpendEvidence('Transaction is not confirmed');
  for (const [inputIndex, vin] of tx.vin.entries()) {
    if (vin.coinbase !== undefined) continue;
    const input: Input = {
      scriptSig: pushes(fromHex(vin.scriptSig?.hex ?? '')),
      witness: (vin.txinwitness ?? []).map(fromHex),
    };
    const match =
      target.kind === 'address' ? matchAddress(target.decoded, input) : matchKey(target.key, input);
    if (match)
      return RevealedSpend.parse({
        ...match,
        txid: tx.txid,
        blockHash: tx.blockhash,
        confirmations: tx.confirmations,
        inputIndex,
      });
  }
  return null;
}
