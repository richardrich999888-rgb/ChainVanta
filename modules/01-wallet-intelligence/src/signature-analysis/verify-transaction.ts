import { z } from 'zod';
import { keccak256, recoverTransactionAddress, serializeTransaction, type Hex } from 'viem';
import {
  Address,
  Hash,
  HexData,
  HexQuantity,
  SignatureEvidence,
} from '../../../../packages/domain-models/src/index.js';
const Transaction = z.object({
  hash: Hash,
  blockHash: Hash,
  blockNumber: HexQuantity,
  from: Address,
  to: Address.nullable(),
  type: z.enum(['0x0', '0x1', '0x2']),
  chainId: HexQuantity,
  nonce: HexQuantity,
  gas: HexQuantity,
  value: HexQuantity,
  input: HexData,
  gasPrice: HexQuantity.optional(),
  maxFeePerGas: HexQuantity.optional(),
  maxPriorityFeePerGas: HexQuantity.optional(),
  accessList: z.array(z.object({ address: Address, storageKeys: z.array(Hash) })).optional(),
  r: Hash,
  s: Hash,
  v: HexQuantity,
});
export async function verifyTransaction(
  raw: unknown,
  receipt: unknown,
  chainId: number,
  address: string,
  hash: string,
) {
  const tx = Transaction.parse(raw);
  const rc = z
    .object({
      transactionHash: Hash,
      blockHash: Hash,
      blockNumber: HexQuantity,
      status: z.enum(['0x0', '0x1']),
    })
    .parse(receipt);
  if (
    tx.hash !== hash ||
    rc.transactionHash !== hash ||
    rc.blockHash !== tx.blockHash ||
    rc.blockNumber !== tx.blockNumber ||
    BigInt(tx.chainId) !== BigInt(chainId) ||
    tx.from !== address
  )
    throw new Error('Inconsistent transaction context');
  const nonce = Number(BigInt(tx.nonce));
  if (!Number.isSafeInteger(nonce)) throw new Error('Unsupported nonce');
  const common = {
    chainId,
    nonce,
    gas: BigInt(tx.gas),
    value: BigInt(tx.value),
    data: tx.input as Hex,
    to: tx.to as Hex | undefined,
  };
  const signature = { r: tx.r as Hex, s: tx.s as Hex, v: BigInt(tx.v) };
  const accessList = (tx.accessList ?? []).map((v) => ({
    address: v.address as Hex,
    storageKeys: v.storageKeys as Hex[],
  }));
  const serialized =
    tx.type === '0x0'
      ? serializeTransaction(
          { ...common, type: 'legacy', gasPrice: BigInt(HexQuantity.parse(tx.gasPrice)) },
          signature,
        )
      : tx.type === '0x1'
        ? serializeTransaction(
            {
              ...common,
              type: 'eip2930',
              gasPrice: BigInt(HexQuantity.parse(tx.gasPrice)),
              accessList,
            },
            signature,
          )
        : serializeTransaction(
            {
              ...common,
              type: 'eip1559',
              maxFeePerGas: BigInt(HexQuantity.parse(tx.maxFeePerGas)),
              maxPriorityFeePerGas: BigInt(HexQuantity.parse(tx.maxPriorityFeePerGas)),
              accessList,
            },
            signature,
          );
  if (
    keccak256(serialized) !== hash ||
    (await recoverTransactionAddress({ serializedTransaction: serialized })).toLowerCase() !==
      address
  )
    throw new Error('Signature verification failed');
  return SignatureEvidence.parse({
    hash,
    blockHash: tx.blockHash,
    blockNumber: tx.blockNumber,
    sender: address,
    algorithm: 'ECDSA-secp256k1',
    serializedTransaction: serialized,
    receiptStatus: rc.status === '0x1' ? 'success' : 'reverted',
    parserVersion: 'evm-transaction/1.0.0',
  });
}
