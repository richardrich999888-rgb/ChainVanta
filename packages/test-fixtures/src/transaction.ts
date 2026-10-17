import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, parseTransaction, toHex } from 'viem';
import { ADDRESS, BLOCK_HASH } from './fixtures.js';
export async function signedTransactionFixture() {
  // Public deterministic TEST ONLY key; signatures never leave the local test process.
  const account = privateKeyToAccount(`0x${'11'.repeat(32)}`);
  const serialized = await account.signTransaction({
    chainId: 1,
    nonce: 0,
    gas: 21000n,
    to: ADDRESS,
    value: 0n,
    type: 'eip1559',
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
    accessList: [],
  });
  const parsed = parseTransaction(serialized),
    hash = keccak256(serialized),
    address = account.address.toLowerCase();
  return {
    hash,
    address,
    raw: {
      hash,
      blockHash: BLOCK_HASH,
      blockNumber: '0x100',
      from: address,
      to: ADDRESS,
      type: '0x2',
      chainId: '0x1',
      nonce: '0x0',
      gas: '0x5208',
      value: '0x0',
      input: '0x',
      maxFeePerGas: '0x2',
      maxPriorityFeePerGas: '0x1',
      accessList: [],
      r: parsed.r,
      s: parsed.s,
      v: toHex(parsed.v ?? BigInt(parsed.yParity!)),
    },
    receipt: { transactionHash: hash, blockHash: BLOCK_HASH, blockNumber: '0x100', status: '0x1' },
  };
}
