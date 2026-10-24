import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  BITCOIN_NETWORKS,
  BitcoinScanRequest,
  bip122ChainId,
  type BitcoinObservation,
} from '../../packages/domain-models/src/bitcoin.js';
import {
  InvalidAddress,
  classifyScript,
  decodeAddress,
  fromHex,
  hash160,
  keyExposure,
  pushes,
  sha256Hex,
  toHex,
} from '../../modules/01-wallet-intelligence/src/key-dependencies/bitcoin-codec.js';
import {
  InvalidSpendEvidence,
  extractRevealedSpend,
} from '../../modules/01-wallet-intelligence/src/signature-analysis/bitcoin-spend.js';
import { assessBitcoin } from '../../modules/01-wallet-intelligence/src/assessment/bitcoin.js';
import { toCycloneDxBitcoin } from '../../core/cbom-engine/exporters/cyclonedx.js';
import {
  DUMMY_SIGNATURE,
  TX_BLOCK,
  p2pkhAddress,
  p2wpkhAddress,
  push,
  spendingTransaction,
  testKey,
} from '../../packages/test-fixtures/src/bitcoin.js';
import { TENANT_A } from '../../packages/test-fixtures/src/fixtures.js';

const GENESIS_KEY =
  '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f';
const TXID = '01'.repeat(32);
const multisig = (m: number, keys: string[]) =>
  `${(0x50 + m).toString(16)}${keys.map(push).join('')}${(0x50 + keys.length).toString(16)}ae`;

describe('network parameters', () => {
  it('derives each genesis hash from its header (double SHA-256, little-endian fields)', () => {
    const sha = (b: Buffer) => createHash('sha256').update(b).digest();
    const le32 = (n: number) => {
      const b = Buffer.alloc(4);
      b.writeUInt32LE(n >>> 0);
      return b;
    };
    // The genesis coinbase (and so merkle root) is shared; time, bits and nonce differ.
    const merkle = Buffer.from(
      '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
      'hex',
    ).reverse();
    const headers = {
      mainnet: [1231006505, 0x1d00ffff, 2083236893],
      testnet3: [1296688602, 0x1d00ffff, 414098458],
      signet: [1598918400, 0x1e0377ae, 52613770],
      regtest: [1296688602, 0x207fffff, 2],
    } as const;
    for (const [network, [time, bits, nonce]] of Object.entries(headers)) {
      const header = Buffer.concat([
        le32(1),
        Buffer.alloc(32),
        merkle,
        le32(time),
        le32(bits),
        le32(nonce),
      ]);
      expect(
        Buffer.from(sha(sha(header)))
          .reverse()
          .toString('hex'),
      ).toBe(BITCOIN_NETWORKS[network as keyof typeof headers].genesis);
    }
    expect(bip122ChainId('mainnet')).toBe('bip122:000000000019d6689c085ae165831e93');
  });
});

describe('address codec', () => {
  it("decodes Satoshi's genesis address to HASH160 of the genesis coinbase key", () => {
    const decoded = decodeAddress('mainnet', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
    expect(decoded).toMatchObject({
      scriptType: 'p2pkh',
      program: toHex(hash160(fromHex(GENESIS_KEY))),
    });
  });

  it('accepts BIP-173 and BIP-350 test vectors', () => {
    expect(decodeAddress('mainnet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toMatchObject({
      scriptType: 'p2wpkh',
      program: '751e76e8199196d454941c45d1b3a323f1433bd6',
    });
    expect(decodeAddress('mainnet', 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4').scriptType).toBe(
      'p2wpkh',
    );
    expect(
      decodeAddress('mainnet', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'),
    ).toMatchObject({
      scriptType: 'p2tr',
      program: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    });
  });

  it.each([
    ['bad bech32 checksum', 'mainnet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5'],
    ['mixed case', 'mainnet', 'bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'],
    // BIP-350: witness v1 must use bech32m, not bech32.
    [
      'v1 with bech32 checksum',
      'mainnet',
      'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
    ],
    ['bad base58 checksum', 'mainnet', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb'],
    ['mainnet address on testnet', 'testnet3', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'],
    ['testnet address on mainnet', 'mainnet', 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'],
  ] as const)('rejects %s', (_, network, address) => {
    expect(() => decodeAddress(network, address)).toThrow(InvalidAddress);
  });

  it('requires exactly one of address or public key, and validates key encoding', () => {
    expect(BitcoinScanRequest.safeParse({ network: 'regtest' }).success).toBe(false);
    expect(
      BitcoinScanRequest.safeParse({
        network: 'regtest',
        address: 'x'.repeat(20),
        publicKey: testKey(1),
      }).success,
    ).toBe(false);
    expect(
      BitcoinScanRequest.safeParse({ network: 'regtest', publicKey: '05' + '00'.repeat(32) })
        .success,
    ).toBe(false);
    expect(
      BitcoinScanRequest.safeParse({ network: 'mainnet', publicKey: GENESIS_KEY }).success,
    ).toBe(true);
  });
});

describe('script classification', () => {
  it.each([
    ['p2pk uncompressed (genesis)', `41${GENESIS_KEY}ac`, 'p2pk', 'public-key-in-script'],
    ['p2pk compressed', `${push(testKey(1))}ac`, 'p2pk', 'public-key-in-script'],
    ['p2pkh', `76a914${'11'.repeat(20)}88ac`, 'p2pkh', 'hash-locked'],
    ['p2sh', `a914${'11'.repeat(20)}87`, 'p2sh', 'hash-locked'],
    ['p2wpkh', `0014${'11'.repeat(20)}`, 'p2wpkh', 'hash-locked'],
    ['p2wsh', `0020${'11'.repeat(32)}`, 'p2wsh', 'hash-locked'],
    ['p2tr', `5120${'11'.repeat(32)}`, 'p2tr', 'public-key-in-script'],
    [
      'bare 1-of-2 multisig',
      multisig(1, [testKey(1), testKey(2)]),
      'bare-multisig',
      'public-key-in-script',
    ],
    ['off-curve p2pk', `21${'02' + '00'.repeat(32)}ac`, 'unknown', 'unknown'],
    ['OP_RETURN', '6a0401020304', 'unknown', 'unknown'],
  ])('classifies %s', (_, script, type, exposure) => {
    const classified = classifyScript(script);
    expect(classified.scriptType).toBe(type);
    expect(keyExposure(classified.scriptType)).toBe(exposure);
  });

  it('parses data pushes, including PUSHDATA forms, and rejects truncation and opcodes', () => {
    expect(pushes(fromHex(`0001ff4c02aabb4d0300010203`))?.map(toHex)).toEqual([
      '',
      'ff',
      'aabb',
      '010203',
    ]);
    expect(pushes(fromHex('05aabb'))).toBeNull();
    expect(pushes(fromHex('76a9'))).toBeNull();
  });
});

describe('spend evidence', () => {
  const key = testKey(1);
  const keyHash = toHex(hash160(fromHex(key)));
  const target = (network: 'regtest', address: string) => ({
    kind: 'address' as const,
    decoded: decodeAddress(network, address),
  });
  const extract = (tx: unknown, t: Parameters<typeof extractRevealedSpend>[2]) =>
    extractRevealedSpend(tx, { txid: TXID, blockHash: TX_BLOCK }, t);

  it('reveals a P2PKH key from scriptSig and a P2WPKH key from the witness', () => {
    expect(
      extract(
        spendingTransaction(TXID, { scriptSig: push(DUMMY_SIGNATURE) + push(key) }),
        target('regtest', p2pkhAddress('regtest', key)),
      ),
    ).toMatchObject({
      source: 'p2pkh-scriptsig',
      publicKeys: [key],
      threshold: null,
      inputIndex: 0,
    });
    expect(
      extract(
        spendingTransaction(TXID, { witness: [DUMMY_SIGNATURE, key] }),
        target('regtest', p2wpkhAddress('regtest', key)),
      ),
    ).toMatchObject({ source: 'p2wpkh-witness', publicKeys: [key] });
  });

  it('ignores inputs whose key does not hash to the target', () => {
    expect(
      extract(
        spendingTransaction(TXID, { witness: [DUMMY_SIGNATURE, testKey(2)] }),
        target('regtest', p2wpkhAddress('regtest', key)),
      ),
    ).toBeNull();
  });

  it('reveals multisig keys from a P2WSH witness script matching the program', () => {
    const script = multisig(2, [testKey(1), testKey(2), testKey(3)]);
    const decoded = {
      scriptType: 'p2wsh' as const,
      program: sha256Hex(fromHex(script)),
      scriptPubKey: `0020${sha256Hex(fromHex(script))}`,
    };
    expect(
      extract(
        spendingTransaction(TXID, { witness: ['', DUMMY_SIGNATURE, DUMMY_SIGNATURE, script] }),
        {
          kind: 'address',
          decoded,
        },
      ),
    ).toMatchObject({
      source: 'p2wsh-witness-script',
      publicKeys: [testKey(1), testKey(2), testKey(3)],
      threshold: 2,
    });
  });

  it('reveals a nested P2SH-P2WPKH key only when both commitments match', () => {
    const redeem = `0014${keyHash}`;
    const decoded = {
      scriptType: 'p2sh' as const,
      program: toHex(hash160(fromHex(redeem))),
      scriptPubKey: '',
    };
    const tx = spendingTransaction(TXID, {
      scriptSig: push(redeem),
      witness: [DUMMY_SIGNATURE, key],
    });
    expect(extract(tx, { kind: 'address', decoded })?.source).toBe('p2sh-p2wpkh-witness');
    const wrongKey = spendingTransaction(TXID, {
      scriptSig: push(redeem),
      witness: [DUMMY_SIGNATURE, testKey(2)],
    });
    expect(extract(wrongKey, { kind: 'address', decoded })).toBeNull();
  });

  it('matches a public-key target by exact key push', () => {
    expect(
      extract(spendingTransaction(TXID, { witness: [DUMMY_SIGNATURE, key] }), {
        kind: 'public-key',
        key,
      }),
    ).toMatchObject({ publicKeys: [key] });
  });

  it.each([
    ['another transaction', { txid: '02'.repeat(32) }],
    ['another block', { blockhash: '03'.repeat(32) }],
    ['an unconfirmed transaction', { confirmations: 0 }],
    ['a transaction off the active chain', { in_active_chain: false }],
  ])('rejects %s', (_, overrides) => {
    const tx = spendingTransaction(TXID, { witness: [DUMMY_SIGNATURE, key] }, overrides);
    expect(() => extract(tx, { kind: 'public-key', key })).toThrow(InvalidSpendEvidence);
  });
});

describe('Bitcoin intelligence', () => {
  const base: BitcoinObservation = {
    network: 'regtest',
    chainId: bip122ChainId('regtest'),
    target: {
      kind: 'address',
      value: 'bcrt1qexample',
      scriptTypes: ['p2wpkh'],
      descriptor: 'addr(x)',
    },
    tipHeight: 200,
    tipHash: 'cd'.repeat(32),
    utxoCount: 0,
    totalSats: '0',
    groups: [],
    sampleOutpoints: [],
    revealedSpend: null,
    source: 'bitcoin-core:regtest',
    observedAt: '2026-10-24T00:00:00.000Z',
    parserVersion: 'bitcoin-snapshot/1.0.0',
  };
  const group = (scriptType: string, keyExposure: string, sats: string, minConfirmations = 50) =>
    ({
      scriptType,
      keyExposure,
      count: 1,
      sats,
      minConfirmations,
    }) as BitcoinObservation['groups'][number];
  const revealed = {
    txid: TXID,
    blockHash: TX_BLOCK,
    confirmations: 12,
    inputIndex: 0,
    source: 'p2wpkh-witness' as const,
    publicKeys: [testKey(1)],
    threshold: null,
  };
  const ids = (a: ReturnType<typeof assessBitcoin>) => a.posture.findings.map((f) => f.ruleId);

  it('reports hash-protected value when only hash-locked outputs exist and no spend is supplied', () => {
    const a = assessBitcoin(TENANT_A, {
      ...base,
      utxoCount: 1,
      totalSats: '5000',
      groups: [group('p2wpkh', 'hash-locked', '5000')],
    });
    expect(a.qbom).toMatchObject({
      status: 'hash-protected',
      exposedSats: '0',
      hashProtectedSats: '5000',
    });
    expect(ids(a)).toEqual(['CV-BTC-003']);
    expect(a.cbom.components[0]).toMatchObject({
      algorithm: 'ECDSA-secp256k1',
      confidence: 'observed',
    });
  });

  it('reports key reuse when a supplied spend revealed the key of remaining outputs', () => {
    const a = assessBitcoin(TENANT_A, {
      ...base,
      utxoCount: 1,
      totalSats: '5000',
      groups: [group('p2wpkh', 'hash-locked', '5000')],
      revealedSpend: revealed,
    });
    expect(a.qbom).toMatchObject({
      status: 'public-key-exposed',
      exposedSats: '5000',
      hashProtectedSats: '0',
    });
    expect(ids(a)).toEqual(['CV-BTC-002']);
    expect(a.trustGraph.edges.map((e) => e.relation)).toContain('revealed-key');
  });

  it('reports keys exposed in output scripts and shallow confirmations', () => {
    const a = assessBitcoin(TENANT_A, {
      ...base,
      target: {
        kind: 'public-key',
        value: testKey(1),
        scriptTypes: ['p2pk', 'p2pkh', 'p2wpkh', 'p2sh'],
        descriptor: 'combo(x)',
      },
      utxoCount: 2,
      totalSats: '7000',
      groups: [
        group('p2pk', 'public-key-in-script', '5000', 2),
        group('p2pkh', 'hash-locked', '2000'),
      ],
    });
    expect(a.qbom).toMatchObject({
      status: 'public-key-exposed',
      exposedSats: '5000',
      hashProtectedSats: '2000',
    });
    expect(ids(a)).toEqual(['CV-BTC-001', 'CV-BTC-003', 'CV-BTC-005']);
    expect(a.assetKind).toBe('bitcoin-public-key');
    // P2SH from combo() is nested P2WPKH, but its script is hidden until spent: unknown.
    expect(a.cbom.components.map((c) => [c.purpose.split(' ')[0], c.confidence])).toEqual([
      ['p2pk', 'observed'],
      ['p2pkh', 'observed'],
      ['p2wpkh', 'observed'],
      ['p2sh', 'unknown'],
    ]);
  });

  it('notes that a P2TR address exposes its key even with no unspent outputs', () => {
    const a = assessBitcoin(TENANT_A, {
      ...base,
      target: { ...base.target, scriptTypes: ['p2tr'] },
    });
    expect(a.qbom.status).toBe('no-unspent-outputs');
    expect(a.qbom.reason).toContain('taproot output key');
    expect(a.cbom.components[0]?.algorithm).toBe('Schnorr-secp256k1');
  });

  it('exports a valid CycloneDX CBOM with the reviewed Schnorr entry', () => {
    const a = assessBitcoin(TENANT_A, {
      ...base,
      target: { ...base.target, scriptTypes: ['p2tr'] },
    });
    const bom = toCycloneDxBitcoin(a);
    expect(bom.components[0]?.cryptoProperties.algorithmProperties).toMatchObject({
      primitive: 'signature',
      curve: 'secp256k1',
      nistQuantumSecurityLevel: 0,
    });
    expect(bom.metadata.properties).toContainEqual({
      name: 'chainvanta:asset',
      value: `${bip122ChainId('regtest')}:bcrt1qexample`,
    });
  });
});
