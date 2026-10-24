import { z } from 'zod';
import { Component, Digest, Finding } from './index.js';

/**
 * Bitcoin network parameters. Genesis hashes are verified in tests by recomputing
 * double-SHA-256 over each genesis header. Address parameters follow BIP-13 (base58 version
 * bytes), BIP-173 (bech32 HRP, witness v0) and BIP-350 (bech32m, witness v1+).
 */
export const BITCOIN_NETWORKS = {
  mainnet: {
    genesis: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    hrp: 'bc',
    p2pkhVersion: 0x00,
    p2shVersion: 0x05,
  },
  testnet3: {
    genesis: '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
    hrp: 'tb',
    p2pkhVersion: 0x6f,
    p2shVersion: 0xc4,
  },
  signet: {
    genesis: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
    hrp: 'tb',
    p2pkhVersion: 0x6f,
    p2shVersion: 0xc4,
  },
  regtest: {
    genesis: '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
    hrp: 'bcrt',
    p2pkhVersion: 0x6f,
    p2shVersion: 0xc4,
  },
} as const;
export const BitcoinNetwork = z.enum(['mainnet', 'testnet3', 'signet', 'regtest']);
export type BitcoinNetwork = z.infer<typeof BitcoinNetwork>;

/** CAIP-2 chain id: `bip122:` + the first 32 hex characters of the genesis block hash. */
export const bip122ChainId = (network: BitcoinNetwork) =>
  `bip122:${BITCOIN_NETWORKS[network].genesis.slice(0, 32)}`;
/** CAIP-10 account id for a Bitcoin address or public-key target. */
export const bitcoinAssetId = (network: BitcoinNetwork, target: string) =>
  `${bip122ChainId(network)}:${target}`;

const BitcoinHash = z.string().regex(/^[0-9a-f]{64}$/);
/** Compressed (33-byte) or uncompressed (65-byte) SEC1 secp256k1 public key, lowercase hex. */
export const BitcoinPublicKey = z
  .string()
  .regex(/^(?:0[23][0-9a-fA-F]{64}|04[0-9a-fA-F]{128})$/)
  .transform((v) => v.toLowerCase());
/** Address syntax only; network-specific decoding and checksums are validated by the codec. */
export const BitcoinAddressText = z.string().regex(/^[A-Za-z0-9]{14,90}$/);
const Sats = z.string().regex(/^\d+$/);

export const BitcoinScanRequest = z
  .object({
    network: BitcoinNetwork,
    address: BitcoinAddressText.optional(),
    /** Scans every standard script for this key (P2PK, P2PKH, P2WPKH, P2SH-P2WPKH). */
    publicKey: BitcoinPublicKey.optional(),
    /** A confirmed transaction that spends from the target, proving which key or script it revealed. */
    spendTransaction: z.object({ txid: BitcoinHash, blockHash: BitcoinHash }).strict().optional(),
  })
  .strict()
  .refine((v) => !!v.address !== !!v.publicKey, 'Supply exactly one of address or publicKey');
export type BitcoinScanInput = z.infer<typeof BitcoinScanRequest>;

/** Output script types, classified from scriptPubKey bytes, never from node labels. */
export const ScriptType = z.enum([
  'p2pk',
  'p2pkh',
  'p2sh',
  'p2wpkh',
  'p2wsh',
  'p2tr',
  'bare-multisig',
  'unknown',
]);
export type ScriptType = z.infer<typeof ScriptType>;
/**
 * What an unspent output's own script reveals:
 * - public-key-in-script: the key is on-chain now (P2PK, bare multisig, P2TR output key).
 * - hash-locked: only a hash is on-chain until the output is spent (P2PKH, P2WPKH, P2SH, P2WSH).
 * - unknown: non-standard script.
 */
export const KeyExposure = z.enum(['public-key-in-script', 'hash-locked', 'unknown']);
export type KeyExposure = z.infer<typeof KeyExposure>;

export const MAX_SAMPLE_OUTPOINTS = 100;

export const RevealedSpend = z
  .object({
    txid: BitcoinHash,
    blockHash: BitcoinHash,
    confirmations: z.number().int().min(1),
    inputIndex: z.number().int().nonnegative(),
    /** How the input revealed key material for the target. */
    source: z.enum([
      'p2pkh-scriptsig',
      'p2wpkh-witness',
      'p2sh-p2wpkh-witness',
      'p2sh-redeem-script',
      'p2wsh-witness-script',
    ]),
    /** Public keys whose hash or script commitment matches the target. */
    publicKeys: z.array(BitcoinPublicKey).min(1).max(20),
    /** For script-hash targets: the m in an m-of-n multisig, when the script is standard multisig. */
    threshold: z.number().int().min(1).nullable(),
  })
  .strict();
export type RevealedSpend = z.infer<typeof RevealedSpend>;

export const BitcoinObservation = z
  .object({
    network: BitcoinNetwork,
    chainId: z.string().regex(/^bip122:[0-9a-f]{32}$/),
    target: z
      .object({
        kind: z.enum(['address', 'public-key']),
        value: z.string(),
        /** Script types covered by the scan descriptor. */
        scriptTypes: z.array(ScriptType).min(1),
        descriptor: z.string().max(200),
      })
      .strict(),
    /** UTXO set snapshot reported by `scantxoutset`. */
    tipHeight: z.number().int().nonnegative(),
    tipHash: BitcoinHash,
    utxoCount: z.number().int().nonnegative(),
    totalSats: Sats,
    groups: z.array(
      z
        .object({
          scriptType: ScriptType,
          keyExposure: KeyExposure,
          count: z.number().int().positive(),
          sats: Sats,
          minConfirmations: z.number().int().positive(),
        })
        .strict(),
    ),
    sampleOutpoints: z
      .array(
        z
          .object({
            txid: BitcoinHash,
            vout: z.number().int().nonnegative(),
            sats: Sats,
            height: z.number().int().nonnegative(),
            scriptType: ScriptType,
          })
          .strict(),
      )
      .max(MAX_SAMPLE_OUTPOINTS),
    revealedSpend: RevealedSpend.nullable(),
    source: z.string(),
    observedAt: z.iso.datetime(),
    parserVersion: z.literal('bitcoin-snapshot/1.0.0'),
    demonstration: z.boolean().optional(),
  })
  .strict();
export type BitcoinObservation = z.infer<typeof BitcoinObservation>;

export const BitcoinQbom = z
  .object({
    format: z.literal('chainvanta-qbom/0.1'),
    ruleVersion: z.literal('bitcoin-quantum-exposure/1.0.0'),
    /**
     * public-key-exposed: some unspent value is locked to a key that is public on-chain.
     * hash-protected: all unspent value is hash-locked and no revealing spend was supplied.
     * no-unspent-outputs: nothing to protect at the snapshot (the key may still be exposed).
     * unknown: non-standard scripts prevent a conclusion.
     */
    status: z.enum(['public-key-exposed', 'hash-protected', 'no-unspent-outputs', 'unknown']),
    exposedSats: Sats,
    hashProtectedSats: Sats,
    reason: z.string(),
    migration: z.literal('requires-further-discovery'),
  })
  .strict();

export const BitcoinAssessment = z.object({
  schemaVersion: z.literal('0.1'),
  kind: z.literal('bitcoin'),
  id: z.uuid(),
  tenantId: z.uuid(),
  createdAt: z.iso.datetime(),
  observation: BitcoinObservation,
  evidenceHash: Digest,
  assetKind: z.enum(['bitcoin-address', 'bitcoin-public-key']),
  cbom: z.object({ format: z.literal('chainvanta-cbom/0.1'), components: z.array(Component) }),
  qbom: BitcoinQbom,
  posture: z.object({
    status: z.literal('needs-review'),
    rulepack: z.literal('bitcoin-baseline/0.1'),
    findings: z.array(Finding),
  }),
  trustGraph: z.object({
    nodes: z.array(z.object({ id: z.string(), kind: z.string() })),
    edges: z.array(z.object({ from: z.string(), to: z.string(), relation: z.string() })),
  }),
  limitations: z.array(z.string()),
});
export type BitcoinAssessment = z.infer<typeof BitcoinAssessment>;
