import { z } from 'zod';
export const Address = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/)
  .transform((v) => v.toLowerCase());
export const Hash = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
export const HexQuantity = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/);
export const HexData = z.string().regex(/^0x(?:[0-9a-fA-F]{2})*$/);
export const Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
export const Confidence = z.enum(['observed', 'authenticated-integration', 'inferred', 'unknown']);
export const ScanRequest = z
  .object({
    address: Address,
    chainId: z.number().int().positive().safe(),
    transactionHash: Hash.optional(),
    adapter: z.literal('ownable-erc20').optional(),
  })
  .strict();
export type ScanInput = z.infer<typeof ScanRequest>;
export const SignatureEvidence = z.object({
  hash: Hash,
  blockHash: Hash,
  blockNumber: HexQuantity,
  sender: Address,
  algorithm: z.literal('ECDSA-secp256k1'),
  serializedTransaction: HexData,
  receiptStatus: z.enum(['success', 'reverted']),
  parserVersion: z.literal('evm-transaction/1.0.0'),
});
export const TokenEvidence = z.object({
  adapter: z.literal('ownable-erc20/1.0.0'),
  owner: Address,
  totalSupply: z.string().regex(/^\d+$/),
  decimals: z.number().int().min(0).max(255),
  calls: z.array(z.object({ data: HexData, result: HexData })).length(3),
  limitation: z.string(),
});
export const Observation = z.object({
  chainId: z.number().int().positive().safe(),
  address: Address,
  blockNumber: HexQuantity,
  blockHash: Hash,
  blockTimestamp: HexQuantity,
  balanceWei: z.string().regex(/^\d+$/),
  transactionCount: z.string().regex(/^\d+$/),
  code: HexData,
  source: z.string(),
  observedAt: z.iso.datetime(),
  finality: z.literal('finalized'),
  signature: SignatureEvidence.optional(),
  token: TokenEvidence.optional(),
  parserVersion: z.literal('evm-snapshot/1.0.0').optional(),
  demonstration: z.boolean().optional(),
});
export type Observation = z.infer<typeof Observation>;
export const Finding = z.object({
  ruleId: z.string(),
  ruleVersion: z.string().optional(),
  severity: z.enum(['info', 'medium', 'high']),
  title: z.string(),
  rationale: z.string(),
  confidence: Confidence,
  evidenceHash: Digest,
});
export type Finding = z.infer<typeof Finding>;
export const Component = z.object({
  algorithm: z.string(),
  purpose: z.string(),
  confidence: Confidence,
  basis: z.string(),
  domain: z
    .enum([
      'transaction-signature',
      'account-authorization',
      'application',
      'transport',
      'consensus',
    ])
    .optional(),
  evidenceRefs: z.array(Digest).optional(),
});
export const Assessment = z.object({
  schemaVersion: z.literal('0.1'),
  id: z.uuid(),
  tenantId: z.uuid(),
  createdAt: z.iso.datetime(),
  observation: Observation,
  evidenceHash: Digest,
  assetKind: z.enum(['code-bearing-account', 'no-code-account']),
  cbom: z.object({ format: z.literal('chainvanta-cbom/0.1'), components: z.array(Component) }),
  qbom: z.object({
    format: z.literal('chainvanta-qbom/0.1'),
    status: z.enum(['unknown', 'classical-signature-observed']),
    reason: z.string(),
    migration: z.literal('requires-further-discovery'),
    ruleVersion: z.string().optional(),
  }),
  posture: z.object({
    status: z.literal('needs-review'),
    rulepack: z.literal('wallet-baseline/0.1'),
    findings: z.array(Finding),
  }),
  trustGraph: z.object({
    nodes: z.array(z.object({ id: z.string(), kind: z.string() })),
    edges: z.array(z.object({ from: z.string(), to: z.string(), relation: z.string() })),
  }),
  limitations: z.array(z.string()),
});
export type Assessment = z.infer<typeof Assessment>;
export const FindingStatus = z.enum(['open', 'acknowledged', 'resolved', 'excepted']);
export type FindingStatus = z.infer<typeof FindingStatus>;
export const FindingUpdate = z
  .object({
    status: FindingStatus,
    reason: z.string().min(10).max(1000),
    expiresAt: z.iso.datetime().optional(),
  })
  .strict()
  .refine((v) => v.status !== 'excepted' || !!v.expiresAt, 'Exceptions require an expiry');
/** One append-only lifecycle event, normalized from storage (timestamps as ISO-8601 UTC). */
export const FindingEventRecord = z.object({
  id: z.uuid(),
  assessmentId: z.uuid(),
  ruleId: z.string().min(1).max(80),
  status: FindingStatus,
  reason: z.string(),
  expiresAt: z.iso.datetime().nullable(),
  actor: z.string(),
  createdAt: z.iso.datetime(),
});
export type FindingEventRecord = z.infer<typeof FindingEventRecord>;
/**
 * Why a finding has its effective status:
 * - default: no lifecycle event exists, so the finding is open.
 * - event: the latest event's status applies.
 * - expired-exception: the latest event was an exception whose expiry has passed; it reverts to open.
 */
export const StatusBasis = z.enum(['default', 'event', 'expired-exception']);
export const EffectiveFinding = Finding.extend({
  assessmentId: z.uuid(),
  asset: z.string(),
  status: FindingStatus,
  statusBasis: StatusBasis,
  statusEventId: z.uuid().nullable(),
  statusChangedAt: z.iso.datetime().nullable(),
  expiresAt: z.iso.datetime().nullable(),
});
export type EffectiveFinding = z.infer<typeof EffectiveFinding>;
export const canonicalAssetId = (chainId: number, address: string) =>
  `eip155:${chainId}:${Address.parse(address)}`;
export const Tenant = z.object({ id: z.uuid(), name: z.string().min(1).max(100) });
export const User = z.object({
  subject: z.string().min(1),
  tenantId: z.uuid(),
  role: z.enum(['viewer', 'analyst', 'admin']),
});
export const Policy = z.object({
  id: z.string(),
  version: z.string(),
  enabled: z.boolean(),
  domain: z.string(),
});
export const ModuleCatalog = [
  ['01-wallet-intelligence', 'Wallet Intelligence', 'partially implemented'],
  ['02-defi-trust-graph', 'DeFi Trust Graph', 'planned'],
  ['03-bridge-assurance', 'Bridge Assurance', 'planned'],
  ['04-contract-crypto-agility', 'Contract Crypto Agility', 'planned'],
  ['05-validator-cpm', 'Validator CPM', 'planned'],
  ['06-zk-crypto-inventory', 'ZK Crypto Inventory', 'planned'],
  ['07-custody-mpc-hsm', 'Custody, MPC & HSM', 'planned'],
  ['08-crosschain-pqc-migration', 'Cross-chain PQC Migration', 'planned'],
  ['09-stablecoin-assurance', 'Stablecoin Assurance', 'partially implemented'],
  ['10-web3-identity', 'Web3 Identity', 'planned'],
  ['11-digital-provenance', 'Digital Provenance', 'planned'],
  ['12-depin-security', 'DePIN Security', 'planned'],
] as const;
