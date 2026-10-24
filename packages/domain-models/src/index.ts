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
    /** Find and verify the account's latest sent transaction. Requires an archive-capable chain. */
    discoverTransaction: z.literal(true).optional(),
    /** Opt-in token adapters: owner/supply accessors, or full privileged-role discovery. */
    adapter: z.enum(['ownable-erc20', 'token-authority']).optional(),
  })
  .strict()
  .refine(
    (v) => !(v.transactionHash && v.discoverTransaction),
    'Supply a transaction hash or request discovery, not both',
  );
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
// --- EVM account structure evidence (EIP-7702, EIP-1167, EIP-1967, Safe, ERC-4337).
/** Upper bounds keep evidence size and RPC usage predictable for hostile or unusual contracts. */
export const STRUCTURE_LIMITS = {
  /** Safe owner lists above this length are not recorded; the Safe is reported as unsupported. */
  maxSafeOwners: 50,
  /** Owner code is read for at most this many owners; the rest stay `not-checked`. */
  maxOwnerCodeReads: 10,
  /** One page of Safe modules; a further page means the module list is incomplete. */
  safeModulePageSize: 10,
  /** Raw reads recorded per observation. */
  maxReads: 40,
  /**
   * Call return data above this size is not stored or decoded (hash and size only). The largest
   * legitimate probe answer, 50 Safe owners, is about 1.7 KB; this stops a contract from inflating
   * stored evidence up to the 1 MB RPC response limit per call.
   */
  maxReturnBytes: 4096,
} as const;

/** One raw chain read, recorded so a reviewer can replay the classification at the same block. */
export const StructureRead = z
  .object({
    method: z.enum(['eth_getStorageAt', 'eth_call', 'eth_getCode']),
    target: Address,
    /** Storage slot, calldata, or `0x` for code reads. */
    input: HexData,
    outcome: z.enum(['returned', 'reverted']),
    /** Storage word or call return data. Code and oversized returns record a hash and size. */
    result: HexData.optional(),
    resultHash: Hash.optional(),
    resultSize: z.number().int().nonnegative().optional(),
    codeHash: Hash.optional(),
    codeSize: z.number().int().nonnegative().optional(),
  })
  .strict();

export const OwnerCodeKind = z.enum([
  /** No code: on standard EVM chains only ECDSA secp256k1 can authorize for this address today. */
  'no-code',
  /** EIP-7702 delegation designator: the address keeps a secp256k1 key. */
  'eip-7702-delegated',
  /** Other code: authorizes through contract logic (EIP-1271), scheme unknown. */
  'contract',
  /** Not read because of `maxOwnerCodeReads`. */
  'not-checked',
]);

export const AccountStructure = z
  .object({
    parserVersion: z.literal('evm-account-structure/1.0.0'),
    /** EIP-7702: code is exactly 0xef0100 || delegate. */
    delegation: z
      .object({ standard: z.literal('eip-7702'), delegate: Address })
      .strict()
      .nullable(),
    /** EIP-1167 canonical minimal proxy runtime code. */
    minimalProxy: z
      .object({
        standard: z.literal('eip-1167'),
        implementation: Address,
        implementationCodeHash: Hash.nullable(),
      })
      .strict()
      .nullable(),
    /** EIP-1967 storage slots. Null when no slot holds a value. */
    eip1967: z
      .object({
        implementation: Address.nullable(),
        implementationCodeHash: Hash.nullable(),
        admin: Address.nullable(),
        beacon: Address.nullable(),
        beaconImplementation: Address.nullable(),
        /** Slots whose upper 12 bytes are non-zero: not an address, not interpreted. */
        malformedSlots: z.array(z.enum(['implementation', 'admin', 'beacon'])),
      })
      .strict()
      .nullable(),
    /** Safe-compatible accessors. Reported by the contract; a lookalike can return the same data. */
    safe: z
      .object({
        owners: z.array(Address).min(1).max(STRUCTURE_LIMITS.maxSafeOwners),
        threshold: z.number().int().min(1),
        version: z.string().max(32).nullable(),
        /** Storage slot 0 of a Safe proxy holds the singleton (master copy). */
        singleton: Address.nullable(),
        modules: z.array(Address),
        modulesComplete: z.boolean(),
        ownerCode: z.array(z.object({ owner: Address, kind: OwnerCodeKind }).strict()),
      })
      .strict()
      .nullable(),
    /** ERC-4337 `entryPoint()` accessor. Owner/validation semantics are vendor-specific. */
    erc4337: z.object({ entryPoint: Address, entryPointHasCode: z.boolean() }).strict().nullable(),
    reads: z.array(StructureRead).max(STRUCTURE_LIMITS.maxReads),
    limitations: z.array(z.string()),
  })
  .strict();
export type AccountStructure = z.infer<typeof AccountStructure>;
export type StructureRead = z.infer<typeof StructureRead>;

// --- Transaction discovery evidence (nonce bisection over archive state).
/** Bisection depth is ceil(log2(finalized block + 1)); 64 covers any 64-bit block number. */
export const MAX_DISCOVERY_PROBES = 64;
export const TransactionDiscovery = z
  .object({
    method: z.literal('nonce-bisection/1.0.0'),
    /** Account nonce at the snapshot block: the number of transactions it has sent. */
    accountNonce: z.string().regex(/^\d+$/),
    outcome: z.enum([
      /** Latest sent transaction located; verified evidence is in `signature`. */
      'found',
      /** Nonce 0: the account has sent no transaction up to the snapshot block. */
      'no-sent-transactions',
      /** Located, but its type (e.g. 0x3 blob, 0x4 set-code) is not supported by the verifier. */
      'unsupported-transaction-type',
      /** Nonce consumed by an EIP-7702 authorization whose recovered signer is the account. */
      'authorization-signature',
      /**
       * Delegated accounts only: the nonce changed with no transaction or authorization from the
       * account, consistent with CREATE executed by delegated code.
       */
      'no-matching-transaction',
      /** Code-bearing account without EIP-7702 delegation: it cannot send transactions. */
      'not-applicable',
    ]),
    blockNumber: HexQuantity.nullable(),
    transactionHash: Hash.nullable(),
    transactionType: HexQuantity.nullable(),
    /** The verified EIP-7702 authorization, for outcome `authorization-signature`. */
    authorization: z
      .object({
        /** Transaction that carried the authorization (sent by any account). */
        transactionHash: Hash,
        nonce: z.string().regex(/^\d+$/),
        chainId: z.string().regex(/^\d+$/),
        delegate: Address,
        /** Signer recovered from the authorization's secp256k1 signature. */
        authority: Address,
      })
      .strict()
      .nullable(),
    /** Every historical nonce read, in order, so the search can be replayed. */
    probes: z
      .array(z.object({ blockNumber: HexQuantity, nonce: z.string().regex(/^\d+$/) }).strict())
      .max(MAX_DISCOVERY_PROBES),
  })
  .strict();
export type TransactionDiscovery = z.infer<typeof TransactionDiscovery>;

// --- Token authority evidence: who can mint, burn, pause, blacklist or upgrade.
export const TOKEN_AUTHORITY_LIMITS = {
  /** Holders enumerated per AccessControlEnumerable role. */
  maxHoldersPerRole: 5,
  /** Distinct authority addresses whose code is classified. */
  maxClassifiedAuthorities: 8,
  /** Reads per token, kept so a monitored job stays within the worker's 60-call cap. */
  maxReads: 32,
  maxReturnBytes: 4096,
} as const;
export const TokenRole = z.enum([
  'owner',
  'pending-owner',
  'default-admin',
  'minter',
  'burner',
  'pauser',
  'upgrader',
  'master-minter',
  'blacklister',
  'rescuer',
  'proxy-admin',
]);
export type TokenRole = z.infer<typeof TokenRole>;
/** Roles that can create supply or replace contract logic. */
export const SUPPLY_OR_LOGIC_ROLES: readonly TokenRole[] = [
  'owner',
  'default-admin',
  'minter',
  'master-minter',
  'upgrader',
  'proxy-admin',
];
export const TokenAuthority = z
  .object({
    adapter: z.literal('token-authority/1.0.0'),
    symbol: z.string().max(32).nullable(),
    decimals: z.number().int().min(0).max(255).nullable(),
    totalSupply: z.string().regex(/^\d+$/).nullable(),
    paused: z.boolean().nullable(),
    /** ERC-165 support for IAccessControl / IAccessControlEnumerable. */
    accessControl: z.enum(['enumerable', 'non-enumerable', 'absent']),
    roles: z.array(
      z
        .object({
          role: TokenRole,
          /** Interface the holder was read from. */
          source: z.enum([
            'ownable',
            'ownable2step',
            'access-control-enumerable',
            'access-control-default-admin-rules',
            'fiat-token',
            'eip1967-admin-slot',
            'zeppelinos-admin-slot',
            'proxy-admin-owner',
          ]),
          holders: z.array(Address).max(TOKEN_AUTHORITY_LIMITS.maxHoldersPerRole),
          /** False when the role has more holders than were enumerated. */
          holdersComplete: z.boolean(),
        })
        .strict(),
    ),
    authorities: z.array(
      z
        .object({
          address: Address,
          kind: z.enum(['no-code', 'eip-7702-delegated', 'contract', 'not-checked']),
        })
        .strict(),
    ),
    reads: z.array(StructureRead).max(TOKEN_AUTHORITY_LIMITS.maxReads),
    limitations: z.array(z.string()),
  })
  .strict();
export type TokenAuthority = z.infer<typeof TokenAuthority>;

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
  structure: AccountStructure.optional(),
  discovery: TransactionDiscovery.optional(),
  tokenAuthority: TokenAuthority.optional(),
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
      'token-administration',
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
export const FindingUpdate = z
  .object({
    status: z.enum(['open', 'acknowledged', 'resolved', 'excepted']),
    reason: z.string().min(10).max(1000),
    expiresAt: z.iso.datetime().optional(),
  })
  .strict()
  .refine((v) => v.status !== 'excepted' || !!v.expiresAt, 'Exceptions require an expiry');
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
