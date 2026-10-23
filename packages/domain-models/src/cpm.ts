import { z } from 'zod';
import { Address, Digest, Finding, Policy, ScanRequest } from './index.js';

export const AssetId = z
  .string()
  .regex(/^eip155:[1-9][0-9]*:0x[0-9a-f]{40}$/)
  .max(100);
export const PolicyRef = z
  .object({
    id: z.string().regex(/^[a-zA-Z0-9_-]{1,60}$/),
    version: z
      .string()
      .regex(/^\d+\.\d+\.\d+$/)
      .max(30),
  })
  .strict();
export const RuleKind = z.enum([
  'quantum-signature',
  'unknown-algorithm',
  'signature-format',
  'migration-required',
  'inventory-completeness',
  'missing-evidence',
  'authority-concentration',
  'key-lifecycle',
  'policy-exception',
  'migration-verification',
]);
export const PolicyRule = z
  .object({
    id: z.string().regex(/^CV-[A-Z0-9-]{1,60}$/),
    kind: RuleKind,
    enabled: z.boolean(),
    severity: Finding.shape.severity,
    title: z.string().min(1).max(160),
    evidenceRequirements: z
      .array(
        z.enum([
          'account-state',
          'transaction-signature',
          'owner-accessor',
          'custody',
          'migration-verification',
        ]),
      )
      .min(1)
      .max(5),
    remediation: z.string().min(10).max(1000),
    standards: z.array(z.string().url().max(300)).max(5),
  })
  .strict();
export const CpmPolicy = Policy.extend({
  id: PolicyRef.shape.id,
  version: PolicyRef.shape.version,
  domain: z.literal('evm-observed'),
  assetKinds: z
    .array(z.enum(['no-code-account', 'code-bearing-account']))
    .min(1)
    .max(2),
  rules: z.array(PolicyRule).min(1).max(20),
})
  .strict()
  .refine((p) => new Set(p.rules.map((r) => r.id)).size === p.rules.length, 'Duplicate rule IDs');
export type CpmPolicy = z.infer<typeof CpmPolicy>;
export const PolicyAssignment = z
  .object({
    assetId: AssetId,
    policy: PolicyRef,
    operationalImportance: z.enum(['normal', 'high', 'critical']).default('normal'),
  })
  .strict();
export const RuleEvaluation = z.object({
  ruleId: z.string(),
  ruleHash: Digest,
  result: z.enum(['violation', 'satisfied', 'unknown', 'not_applicable']),
  confidence: Finding.shape.confidence,
  rationale: z.string(),
  evidenceReferences: z.array(Digest).min(1),
});
export const PostureSnapshot = z.object({
  id: Digest,
  assetId: AssetId,
  chainId: z.number().int().positive(),
  assessmentId: z.uuid(),
  policyId: z.string(),
  policyVersion: z.string(),
  policyHash: Digest,
  evaluatorVersion: z.literal('web3-cpm/1.0.0'),
  assessedAt: z.iso.datetime(),
  observedAlgorithms: z.array(z.string()),
  quantumExposure: z.enum(['exposed', 'potential', 'not_observed', 'unknown']),
  publicKeyExposure: z.enum(['recoverable-from-verified-signature', 'not_observed']),
  migrationReadiness: z.enum(['ready', 'partially_ready', 'blocked', 'unknown']),
  confidence: Finding.shape.confidence,
  findings: z.array(Finding),
  evaluations: z.array(RuleEvaluation),
  evidenceReferences: z.array(Digest).min(1),
  coverage: z.object({
    account: z.literal(true),
    signature: z.boolean(),
    owner: z.boolean(),
    authorization: z.literal(false),
    custody: z.literal(false),
  }),
  owner: Address.optional(),
  signatureType: z.string().optional(),
  dependencies: z.array(z.string()),
  demonstration: z.boolean(),
  limitations: z.array(z.string()),
});
export type PostureSnapshot = z.infer<typeof PostureSnapshot>;
export const CpmAssessRequest = z
  .object({ assessmentId: z.uuid(), policy: PolicyRef.optional() })
  .strict();
export const MonitoringRequest = z
  .object({
    input: ScanRequest,
    policy: PolicyRef.optional(),
    intervalSeconds: z.number().int().min(60).max(2592000),
  })
  .strict();
export const MonitoringUpdate = z
  .object({
    enabled: z.boolean().optional(),
    intervalSeconds: MonitoringRequest.shape.intervalSeconds.optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0);
export const PageQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).max(100000).default(0),
});
export const FindingTransition = z
  .object({
    status: z.enum([
      'open',
      'acknowledged',
      'in_remediation',
      'pending_verification',
      'administratively_closed',
      'excepted',
    ]),
    reason: z.string().min(10).max(1000),
    expiresAt: z.iso.datetime().optional(),
  })
  .strict()
  .refine((v) => v.status !== 'excepted' || !!v.expiresAt, 'Exception expiry required');
export const MigrationCriterion = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('owner_equals'), expected: Address }).strict(),
  z.object({ kind: z.literal('bytecode_hash_equals'), expected: Digest }).strict(),
  z
    .object({ kind: z.literal('signature_algorithm'), expected: z.string().min(1).max(80) })
    .strict(),
]);
export const MigrationRequest = z
  .object({
    assessmentId: z.uuid(),
    goal: z.enum(['authorization-change', 'cryptographic-migration']),
    scope: z.string().min(10).max(500),
    criteria: z.array(MigrationCriterion).min(1).max(8),
  })
  .strict();
export const MigrationResult = z.object({
  validity: z.enum(['provider-finalized', 'invalidated']).optional(),
  effectiveStatus: z.enum(['PENDING_VERIFICATION']).optional(),
  id: z.uuid(),
  assetId: AssetId,
  assessmentId: z.uuid(),
  baselineAssessmentId: z.uuid(),
  status: z.enum([
    'READY_FOR_PLANNING',
    'NEEDS_ADDITIONAL_EVIDENCE',
    'TECHNICALLY_BLOCKED',
    'MIGRATION_IN_PROGRESS',
    'PENDING_VERIFICATION',
    'VERIFIED_FOR_DEFINED_SCOPE',
  ]),
  scope: z.string(),
  checks: z.array(
    z.object({
      criterion: MigrationCriterion,
      result: z.enum(['satisfied', 'not_satisfied', 'unknown']),
      reason: z.string(),
    }),
  ),
  evidenceReferences: z.array(Digest),
  missingEvidence: z.array(z.string()),
  limitations: z.array(z.string()),
});
export type MigrationResult = z.infer<typeof MigrationResult>;
export const DriftEvent = z.object({
  id: Digest,
  assetId: AssetId,
  previousSnapshotId: Digest,
  currentSnapshotId: Digest,
  previousAssessmentId: z.uuid(),
  currentAssessmentId: z.uuid(),
  detectedAt: z.iso.datetime(),
  type: z.enum([
    'ALGORITHM_OBSERVED',
    'ALGORITHM_NO_LONGER_OBSERVED',
    'QUANTUM_EXPOSURE_CHANGED',
    'SIGNATURE_POSTURE_CHANGED',
    'CONTRACT_AUTHORITY_CHANGED',
    'DEPENDENCY_CHANGED',
    'POLICY_VIOLATION',
    'POLICY_REMEDIATED',
    'EVIDENCE_COVERAGE_CHANGED',
    'MIGRATION_STATUS_CHANGED',
    'POLICY_VERSION_CHANGED',
  ]),
  confidence: z.enum(['observed', 'incomplete', 'policy_change']),
  before: z.unknown(),
  after: z.unknown(),
  evidenceReferences: z.array(Digest),
});
export type DriftEvent = z.infer<typeof DriftEvent>;
export const Remediation = z.object({
  assetId: AssetId,
  snapshotId: Digest,
  ruleId: z.string(),
  priority: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEEDS_EVIDENCE']),
  dependency: z.string(),
  rationale: z.string(),
  evidenceReferences: z.array(Digest),
  constraints: z.array(z.string()),
  nextAction: z.string(),
  verificationRequirements: z.array(z.string()),
});
export type Remediation = z.infer<typeof Remediation>;
export const LifecycleEvent = z.object({
  status: z.string(),
  effectiveStatus: z.string(),
  policy_id: z.string(),
  rule_id: z.string(),
  assessment_id: z.uuid(),
  snapshot_id: Digest,
  verification_snapshot_id: Digest.nullable(),
});
export const MonitoringSchedule = z.object({
  id: z.uuid(),
  tenant_id: z.uuid(),
  asset_id: AssetId,
  input: ScanRequest,
  policy_id: z.string(),
  policy_version: z.string(),
  interval_seconds: z.number(),
  enabled: z.boolean(),
  next_run_at: z.iso.datetime(),
  last_success_at: z.iso.datetime().nullable(),
  last_failure_at: z.iso.datetime().nullable(),
  last_failure: z.string().nullable(),
  actor: z.string(),
  created_at: z.iso.datetime(),
  worker_state: z.string().nullable().optional(),
  latest_job_id: z.uuid().nullable().optional(),
  error_code: z.string().nullable().optional(),
  heartbeat_at: z.iso.datetime().nullable().optional(),
});
export const AssessmentJob = z.object({
  id: z.uuid(),
  tenant_id: z.uuid(),
  schedule_id: z.uuid(),
  idempotency_key: z.string(),
  input: ScanRequest,
  policy_id: z.string(),
  policy_version: z.string(),
  status: z.enum(['queued', 'running', 'retry', 'succeeded', 'failed', 'cancelled']),
  attempts: z.number(),
  available_at: z.iso.datetime(),
  lease_until: z.iso.datetime().nullable(),
  worker_id: z.string().nullable(),
  started_at: z.iso.datetime().nullable(),
  finished_at: z.iso.datetime().nullable(),
  assessment_id: z.uuid().nullable(),
  error_code: z.string().nullable(),
  created_at: z.iso.datetime(),
});
export const HistoricalPosture = PostureSnapshot.extend({
  validity: z.enum(['provider-finalized', 'invalidated']),
  invalidationReason: z.string().nullable(),
});
export const PostureResponse = z.object({
  snapshot: HistoricalPosture,
  lifecycle: z.array(LifecycleEvent),
  currentFindings: z.array(
    Finding.extend({
      policyId: z.string(),
      lastObservedAssessmentId: z.uuid(),
      lastObservedSnapshotId: Digest,
      evidenceValidity: z.enum(['provider-finalized', 'invalidated']),
      effectiveStatus: z.string(),
    }),
  ),
  currentStatus: z.enum(['observed', 'collection_failed', 'stale']),
  currentQuantumExposure: PostureSnapshot.shape.quantumExposure,
  monitoring: z.array(
    MonitoringSchedule.pick({
      last_success_at: true,
      last_failure_at: true,
      last_failure: true,
      next_run_at: true,
      enabled: true,
    }),
  ),
});
export const PolicyVersionRecord = z.object({
  active: z.boolean(),
  document: CpmPolicy,
  content_hash: Digest,
  actor: z.string(),
  created_at: z.iso.datetime(),
});
