import { randomUUID } from 'node:crypto';
import type { z } from 'zod';
import { canonicalAssetId, type Assessment } from '../../packages/domain-models/src/index.js';
import { type MigrationRequest, MigrationResult } from '../../packages/domain-models/src/cpm.js';
import { evidenceHash } from '../evidence-engine/evidence-hashing/index.js';
export function assessMigration(
  request: z.infer<typeof MigrationRequest>,
  baseline: Assessment,
  current: Assessment = baseline,
): MigrationResult {
  const assetId = canonicalAssetId(baseline.observation.chainId, baseline.observation.address);
  if (
    assetId !== canonicalAssetId(current.observation.chainId, current.observation.address) ||
    baseline.tenantId !== current.tenantId
  )
    throw new Error('Migration assets do not match');
  const later =
    current.id !== baseline.id &&
    BigInt(current.observation.blockNumber) > BigInt(baseline.observation.blockNumber);
  const checks = request.criteria.map((criterion) => {
    let observed: string | undefined;
    if (criterion.kind === 'owner_equals') observed = current.observation.token?.owner;
    if (criterion.kind === 'bytecode_hash_equals')
      observed = evidenceHash(current.observation.code);
    if (criterion.kind === 'signature_algorithm')
      observed = current.observation.signature?.algorithm;
    return {
      criterion,
      result:
        observed === undefined
          ? ('unknown' as const)
          : observed === criterion.expected
            ? ('satisfied' as const)
            : ('not_satisfied' as const),
      reason:
        observed === undefined
          ? 'Required evidence is unavailable.'
          : 'Compared against the collected finalized observation.',
    };
  });
  const unsupported = request.goal === 'cryptographic-migration';
  const incomplete = checks.some((c) => c.result === 'unknown');
  const baselineAlreadySatisfied = request.criteria.every((c) =>
    c.kind === 'owner_equals'
      ? baseline.observation.token?.owner === c.expected
      : c.kind === 'bytecode_hash_equals'
        ? evidenceHash(baseline.observation.code) === c.expected
        : baseline.observation.signature?.algorithm === c.expected,
  );
  const status = unsupported
    ? baseline.assetKind === 'no-code-account'
      ? 'TECHNICALLY_BLOCKED'
      : 'NEEDS_ADDITIONAL_EVIDENCE'
    : incomplete
      ? 'NEEDS_ADDITIONAL_EVIDENCE'
      : !later
        ? 'READY_FOR_PLANNING'
        : checks.every((c) => c.result === 'satisfied')
          ? baselineAlreadySatisfied
            ? 'PENDING_VERIFICATION'
            : 'VERIFIED_FOR_DEFINED_SCOPE'
          : 'MIGRATION_IN_PROGRESS';
  return MigrationResult.parse({
    id: randomUUID(),
    assetId,
    assessmentId: current.id,
    baselineAssessmentId: baseline.id,
    status,
    scope: request.scope,
    checks,
    evidenceReferences: [...new Set([baseline.evidenceHash, current.evidenceHash])],
    missingEvidence: [
      ...(unsupported
        ? [
            'Supported PQC authorization verifier, protocol and wallet compatibility, upgradeability and custody constraints',
          ]
        : []),
      ...checks.filter((c) => c.result === 'unknown').map((c) => c.criterion.kind),
    ],
    limitations: [
      'Verification is limited to the stated owner accessor or bytecode property; it does not prove complete authorization or cryptographic safety.',
      'A signature no longer being observed does not demonstrate migration.',
      'Provider finality is trusted; consensus is not independently verified.',
      ...(baselineAlreadySatisfied
        ? [
            'The baseline already satisfies these criteria; unchanged properties do not demonstrate migration improvement.',
          ]
        : []),
    ],
  });
}
