import type { Assessment } from '../../../packages/domain-models/src/index.js';
import { effectiveFindings, type EffectiveState } from '../../policy-engine/exceptions/index.js';

export interface ReportOptions {
  /** Projected lifecycle states; omitted means no events were consulted (all findings open). */
  states?: ReadonlyMap<string, EffectiveState>;
  /** Report generation instant; injected so output is reproducible in tests. */
  now?: Date;
}

/**
 * Summarizes assessments. `findingSeverityCounts` counts original findings regardless of status;
 * `effectiveFindingStatusCounts` counts the projected lifecycle status of the same findings.
 * Neither is a risk score.
 */
export function report(items: Assessment[], options: ReportOptions = {}) {
  const findings = items.flatMap((item) => item.posture.findings);
  const effective = effectiveFindings(items, options.states ?? new Map());
  return {
    schemaVersion: 'chainvanta-report/1.1.0',
    generatedAt: (options.now ?? new Date()).toISOString(),
    scope: 'Latest 50 assessments, not the complete tenant inventory',
    assessmentCount: items.length,
    assetCount: new Set(
      items.map((v) => `eip155:${v.observation.chainId}:${v.observation.address}`),
    ).size,
    algorithmObservations: items
      .flatMap((v) => v.cbom.components)
      .reduce<Record<string, number>>((r, v) => {
        r[v.algorithm] = (r[v.algorithm] ?? 0) + 1;
        return r;
      }, {}),
    findingSeverityCounts: findings.reduce<Record<string, number>>((r, v) => {
      r[v.severity] = (r[v.severity] ?? 0) + 1;
      return r;
    }, {}),
    effectiveFindingStatusCounts: effective.reduce<Record<string, number>>((r, v) => {
      r[v.status] = (r[v.status] ?? 0) + 1;
      return r;
    }, {}),
    openMediumOrHighFindings: effective.filter(
      (v) => v.status === 'open' && (v.severity === 'medium' || v.severity === 'high'),
    ).length,
    quantumSignatureObservations: items.filter(
      (v) => v.qbom.status === 'classical-signature-observed',
    ).length,
    unknownQuantumAssessments: items.filter((v) => v.qbom.status === 'unknown').length,
    latestAssessmentAt: items[0]?.createdAt ?? null,
    demonstration: items.some((v) => v.observation.demonstration),
    assessments: items.map((v) => ({
      id: v.id,
      evidenceHash: v.evidenceHash,
      asset: `eip155:${v.observation.chainId}:${v.observation.address}`,
      qbom: v.qbom,
    })),
  };
}
export function compareSnapshots(newer: Assessment, older: Assessment) {
  if (
    newer.tenantId !== older.tenantId ||
    newer.observation.chainId !== older.observation.chainId ||
    newer.observation.address !== older.observation.address
  )
    throw new Error('Snapshots belong to different assets');
  return ['code', 'token'].flatMap((field) => {
    const key = field as 'code' | 'token';
    return JSON.stringify(newer.observation[key]) === JSON.stringify(older.observation[key])
      ? []
      : [{ field, before: older.observation[key] ?? null, after: newer.observation[key] ?? null }];
  });
}
