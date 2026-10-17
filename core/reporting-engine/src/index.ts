import type { Assessment } from '../../../packages/domain-models/src/index.js';
export function report(items: Assessment[]) {
  const findings = items.flatMap((item) => item.posture.findings);
  return {
    schemaVersion: 'chainvanta-report/1.0.0',
    generatedAt: new Date().toISOString(),
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
