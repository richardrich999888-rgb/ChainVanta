import type { DriftEvent, PostureSnapshot } from '../../../packages/domain-models/src/cpm.js';
import { evidenceHash } from '../../evidence-engine/evidence-hashing/index.js';
export function comparePosture(previous: PostureSnapshot, current: PostureSnapshot): DriftEvent[] {
  if (previous.assetId !== current.assetId) throw new Error('Cannot compare different assets');
  if (previous.id === current.id) return [];
  const events: DriftEvent[] = [];
  const add = (
    type: DriftEvent['type'],
    before: unknown,
    after: unknown,
    confidence: DriftEvent['confidence'] = 'observed',
  ) => {
    if (evidenceHash(before) === evidenceHash(after)) return;
    const data = {
      assetId: current.assetId,
      previousSnapshotId: previous.id,
      currentSnapshotId: current.id,
      previousAssessmentId: previous.assessmentId,
      currentAssessmentId: current.assessmentId,
      detectedAt: current.assessedAt,
      type,
      confidence,
      before,
      after,
      evidenceReferences: [
        ...new Set([...previous.evidenceReferences, ...current.evidenceReferences]),
      ].sort(),
    };
    events.push({ id: evidenceHash(data), ...data });
  };
  for (const algorithm of current.observedAlgorithms.filter(
    (a) => !previous.observedAlgorithms.includes(a),
  ))
    add('ALGORITHM_OBSERVED', null, algorithm);
  for (const algorithm of previous.observedAlgorithms.filter(
    (a) => !current.observedAlgorithms.includes(a),
  ))
    add('ALGORITHM_NO_LONGER_OBSERVED', algorithm, null, 'incomplete');
  add(
    'QUANTUM_EXPOSURE_CHANGED',
    previous.quantumExposure,
    current.quantumExposure,
    current.quantumExposure === 'unknown' ? 'incomplete' : 'observed',
  );
  if (previous.signatureType && current.signatureType)
    add('SIGNATURE_POSTURE_CHANGED', previous.signatureType, current.signatureType);
  if (previous.owner && current.owner)
    add('CONTRACT_AUTHORITY_CHANGED', previous.owner, current.owner);
  if (previous.dependencies.join() !== current.dependencies.join())
    add(
      'DEPENDENCY_CHANGED',
      previous.dependencies,
      current.dependencies,
      previous.dependencies.some((d) => !current.dependencies.includes(d))
        ? 'incomplete'
        : 'observed',
    );
  add('EVIDENCE_COVERAGE_CHANGED', previous.coverage, current.coverage, 'incomplete');
  add(
    'MIGRATION_STATUS_CHANGED',
    previous.migrationReadiness,
    current.migrationReadiness,
    current.migrationReadiness === 'unknown' ? 'incomplete' : 'observed',
  );
  if (previous.policyHash !== current.policyHash)
    add('POLICY_VERSION_CHANGED', previous.policyHash, current.policyHash, 'policy_change');
  for (const e of current.evaluations) {
    const old = previous.evaluations.find((p) => p.ruleId === e.ruleId);
    if (e.result === 'violation' && old?.result !== 'violation')
      add(
        'POLICY_VIOLATION',
        { ruleId: e.ruleId, result: old?.result ?? 'not_applicable' },
        { ruleId: e.ruleId, result: e.result },
        old?.ruleHash === e.ruleHash ? 'observed' : 'policy_change',
      );
    if (
      old?.result === 'violation' &&
      e.result === 'satisfied' &&
      old.ruleHash === e.ruleHash &&
      current.assessmentId !== previous.assessmentId
    )
      add(
        'POLICY_REMEDIATED',
        { ruleId: old.ruleId, result: old.result },
        { ruleId: e.ruleId, result: e.result },
      );
  }
  return events;
}
