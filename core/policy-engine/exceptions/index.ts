import {
  canonicalAssetId,
  type Assessment,
  type EffectiveFinding,
  type FindingEventRecord,
  type FindingStatus,
} from '../../../packages/domain-models/src/index.js';

/** Effective lifecycle state of one (assessment, rule) pair at a fixed evaluation instant. */
export interface EffectiveState {
  status: FindingStatus;
  basis: EffectiveFinding['statusBasis'];
  eventId: string | null;
  changedAt: string | null;
  expiresAt: string | null;
}

const DEFAULT_STATE: EffectiveState = {
  status: 'open',
  basis: 'default',
  eventId: null,
  changedAt: null,
  expiresAt: null,
};

/** Stable map key for an (assessment, rule) pair. Rule ids never contain a newline. */
export const findingKey = (assessmentId: string, ruleId: string) => `${assessmentId}\n${ruleId}`;

/**
 * Total order on events: later createdAt wins; equal timestamps fall back to the larger event id.
 * The id tie-break carries no temporal meaning; it only makes the projection deterministic when
 * two events share a timestamp (possible under concurrent writes at clock resolution).
 */
function isLater(candidate: FindingEventRecord, current: FindingEventRecord): boolean {
  const delta = Date.parse(candidate.createdAt) - Date.parse(current.createdAt);
  return delta !== 0 ? delta > 0 : candidate.id > current.id;
}

/**
 * Projects append-only finding events into the effective status per (assessment, rule).
 *
 * Rules:
 * 1. The latest event per pair determines the status (see `isLater`).
 * 2. An `excepted` event whose `expiresAt <= now` no longer applies; the finding reverts to
 *    `open` with basis `expired-exception`. The boundary is inclusive so an exception never
 *    outlives its stated expiry, matching the API's rejection of non-future expiries.
 * 3. Pairs without events are absent from the result; callers use `stateFor` for the default.
 *
 * Pure: the result depends only on `events` and `now`. Supplying full history or only the latest
 * event per pair yields the same projection.
 */
export function projectFindingStates(
  events: readonly FindingEventRecord[],
  now: Date,
): Map<string, EffectiveState> {
  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs)) throw new Error('Evaluation time must be a valid date');
  const latest = new Map<string, FindingEventRecord>();
  for (const event of events) {
    const key = findingKey(event.assessmentId, event.ruleId);
    const current = latest.get(key);
    if (!current || isLater(event, current)) latest.set(key, event);
  }
  const states = new Map<string, EffectiveState>();
  for (const [key, event] of latest) {
    const expired =
      event.status === 'excepted' &&
      (event.expiresAt === null || Date.parse(event.expiresAt) <= nowMs);
    states.set(key, {
      status: expired ? 'open' : event.status,
      basis: expired ? 'expired-exception' : 'event',
      eventId: event.id,
      changedAt: event.createdAt,
      expiresAt: event.expiresAt,
    });
  }
  return states;
}

/** Returns the effective state for a pair, defaulting to open when no event exists. */
export function stateFor(
  states: ReadonlyMap<string, EffectiveState>,
  assessmentId: string,
  ruleId: string,
): EffectiveState {
  return states.get(findingKey(assessmentId, ruleId)) ?? DEFAULT_STATE;
}

/**
 * Attaches effective lifecycle status to every finding of the given assessments.
 * Order is preserved: assessments as supplied, findings in rulepack order.
 */
export function effectiveFindings(
  assessments: readonly Assessment[],
  states: ReadonlyMap<string, EffectiveState>,
): EffectiveFinding[] {
  return assessments.flatMap((assessment) =>
    assessment.posture.findings.map((finding) => {
      const state = stateFor(states, assessment.id, finding.ruleId);
      return {
        ...finding,
        assessmentId: assessment.id,
        asset: canonicalAssetId(assessment.observation.chainId, assessment.observation.address),
        status: state.status,
        statusBasis: state.basis,
        statusEventId: state.eventId,
        statusChangedAt: state.changedAt,
        expiresAt: state.expiresAt,
      };
    }),
  );
}
