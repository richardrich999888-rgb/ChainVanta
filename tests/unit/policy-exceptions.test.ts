import { describe, expect, it } from 'vitest';
import {
  effectiveFindings,
  findingKey,
  projectFindingStates,
  stateFor,
} from '../../core/policy-engine/exceptions/index.js';
import { report } from '../../core/reporting-engine/src/index.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import type { FindingEventRecord } from '../../packages/domain-models/src/index.js';
import { TENANT_A, observation } from '../../packages/test-fixtures/src/fixtures.js';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOW = new Date('2026-10-20T12:00:00.000Z');
let sequence = 0;
const event = (overrides: Partial<FindingEventRecord>): FindingEventRecord => ({
  id: `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`,
  assessmentId: A,
  ruleId: 'CV-WALLET-001',
  status: 'acknowledged',
  reason: 'reviewed by test',
  expiresAt: null,
  actor: 'test',
  createdAt: '2026-10-20T10:00:00.000Z',
  ...overrides,
});

describe('finding status projection', () => {
  it('defaults to open when no event exists', () => {
    expect(stateFor(projectFindingStates([], NOW), A, 'CV-WALLET-001')).toEqual({
      status: 'open',
      basis: 'default',
      eventId: null,
      changedAt: null,
      expiresAt: null,
    });
  });

  it('applies the latest event regardless of input order', () => {
    const older = event({ status: 'acknowledged', createdAt: '2026-10-20T09:00:00.000Z' });
    const newer = event({ status: 'resolved', createdAt: '2026-10-20T11:00:00.000Z' });
    for (const events of [
      [older, newer],
      [newer, older],
    ]) {
      const state = stateFor(projectFindingStates(events, NOW), A, 'CV-WALLET-001');
      expect(state).toMatchObject({ status: 'resolved', basis: 'event', eventId: newer.id });
    }
  });

  it('breaks equal-timestamp ties deterministically by event id', () => {
    const low = event({ id: '00000000-0000-4000-8000-00000000000a', status: 'acknowledged' });
    const high = event({ id: '00000000-0000-4000-8000-00000000000b', status: 'resolved' });
    expect(stateFor(projectFindingStates([high, low], NOW), A, 'CV-WALLET-001').status).toBe(
      'resolved',
    );
    expect(stateFor(projectFindingStates([low, high], NOW), A, 'CV-WALLET-001').status).toBe(
      'resolved',
    );
  });

  it('keeps an unexpired exception and reverts an expired one to open', () => {
    const exception = event({ status: 'excepted', expiresAt: '2026-10-20T12:00:00.001Z' });
    expect(stateFor(projectFindingStates([exception], NOW), A, exception.ruleId)).toMatchObject({
      status: 'excepted',
      basis: 'event',
      expiresAt: exception.expiresAt,
    });
    const later = new Date('2026-10-21T00:00:00.000Z');
    expect(stateFor(projectFindingStates([exception], later), A, exception.ruleId)).toMatchObject({
      status: 'open',
      basis: 'expired-exception',
      eventId: exception.id,
    });
  });

  it('treats the expiry instant itself as expired', () => {
    const exception = event({ status: 'excepted', expiresAt: NOW.toISOString() });
    expect(stateFor(projectFindingStates([exception], NOW), A, exception.ruleId).status).toBe(
      'open',
    );
  });

  it('fails closed on an exception without an expiry', () => {
    const exception = event({ status: 'excepted', expiresAt: null });
    expect(stateFor(projectFindingStates([exception], NOW), A, exception.ruleId)).toMatchObject({
      status: 'open',
      basis: 'expired-exception',
    });
  });

  it('does not let a later event on one rule or assessment affect another', () => {
    const other = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    const states = projectFindingStates(
      [
        event({ ruleId: 'CV-WALLET-001', status: 'resolved' }),
        event({ ruleId: 'CV-QUANTUM-001', status: 'acknowledged' }),
        event({ assessmentId: other, status: 'excepted', expiresAt: '2027-01-01T00:00:00.000Z' }),
      ],
      NOW,
    );
    expect(states.size).toBe(3);
    expect(states.get(findingKey(A, 'CV-WALLET-001'))?.status).toBe('resolved');
    expect(states.get(findingKey(A, 'CV-QUANTUM-001'))?.status).toBe('acknowledged');
    expect(states.get(findingKey(other, 'CV-WALLET-001'))?.status).toBe('excepted');
  });

  it('rejects an invalid evaluation time', () => {
    expect(() => projectFindingStates([], new Date(Number.NaN))).toThrow('valid date');
  });
});

describe('effective findings and reports', () => {
  const assessment = { ...assessWallet(TENANT_A, { ...observation, code: '0x6000' }), id: A };

  it('attaches status to every finding in rulepack order', () => {
    const states = projectFindingStates([event({ status: 'resolved' })], NOW);
    const findings = effectiveFindings([assessment], states);
    expect(findings.map((f) => [f.ruleId, f.status, f.statusBasis])).toEqual([
      ['CV-WALLET-001', 'resolved', 'event'],
      ['CV-WALLET-002', 'open', 'default'],
    ]);
    expect(findings[0]).toMatchObject({
      assessmentId: A,
      asset: `eip155:1:${observation.address}`,
      evidenceHash: assessment.evidenceHash,
    });
  });

  it('reports effective status counts without changing original severity counts', () => {
    const states = projectFindingStates(
      [event({ status: 'excepted', expiresAt: '2027-01-01T00:00:00.000Z' })],
      NOW,
    );
    const result = report([assessment], { states, now: NOW });
    expect(result.generatedAt).toBe(NOW.toISOString());
    expect(result.findingSeverityCounts).toEqual({ info: 2 });
    expect(result.effectiveFindingStatusCounts).toEqual({ excepted: 1, open: 1 });
    expect(result.openMediumOrHighFindings).toBe(0);
    expect(report([assessment]).effectiveFindingStatusCounts).toEqual({ open: 2 });
  });
});
