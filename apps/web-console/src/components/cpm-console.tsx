'use client';
import { useCallback, useEffect, useState, useRef } from 'react';
import type { Assessment } from '../../../../packages/domain-models/src/index';
import type { components } from '../../../../packages/api-contracts/generated';
type Schemas = components['schemas'];
async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(`/api/cpm/${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error?.message ?? 'CPM request failed');
  return value;
}
export function CpmConsole({
  items,
  selected,
  onSelect,
  role,
  mode = 'posture',
}: {
  items: Assessment[];
  selected: Assessment | null;
  onSelect: (a: Assessment) => void;
  role: string;
  mode?: 'posture' | 'migration';
}) {
  const [state, setState] = useState<Schemas['PostureResponse'] | null>(null),
    [schedules, setSchedules] = useState<Schemas['MonitoringSchedule'][]>([]),
    [drift, setDrift] = useState<Schemas['DriftEvent'][]>([]),
    [recommendations, setRecommendations] = useState<Schemas['Remediation'][]>([]),
    [history, setHistory] = useState<Schemas['HistoricalPosture'][]>([]);
  const [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [migration, setMigration] = useState<Schemas['MigrationResult'] | null>(null),
    [message, setMessage] = useState('');
  const asset = selected
    ? `eip155:${selected.observation.chainId}:${selected.observation.address}`
    : '';
  const context = useRef(asset);
  const refresh = useCallback(async () => {
    if (!asset) return;
    const [p, s, d, r, h] = await Promise.all([
      request<Schemas['PostureResponse']>(`posture/${encodeURIComponent(asset)}`).catch((e) => {
        if (e.message === 'Posture not found') return null;
        throw e;
      }),
      request<Schemas['MonitoringSchedule'][]>('monitoring?limit=100'),
      request<Schemas['DriftEvent'][]>('drift?limit=100'),
      request<Schemas['Remediation'][]>('remediation?limit=100'),
      request<Schemas['HistoricalPosture'][]>(`history/${encodeURIComponent(asset)}?limit=25`),
    ]);
    if (context.current !== asset) return;
    setState(p);
    setSchedules(s);
    setDrift(d);
    setRecommendations(r);
    setHistory(h);
  }, [asset]);
  useEffect(() => {
    context.current = asset;
    setState(null);
    setMigration(null);
    setError('');
    let active = true;
    const load = async () => {
      try {
        if (active) await refresh();
      } catch (e) {
        if (active) setError((e as Error).message);
      }
    };
    void load();
    const timer = setInterval(() => void load(), 15000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [refresh, asset]);
  async function act(action: () => Promise<unknown>, success: string) {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await action();
      await refresh();
      setMessage(success);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const editable = role !== 'viewer',
    admin = role === 'admin',
    currentSchedules = schedules.filter((s) => s.asset_id === asset);
  return (
    <section className="panel cpm-panel">
      <div className="panel-title">
        <div>
          <h2>
            {mode === 'migration'
              ? 'Migration readiness and verification'
              : 'Continuous cryptographic posture'}
          </h2>
          <p>Observed evidence, recorded changes and explicit unknowns.</p>
        </div>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => void act(async () => {}, 'Evidence refreshed')}
        >
          Refresh
        </button>
      </div>
      <div className="evidence-body">
        {!items.length ? (
          <p>Collect an assessment from Overview to register an asset.</p>
        ) : (
          <>
            <label htmlFor="cpm-assessment">Assessment context</label>
            <select
              id="cpm-assessment"
              value={selected?.id ?? ''}
              onChange={(e) => {
                const a = items.find((v) => v.id === e.target.value);
                if (a) onSelect(a);
              }}
            >
              {items.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.observation.address} · {a.createdAt}
                </option>
              ))}
            </select>
            <p>
              <code>{asset}</code>
            </p>
            {!state && (
              <>
                <p>No CPM snapshot for this saved asset yet.</p>
                {editable && selected && (
                  <button
                    className="primary"
                    disabled={busy}
                    onClick={() =>
                      void act(
                        () => request('assess', 'POST', { assessmentId: selected.id }),
                        'CPM evaluation saved',
                      )
                    }
                  >
                    Evaluate saved evidence
                  </button>
                )}
              </>
            )}
            {state && (
              <>
                {state.snapshot.demonstration && (
                  <div className="notice">
                    DEMONSTRATION — deterministic fixtures, not live network validation.
                  </div>
                )}
                {state.snapshot.validity === 'invalidated' && (
                  <div className="notice" role="alert">
                    Evidence invalidated: {state.snapshot.invalidationReason}. Posture is stale and
                    requires reassessment.
                  </div>
                )}
                <div className="cpm-summary">
                  <article>
                    <span>Quantum exposure</span>
                    <strong>{state.currentQuantumExposure}</strong>
                    <p>
                      {state.currentStatus} · {state.snapshot.publicKeyExposure}
                    </p>
                  </article>
                  <article>
                    <span>Authorization evidence</span>
                    <strong>Unknown</strong>
                    <p>Custody and complete authorization remain unverified.</p>
                  </article>
                  <article>
                    <span>Assessed at</span>
                    <strong>
                      {new Date(state.snapshot.assessedAt)
                        .toISOString()
                        .slice(0, 19)
                        .replace('T', ' ')}{' '}
                      UTC
                    </strong>
                    <p>
                      {state.snapshot.policyId} / {state.snapshot.policyVersion}
                    </p>
                  </article>
                </div>
                <p>
                  Observed algorithms:{' '}
                  {state.snapshot.observedAlgorithms.join(', ') ||
                    'None supported by this evidence'}
                  . Exposure describes a cryptographic dependency; it does not establish current
                  compromise.
                </p>
              </>
            )}
            {mode === 'posture' && (
              <>
                <h3>Continuous monitoring</h3>
                <p>
                  {schedules.filter((s) => s.enabled).length} active schedules in the displayed
                  tenant page (up to 100). Worker state comes from persisted jobs.
                </p>
                {editable && selected && (
                  <form
                    className="cpm-form"
                    onSubmit={(e) => {
                      e.preventDefault();
                      const data = new FormData(e.currentTarget);
                      void act(
                        () =>
                          request('monitoring', 'POST', {
                            input: {
                              address: selected.observation.address,
                              chainId: selected.observation.chainId,
                              ...(selected.observation.signature
                                ? { transactionHash: selected.observation.signature.hash }
                                : {}),
                              ...(selected.observation.token
                                ? { adapter: 'ownable-erc20' }
                                : selected.observation.tokenAuthority
                                  ? { adapter: 'token-authority' }
                                  : {}),
                            },
                            intervalSeconds: Number(data.get('interval')),
                          }),
                        'Monitoring schedule created',
                      );
                    }}
                  >
                    <label htmlFor="cpm-interval">Assessment frequency</label>
                    <select id="cpm-interval" name="interval">
                      <option value="3600">Every hour</option>
                      <option value="86400">Every day</option>
                      <option value="60">Every minute (local demonstration)</option>
                    </select>
                    <button className="primary" disabled={busy}>
                      Schedule monitoring
                    </button>
                  </form>
                )}
                {!currentSchedules.length && <p>No monitoring schedule for this asset.</p>}
                {currentSchedules.map((s) => (
                  <article className="finding" key={s.id}>
                    <span className="status">
                      {s.enabled ? (s.worker_state ?? 'awaiting worker') : 'paused'}
                    </span>
                    <strong>Every {s.interval_seconds} seconds</strong>
                    <dl>
                      <dt>Last successful collection</dt>
                      <dd>{s.last_success_at ?? 'No successful run yet'}</dd>
                      <dt>Last collection failure</dt>
                      <dd>
                        {s.last_failure_at
                          ? `${s.last_failure_at}: ${s.last_failure}`
                          : 'None recorded'}
                      </dd>
                      <dt>Next scheduled assessment</dt>
                      <dd>{s.enabled ? s.next_run_at : 'Paused'}</dd>
                      <dt>Worker heartbeat</dt>
                      <dd>{s.heartbeat_at ?? 'No worker has claimed a job'}</dd>
                    </dl>
                    {s.last_failure_at &&
                      (!s.last_success_at || s.last_failure_at > s.last_success_at) && (
                        <p role="status">
                          Collection failed. Previous findings remain; current posture is unknown
                          until reassessment succeeds.
                        </p>
                      )}
                    {admin && (
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() =>
                          void act(
                            () => request(`monitoring/${s.id}`, 'PATCH', { enabled: !s.enabled }),
                            s.enabled ? 'Monitoring paused' : 'Monitoring resumed',
                          )
                        }
                      >
                        {s.enabled ? 'Pause monitoring' : 'Resume monitoring'}
                      </button>
                    )}
                  </article>
                ))}
                <h3>Findings and remediation</h3>
                {state?.currentFindings.map((f) => {
                  const event = state.lifecycle.find(
                      (e) => e.rule_id === f.ruleId && e.policy_id === f.policyId,
                    ),
                    rec = recommendations.find((r) => r.assetId === asset && r.ruleId === f.ruleId);
                  return (
                    <article className="finding" key={`${f.policyId}:${f.ruleId}`}>
                      <span className="status">
                        {rec?.priority ?? 'NEEDS_EVIDENCE'} ·{' '}
                        {event?.effectiveStatus ?? f.effectiveStatus}
                      </span>
                      <strong>{f.title}</strong>
                      <p>{f.rationale}</p>
                      {rec && (
                        <>
                          <p>{rec.nextAction}</p>
                          <p>Dependency: {rec.dependency}</p>
                        </>
                      )}
                      <code>{f.evidenceHash}</code>
                      {admin && state && (
                        <details>
                          <summary>Manage finding</summary>
                          <form
                            className="cpm-form"
                            onSubmit={(e) => {
                              e.preventDefault();
                              const data = new FormData(e.currentTarget);
                              void act(
                                () =>
                                  request(
                                    `findings/${encodeURIComponent(f.lastObservedSnapshotId)}/${f.ruleId}`,
                                    'PATCH',
                                    {
                                      status: data.get('status'),
                                      reason: data.get('reason'),
                                      ...(data.get('expires')
                                        ? {
                                            expiresAt: new Date(
                                              String(data.get('expires')),
                                            ).toISOString(),
                                          }
                                        : {}),
                                    },
                                  ),
                                'Finding history updated',
                              );
                            }}
                          >
                            <label>
                              Transition
                              <select name="status" aria-label={`Status for ${f.ruleId}`}>
                                <option value="acknowledged">Acknowledge</option>
                                <option value="in_remediation">In remediation</option>
                                <option value="pending_verification">Pending verification</option>
                                <option value="excepted">Timed exception</option>
                                <option value="open">Reopen</option>
                                <option value="administratively_closed">
                                  Administrative closure
                                </option>
                              </select>
                            </label>
                            <label>
                              Reason
                              <input name="reason" minLength={10} maxLength={1000} required />
                            </label>
                            <label>
                              Exception expiry
                              <input name="expires" type="datetime-local" />
                            </label>
                            <button className="secondary" disabled={busy}>
                              Record transition
                            </button>
                          </form>
                        </details>
                      )}
                    </article>
                  );
                })}
                <h3>Cryptographic drift</h3>
                <p>
                  Latest 100 tenant events, filtered to this asset. Missing observations are
                  incomplete evidence.
                </p>
                {!drift.some((d) => d.assetId === asset) && (
                  <p>No cryptographic change recorded.</p>
                )}
                {drift
                  .filter((d) => d.assetId === asset)
                  .map((d) => (
                    <details key={d.id} className="finding">
                      <summary>
                        {d.type} · {d.confidence} · {d.detectedAt}
                      </summary>
                      <p>
                        Previous assessment: <code>{d.previousAssessmentId}</code>
                      </p>
                      <p>
                        Current assessment: <code>{d.currentAssessmentId}</code>
                      </p>
                      <pre>
                        {JSON.stringify(
                          { before: d.before, after: d.after, evidence: d.evidenceReferences },
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  ))}
                <h3>Assessment history</h3>
                <p>{history.length} latest stored CPM snapshots for this asset.</p>
                {history.map((h) => (
                  <p key={h.id}>
                    {h.assessedAt} · {h.policyVersion} · {h.quantumExposure} · {h.validity}
                  </p>
                ))}
              </>
            )}
            {mode === 'migration' && selected && (
              <>
                <h3>Define the verification scope</h3>
                <p>
                  Supported verification compares owner-accessor or bytecode properties. PQC
                  migration compatibility and execution remain unsupported.
                </p>
                {editable && (
                  <form
                    className="cpm-form"
                    onSubmit={(e) => {
                      e.preventDefault();
                      const data = new FormData(e.currentTarget);
                      void act(async () => {
                        const result = await request<Schemas['MigrationResult']>(
                          'migrations/assess',
                          'POST',
                          {
                            assessmentId: selected.id,
                            goal: data.get('goal'),
                            scope: data.get('scope'),
                            criteria: [{ kind: data.get('kind'), expected: data.get('expected') }],
                          },
                        );
                        setMigration(result);
                      }, 'Migration assessment saved');
                    }}
                  >
                    <label htmlFor="cpm-goal">Goal</label>
                    <select id="cpm-goal" name="goal">
                      <option value="authorization-change">
                        Defined authorization property change
                      </option>
                      <option value="cryptographic-migration">
                        Cryptographic migration readiness
                      </option>
                    </select>
                    <label htmlFor="cpm-scope">Defined scope</label>
                    <input
                      id="cpm-scope"
                      name="scope"
                      defaultValue="Verify the defined owner() accessor value only"
                      minLength={10}
                      maxLength={500}
                      required
                    />
                    <label htmlFor="cpm-kind">Acceptance criterion</label>
                    <select id="cpm-kind" name="kind">
                      <option value="owner_equals">owner() equals</option>
                      <option value="bytecode_hash_equals">Bytecode SHA-256 equals</option>
                      <option value="signature_algorithm">
                        Observed signature algorithm equals
                      </option>
                    </select>
                    <label htmlFor="cpm-expected">Expected value</label>
                    <input
                      id="cpm-expected"
                      name="expected"
                      placeholder="0x… owner address"
                      maxLength={80}
                      required
                    />
                    <button className="primary" disabled={busy}>
                      Assess migration readiness
                    </button>
                  </form>
                )}
                {migration && (
                  <article className="finding">
                    <span className="status">{migration.effectiveStatus ?? migration.status}</span>
                    <strong>{migration.scope}</strong>
                    <p>
                      {migration.missingEvidence.join('; ') ||
                        'Defined property evidence is available.'}
                    </p>
                    <ul>
                      {migration.checks.map((c, i) => (
                        <li key={i}>
                          {c.criterion.kind}: {c.result}
                        </li>
                      ))}
                    </ul>
                    <p>{migration.limitations.join(' ')}</p>
                    <code>{migration.id}</code>
                    {editable && (
                      <form
                        className="cpm-form"
                        onSubmit={(e) => {
                          e.preventDefault();
                          const data = new FormData(e.currentTarget);
                          void act(
                            async () =>
                              setMigration(
                                await request<Schemas['MigrationResult']>(
                                  `migrations/${migration.id}/verify`,
                                  'POST',
                                  { assessmentId: data.get('assessmentId') },
                                ),
                              ),
                            'Verification result saved',
                          );
                        }}
                      >
                        <label>
                          Later saved assessment
                          <select name="assessmentId">
                            {[
                              ...new Map([
                                ...history.map(
                                  (h) =>
                                    [
                                      h.assessmentId,
                                      {
                                        id: h.assessmentId,
                                        label: `${h.assessedAt} · ${h.validity}`,
                                      },
                                    ] as const,
                                ),
                                ...items
                                  .filter(
                                    (a) =>
                                      a.observation.address === selected.observation.address &&
                                      a.observation.chainId === selected.observation.chainId,
                                  )
                                  .map(
                                    (a) =>
                                      [
                                        a.id,
                                        {
                                          id: a.id,
                                          label: `${a.createdAt} · ${a.observation.blockNumber}`,
                                        },
                                      ] as const,
                                  ),
                              ]).values(),
                            ].map((a) => (
                              <option value={a.id} key={a.id}>
                                {a.label}
                              </option>
                            ))}
                          </select>
                        </label>
                        <button className="secondary" disabled={busy}>
                          Verify defined scope
                        </button>
                      </form>
                    )}
                  </article>
                )}
              </>
            )}
          </>
        )}
        {message && <p role="status">{message}</p>}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
      </div>
    </section>
  );
}
