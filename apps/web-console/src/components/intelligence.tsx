'use client';
import { useState } from 'react';
import type { Assessment } from '../../../../packages/domain-models/src/index';
export function Intelligence({
  view,
  items,
  selected,
  onSelect,
}: {
  view: string;
  items: Assessment[];
  selected: Assessment | null;
  onSelect: (item: Assessment) => void;
}) {
  const [node, setNode] = useState('');
  const findings = items.flatMap((item) =>
    item.posture.findings.map((f) => ({ ...f, id: item.id })),
  );
  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <h2>{view}</h2>
          <p>Based on the latest {items.length} saved assessments. Unknowns remain explicit.</p>
        </div>
        {view === 'Reports' && (
          <a className="secondary button" href="/api/reports">
            Export report JSON ↓
          </a>
        )}
      </div>
      <div className="evidence-body">
        {!items.length ? (
          <p>No assessments yet. Collect evidence from Overview.</p>
        ) : (
          <>
            <label htmlFor="intelligence-assessment">Assessment context</label>
            <select
              id="intelligence-assessment"
              value={selected?.id ?? ''}
              onChange={(event) => {
                const item = items.find((v) => v.id === event.target.value);
                if (item) {
                  onSelect(item);
                  setNode('');
                }
              }}
            >
              {items.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.observation.address} · {item.createdAt}
                </option>
              ))}
            </select>
            {view === 'CBOM' && selected && (
              <>
                <h3>Cryptographic dependencies</h3>
                {selected.cbom.components.map((c, i) => (
                  <article className="finding" key={i}>
                    <span className="status">{c.confidence}</span>
                    <strong>{c.algorithm}</strong>
                    <p>
                      {c.purpose} · {c.domain ?? 'account-authorization'}
                    </p>
                    <p>{c.basis}</p>
                    <code>{selected.evidenceHash}</code>
                  </article>
                ))}
              </>
            )}
            {view === 'QBOM' && selected && (
              <>
                <h3>{selected.qbom.status}</h3>
                <p>{selected.qbom.reason}</p>
                <p>Rule: {selected.qbom.ruleVersion ?? 'legacy'}</p>
                <h3>Migration priority</h3>
                <p>
                  {selected.observation.signature
                    ? 'Investigate transaction-signature migration with the chain and wallet maintainers. No drop-in PQC upgrade is asserted.'
                    : 'Discover authorization mechanisms before assigning migration priority.'}
                </p>
                <p>
                  Consensus, transport and application cryptography remain outside this observation.
                </p>
              </>
            )}
            {view === 'Trust Graph' && selected && (
              <>
                <h3>Evidence-supported relationships</h3>
                <div className="graph-nodes">
                  {selected.trustGraph.nodes.map((n) => (
                    <button
                      className="secondary"
                      key={n.id}
                      onClick={() => setNode(n.id)}
                      aria-pressed={node === n.id}
                    >
                      {n.kind}
                      <small>{n.id.slice(0, 24)}…</small>
                    </button>
                  ))}
                </div>
                <ul>
                  {selected.trustGraph.edges
                    .filter((e) => !node || e.from === node || e.to === node)
                    .map((e, i) => (
                      <li key={i}>
                        <code>{e.from}</code>
                        <p>→ {e.relation} →</p>
                        <code>{e.to}</code>
                      </li>
                    ))}
                </ul>
                {node && (
                  <button className="text-button" onClick={() => setNode('')}>
                    Show all relationships
                  </button>
                )}
                <p>Observed relationships do not establish causal risk propagation.</p>
              </>
            )}
            {view === 'Reports' && (
              <>
                <h3>Assessment summary</h3>
                <p>
                  {items.length} assessments across{' '}
                  {
                    new Set(items.map((v) => `${v.observation.chainId}:${v.observation.address}`))
                      .size
                  }{' '}
                  accounts.
                </p>
                <p>
                  {findings.filter((f) => f.severity === 'medium').length} medium findings ·{' '}
                  {findings.filter((f) => f.severity === 'info').length} informational findings.
                </p>
                <p>
                  {items.filter((v) => v.qbom.status === 'unknown').length} assessments have unknown
                  quantum exposure.
                </p>
                <p>
                  No composite risk score is assigned. Export includes evidence references and
                  quantum migration limitations.
                </p>
              </>
            )}
          </>
        )}
      </div>
    </section>
  );
}
