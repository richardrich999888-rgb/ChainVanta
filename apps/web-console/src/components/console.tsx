'use client';
import { useState } from 'react';
import { Intelligence } from './intelligence';
import { ModuleCatalog, type Assessment } from '../../../../packages/domain-models/src/index';
import { useConsoleNavigation } from '../hooks/use-console-navigation';
import { viewRoutes, type View } from '../lib/navigation';
const short = (value: string) => `${value.slice(0, 8)}…${value.slice(-6)}`;

export function Console({
  initial,
  chains,
  tenantId,
  view,
  selectedId,
}: {
  initial: Assessment[];
  chains: { chainId: number; name: string }[];
  tenantId: string;
  view: View;
  selectedId?: string;
}) {
  const navigate = useConsoleNavigation();
  const [items, setItems] = useState(initial);
  const [selected, setSelected] = useState<Assessment | null>(
    (selectedId ? initial.find((item) => item.id === selectedId) : initial[0]) ?? null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const assets = new Set(
    items.map((item) => `${item.observation.chainId}:${item.observation.address}`),
  ).size;
  const titles: Record<View, string> = {
    Overview: 'Your cryptographic landscape.',
    Inventory: 'Every observation, in context.',
    Evidence: 'Findings you can trace.',
    Settings: 'Workspace configuration.',
    Migrations: 'Migration readiness.',
    CBOM: 'Know the cryptographic dependencies.',
    QBOM: 'Plan from verified evidence.',
    CPM: 'Trace posture and change.',
    'Trust Graph': 'Explore observed relationships.',
    Reports: 'Intelligence you can share.',
  };
  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brand-mark">◈</span> ChainVanta
        </a>
        <div className="workspace">
          <span className="workspace-icon">S</span>
          <div>
            SYNTRIASS<span>Research workspace</span>
          </div>
          <span className="dot" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {(Object.keys(viewRoutes) as View[]).map((name, index) => (
            <button
              key={name}
              aria-label={name}
              onClick={() => navigate(name, selected?.id)}
              aria-current={view === name ? 'page' : undefined}
              className={view === name ? 'nav-item active' : 'nav-item'}
            >
              <span>{['▦', '▤', '◈', '◌', '◷', '◇', '◇', '↗', '▧', '⊞'][index]}</span>
              {name}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="scope">
            <span className="dot" /> Read-only analysis
            <p>
              No keys. No signatures.
              <br />
              Just observable evidence.
            </p>
          </div>
          <button
            className="signout"
            onClick={async () => {
              await fetch('/api/session', { method: 'DELETE' });
              window.location.assign('/');
            }}
          >
            Sign out <span>↗</span>
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <span>
            Workspace <span className="slash">/</span> <strong>{view}</strong>
          </span>
          <div>
            <span className="prototype">PROTOTYPE</span>
            <span className="avatar" title={tenantId}>
              S
            </span>
          </div>
        </header>
        <main className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">CRYPTOGRAPHIC INTELLIGENCE</div>
              <h1>{titles[view]}</h1>
              <p>Discover on-chain assets. Understand what is known. Preserve the evidence.</p>
            </div>
            <span className="network-pill">
              <span className="dot" />
              {chains.length} configured {chains.length === 1 ? 'network' : 'networks'}
            </span>
          </div>
          {items.some((item) => item.observation.demonstration) && (
            <div className="notice">
              DEMONSTRATION DATA — deterministic local blockchain fixtures, not live-chain evidence.
            </div>
          )}
          {['CBOM', 'QBOM', 'CPM', 'Trust Graph', 'Reports'].includes(view) && (
            <Intelligence view={view} items={items} selected={selected} onSelect={setSelected} />
          )}
          {view === 'Overview' && (
            <>
              <div className="metrics">
                {[
                  ['Observed assets', String(assets), 'Unique accounts in recent assessments', '◈'],
                  ['Saved assessments', String(items.length), 'Latest 50 in this workspace', '▤'],
                  [
                    'Verified signatures',
                    String(items.filter((v) => v.observation.signature).length),
                    'Supplied transaction signatures only',
                    '◌',
                  ],
                  ['Evidence records', String(items.length), 'Hash-checked on retrieval', '◇'],
                ].map(([title, value, detail, icon]) => (
                  <section className="metric" key={title}>
                    <div>
                      {title}
                      <span>{icon}</span>
                    </div>
                    <strong>{value}</strong>
                    <p>{detail}</p>
                  </section>
                ))}
              </div>
              <section className="scan-panel">
                <div className="scan-intro">
                  <div className="section-kicker">START WITH AN ADDRESS</div>
                  <h2>Discover an account</h2>
                  <p>
                    Capture a finalized snapshot of balance, nonce and bytecode from your configured
                    RPC provider.
                  </p>
                  <div className="mini-flow">
                    Discover <span>→</span> Assess <span>→</span> Verify
                  </div>
                </div>
                <form
                  className="scan-form"
                  onSubmit={async (event) => {
                    event.preventDefault();
                    const form = new FormData(event.currentTarget);
                    setBusy(true);
                    setError('');
                    try {
                      const response = await fetch('/api/assessments', {
                        method: 'POST',
                        headers: {
                          'content-type': 'application/json',
                          'idempotency-key': crypto.randomUUID(),
                        },
                        body: JSON.stringify({
                          address: form.get('address'),
                          chainId: Number(form.get('chainId')),
                          ...(form.get('transactionHash')
                            ? { transactionHash: form.get('transactionHash') }
                            : {}),
                          ...(form.get('adapter') ? { adapter: form.get('adapter') } : {}),
                        }),
                      });
                      const data = await response.json();
                      if (!response.ok) setError(data.error?.message ?? 'Assessment failed');
                      else {
                        setItems((current) => [data, ...current].slice(0, 50));
                        setSelected(data);
                      }
                    } catch {
                      setError(
                        'Connection lost. Refresh to check whether the assessment was saved before retrying.',
                      );
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <div className="form-row">
                    <div>
                      <label htmlFor="chainId">Network</label>
                      <select id="chainId" name="chainId">
                        {chains.map((chain) => (
                          <option key={chain.chainId} value={chain.chainId}>
                            {chain.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="address-field">
                      <label htmlFor="address">EVM account address</label>
                      <input
                        id="address"
                        name="address"
                        placeholder="0x…"
                        required
                        pattern="0x[0-9a-fA-F]{40}"
                        maxLength={42}
                        spellCheck={false}
                        autoComplete="off"
                      />
                    </div>
                  </div>
                  <details>
                    <summary>Additional evidence (optional)</summary>
                    <label htmlFor="transactionHash">Transaction hash sent by this account</label>
                    <input
                      id="transactionHash"
                      name="transactionHash"
                      pattern="0x[0-9a-fA-F]{64}"
                      placeholder="0x… (finalized legacy, type 1 or type 2)"
                    />
                    <label htmlFor="adapter">Contract adapter</label>
                    <select id="adapter" name="adapter">
                      <option value="">Account snapshot only</option>
                      <option value="ownable-erc20">Ownable ERC20 accessors</option>
                    </select>
                    <p>
                      Use the token adapter only for a known compatible contract. Unsupported
                      patterns fail explicitly.
                    </p>
                  </details>
                  <button className="primary" disabled={busy}>
                    {busy ? 'Collecting finalized evidence…' : 'Run assessment ↗'}
                  </button>
                  <span className="form-note">
                    {busy ? 'This can take up to 45 seconds.' : 'No transactions are submitted.'}
                  </span>
                  <p role="alert" className="error">
                    {error}
                  </p>
                </form>
              </section>
            </>
          )}
          {(view === 'Overview' || view === 'Inventory') && (
            <section className="panel">
              <div className="panel-title">
                <div>
                  <h2>
                    Recent assessments <span className="count">{items.length}</span>
                  </h2>
                  <p>Provider observations with an explicit chain of evidence.</p>
                </div>
                <span className="small-muted">FINALIZED SNAPSHOTS</span>
              </div>
              {items.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Account</th>
                        <th>Network</th>
                        <th>Account state</th>
                        <th>Quantum posture</th>
                        <th>Evidence</th>
                        <th>
                          <span className="sr-only">Action</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((item) => (
                        <tr key={item.id}>
                          <td>
                            <span className="account-icon">◈</span>
                            <code title={item.observation.address}>
                              {short(item.observation.address)}
                            </code>
                            <small>
                              {new Date(item.createdAt)
                                .toISOString()
                                .replace('T', ' ')
                                .slice(0, 16)}{' '}
                              UTC
                            </small>
                          </td>
                          <td>
                            {chains.find((c) => c.chainId === item.observation.chainId)?.name ??
                              item.observation.chainId}
                          </td>
                          <td>
                            {item.assetKind === 'code-bearing-account'
                              ? 'Code present'
                              : 'No code observed'}
                          </td>
                          <td>
                            <span className="status unknown">
                              {item.qbom.status === 'unknown' ? '◌ Unknown' : 'Classical signature'}
                            </span>
                          </td>
                          <td>
                            <span className="verified">◇ Hash verified</span>
                          </td>
                          <td>
                            <button
                              className="text-button"
                              onClick={() => {
                                setSelected(item);
                                navigate('Evidence', item.id);
                              }}
                            >
                              Inspect ↗
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">
                  <span>◇</span>
                  <h3>Your evidence starts here</h3>
                  <p>
                    Run an assessment to build your first cryptographic inventory.
                    <br />
                    Only collected observations will appear in this workspace.
                  </p>
                </div>
              )}
            </section>
          )}
          {view === 'Evidence' && (
            <section className="panel">
              <div className="panel-title">
                <div>
                  <h2>Evidence explorer</h2>
                  <p>Inspect the observation, assessment and provenance together.</p>
                </div>
                {selected && (
                  <a className="secondary button" href={`/api/assessments/${selected.id}`}>
                    Export JSON ↓
                  </a>
                )}
              </div>
              {selected ? (
                <div className="evidence-body">
                  <label htmlFor="observation">Saved assessment</label>
                  <select
                    id="observation"
                    value={selected.id}
                    onChange={(event) =>
                      setSelected(items.find((item) => item.id === event.target.value) ?? null)
                    }
                  >
                    {items.map((item) => (
                      <option key={item.id} value={item.id}>
                        {short(item.observation.address)} · {new Date(item.createdAt).toISOString()}
                      </option>
                    ))}
                  </select>
                  <div className="evidence-grid">
                    <div>
                      <div className="section-kicker">CRYPTOGRAPHIC INVENTORY</div>
                      <h3>{selected.cbom.components[0]?.algorithm ?? 'unknown'}</h3>
                      <p>{selected.cbom.components[0]?.basis}</p>
                      <div className="section-kicker">QUANTUM EXPOSURE</div>
                      <p>{selected.qbom.reason}</p>
                    </div>
                    <div>
                      <div className="section-kicker">OBSERVATION</div>
                      <dl>
                        <dt>Block number</dt>
                        <dd>{BigInt(selected.observation.blockNumber).toString()}</dd>
                        <dt>Balance (wei)</dt>
                        <dd>{selected.observation.balanceWei}</dd>
                        <dt>Transaction count</dt>
                        <dd>{selected.observation.transactionCount}</dd>
                        <dt>Evidence digest</dt>
                        <dd>
                          <code>{selected.evidenceHash}</code>
                        </dd>
                      </dl>
                    </div>
                  </div>
                  <h3>Posture findings</h3>
                  {selected.posture.findings.map((finding) => (
                    <div className="finding" key={finding.ruleId}>
                      <span className="status">{finding.confidence}</span>
                      <strong>{finding.title}</strong>
                      <p>{finding.rationale}</p>
                    </div>
                  ))}
                  <details>
                    <summary>Scope and limitations</summary>
                    <ul>
                      {selected.limitations.map((limitation) => (
                        <li key={limitation}>{limitation}</li>
                      ))}
                    </ul>
                  </details>
                  <details>
                    <summary>Full evidence record</summary>
                    <pre>{JSON.stringify(selected, null, 2)}</pre>
                  </details>
                </div>
              ) : (
                <div className="empty">
                  <h3>No evidence collected yet</h3>
                  <p>Run your first assessment from Overview.</p>
                  <button className="secondary" onClick={() => navigate('Overview')}>
                    Go to Overview
                  </button>
                </div>
              )}
            </section>
          )}
          {view === 'Migrations' && (
            <section className="panel">
              <div className="panel-title">
                <div>
                  <h2>Migration planning is planned</h2>
                  <p>Cross-chain migration adapters and execution are not implemented.</p>
                </div>
              </div>
              <div className="evidence-body">
                <p>
                  Review collected cryptographic dependencies and quantum exposure in QBOM before
                  defining a migration plan. Saved observations do not establish migration
                  compatibility.
                </p>
                <button className="secondary" onClick={() => navigate('QBOM', selected?.id)}>
                  Review QBOM
                </button>
              </div>
            </section>
          )}
          {view === 'Settings' && (
            <>
              <section className="panel">
                <div className="panel-title">
                  <div>
                    <h2>Workspace settings</h2>
                    <p>Tenant and network configuration is provisioned by your administrator.</p>
                  </div>
                </div>
                <div className="evidence-body">
                  <dl>
                    <dt>Tenant</dt>
                    <dd>
                      <code>{tenantId}</code>
                    </dd>
                    <dt>Configured networks</dt>
                    <dd>{chains.map((chain) => `${chain.name} (${chain.chainId})`).join(', ')}</dd>
                  </dl>
                  <h3>Module availability</h3>
                </div>
              </section>
              <div className="notice">
                Wallet and Stablecoin Intelligence are partially implemented. Ten remaining modules
                are planned and do not run assessments.
              </div>
              <div className="module-grid">
                {ModuleCatalog.map(([id, name, status]) => (
                  <section className="module-card" key={id}>
                    <div>
                      <span className="module-number">{id.slice(0, 2)}</span>
                      <span
                        className={`status ${status === 'partially implemented' ? 'available' : ''}`}
                      >
                        {status}
                      </span>
                    </div>
                    <h2>{name}</h2>
                    <p>
                      {status === 'partially implemented'
                        ? 'Finalized EVM snapshots, conservative inventory and traceable evidence.'
                        : 'Planned extension of the shared inventory, posture and evidence engines.'}
                    </p>
                    {status === 'partially implemented' && (
                      <button className="text-button" onClick={() => navigate('Overview')}>
                        Open discovery ↗
                      </button>
                    )}
                  </section>
                ))}
              </div>
            </>
          )}
          <footer>
            <span>
              ◈ ChainVanta <span className="footer-divider">/</span> A SYNTRIASS platform
            </span>
            <span>Evidence-backed. Uncertainty-aware.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
