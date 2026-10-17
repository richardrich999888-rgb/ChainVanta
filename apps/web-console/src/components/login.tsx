'use client';
import { useState } from 'react';
export function Login({ expired = false }: { expired?: boolean }) {
  const [error, setError] = useState(expired ? 'Your session expired. Sign in again.' : '');
  const [busy, setBusy] = useState(false);
  return (
    <main className="login">
      <div className="login-intro">
        <div className="eyebrow">SYNTRIASS / SECURITY INTELLIGENCE</div>
        <h1>
          Understand your
          <br />
          cryptographic
          <br />
          <span>exposure.</span>
        </h1>
        <p>
          From on-chain observations to verifiable evidence.
          <br />A clearer view of your Web3 security posture.
        </p>
        <div className="login-proof">
          READ-ONLY DISCOVERY <span>•</span> EVIDENCE FIRST
        </div>
      </div>
      <div className="login-card">
        <div className="brand">
          <span className="brand-mark">◈</span> ChainVanta
        </div>
        <div className="eyebrow">WORKSPACE ACCESS</div>
        <h2>Open your console</h2>
        <p>Use the tenant API key issued by your workspace operator.</p>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError('');
            try {
              const response = await fetch('/api/session', {
                method: 'POST',
                body: new FormData(event.currentTarget),
              });
              const data = await response.json();
              if (!response.ok) setError(data.error);
              else window.location.assign('/');
            } catch {
              setError('Unable to connect. Try again.');
            } finally {
              setBusy(false);
            }
          }}
        >
          <label htmlFor="key">Tenant API key</label>
          <input
            id="key"
            name="key"
            type="password"
            required
            minLength={32}
            maxLength={256}
            autoComplete="current-password"
            placeholder="Enter your workspace key"
          />
          <button className="primary" disabled={busy}>
            {busy ? 'Connecting…' : 'Continue to workspace →'}
          </button>
          <p role="alert" className="error">
            {error}
          </p>
        </form>
        <div className="fineprint">
          Prototype access · Session lasts one hour
          <br />
          No wallet connection or private keys required.
        </div>
      </div>
    </main>
  );
}
