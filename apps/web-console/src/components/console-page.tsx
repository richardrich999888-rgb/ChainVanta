import { cookies } from 'next/headers';
import { api, SESSION_COOKIE } from '../lib/api';
import { Console } from './console';
import { Login } from './login';
import type { Assessment } from '../../../../packages/domain-models/src/index';
import type { View } from '../lib/navigation';

export type ConsolePageProps = {
  searchParams: Promise<{ assessment?: string | string[] }>;
};

export default async function ConsolePage({
  view,
  searchParams,
}: ConsolePageProps & { view: View }) {
  if (!(await cookies()).has(SESSION_COOKIE)) return <Login />;
  const query = await searchParams;
  const selectedId = typeof query.assessment === 'string' ? query.assessment : undefined;
  try {
    const [assessments, chains, session] = await Promise.all([
      api('/assessments'),
      api('/chains'),
      api('/session'),
    ]);
    if ([assessments, chains, session].some((response) => response.status === 401))
      return <Login expired />;
    if (![assessments, chains, session].every((response) => response.ok))
      throw new Error('Unavailable');
    const principal = await session.json();
    return (
      <Console
        key={`${view}:${selectedId ?? ''}`}
        view={view}
        selectedId={selectedId}
        initial={(await assessments.json()) as Assessment[]}
        chains={await chains.json()}
        tenantId={principal.tenantId}
        role={principal.role}
      />
    );
  } catch {
    return (
      <main className="login">
        <div className="login-card">
          <div className="brand">◈ ChainVanta</div>
          <h1>Connection interrupted</h1>
          <p>
            The API or evidence store is unavailable. Your saved assessments will appear when the
            connection returns.
          </p>
          <a className="primary button" href="/">
            Try again
          </a>
        </div>
      </main>
    );
  }
}
