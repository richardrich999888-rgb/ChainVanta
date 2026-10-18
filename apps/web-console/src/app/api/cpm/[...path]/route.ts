import { api, sameOrigin } from '../../../../lib/api';
async function proxy(request: Request, context: { params: Promise<{ path: string[] }> }) {
  if (request.method !== 'GET' && !sameOrigin(request))
    return Response.json({ error: { message: 'Invalid origin' } }, { status: 403 });
  const { path } = await context.params;
  if (
    path.length > 4 ||
    !path.every((p) => /^[a-zA-Z0-9:_-]{1,150}$/.test(p)) ||
    ![
      'assess',
      'posture',
      'history',
      'policies',
      'assignments',
      'monitoring',
      'jobs',
      'drift',
      'remediation',
      'notifications',
      'findings',
      'migrations',
    ].includes(path[0] ?? '')
  )
    return Response.json({ error: { message: 'Unsupported route' } }, { status: 404 });
  try {
    let body: string | undefined;
    if (request.method !== 'GET' && request.body) {
      const reader = request.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 8192) {
          await reader.cancel();
          return Response.json({ error: { message: 'Request too large' } }, { status: 413 });
        }
        chunks.push(value);
      }
      body = Buffer.concat(chunks).toString('utf8');
    }
    const url = new URL(request.url),
      query = new URLSearchParams();
    for (const name of ['limit', 'offset'])
      if (url.searchParams.has(name)) query.set(name, url.searchParams.get(name)!);
    const response = await api(`/cpm/${path.map(encodeURIComponent).join('/')}?${query}`, {
      method: request.method,
      ...(body ? { body } : {}),
    });
    return Response.json(await response.json(), {
      status: response.status,
      headers: { 'Cache-Control': 'no-store' },
    });
  } catch {
    return Response.json(
      { error: { message: 'CPM unavailable. Saved evidence is unchanged.' } },
      { status: 503 },
    );
  }
}
export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
