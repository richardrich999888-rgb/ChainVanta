import { api, sameOrigin } from '../../../lib/api';
import { ScanRequest } from '../../../../../../packages/domain-models/src/index';
export async function POST(request: Request) {
  if (!sameOrigin(request))
    return Response.json({ error: { message: 'Invalid origin' } }, { status: 403 });
  try {
    const text = await request.text();
    if (text.length > 2048)
      return Response.json({ error: { message: 'Request too large' } }, { status: 413 });
    const parsed = ScanRequest.safeParse(JSON.parse(text));
    if (!parsed.success)
      return Response.json(
        { error: { message: 'Enter a valid EVM address and chain' } },
        { status: 400 },
      );
    const response = await api('/assessments', {
      method: 'POST',
      headers: request.headers.has('idempotency-key')
        ? { 'idempotency-key': request.headers.get('idempotency-key')! }
        : {},
      body: JSON.stringify(parsed.data),
    });
    return Response.json(await response.json(), {
      status: response.status,
      headers: { 'Cache-Control': 'no-store' },
    });
  } catch {
    return Response.json(
      { error: { message: 'Assessment unavailable. Check the API and try again.' } },
      { status: 503 },
    );
  }
}
