import { api } from '../../../lib/api';
export async function GET(request: Request) {
  try {
    const response = await api('/history' + new URL(request.url).search);
    return Response.json(await response.json(), {
      status: response.status,
      headers: { 'Cache-Control': 'no-store' },
    });
  } catch {
    return Response.json({ error: { message: 'Service unavailable' } }, { status: 503 });
  }
}
