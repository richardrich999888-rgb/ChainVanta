import { api } from '../../../../lib/api';
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return Response.json({ error: 'Invalid ID' }, { status: 400 });
  try {
    const response = await api(`/assessments/${id}`);
    return Response.json(await response.json(), {
      status: response.status,
      headers: {
        'Cache-Control': 'no-store',
        ...(response.ok
          ? { 'Content-Disposition': `attachment; filename="chainvanta-${id}.json"` }
          : {}),
      },
    });
  } catch {
    return Response.json({ error: 'API unavailable' }, { status: 503 });
  }
}
