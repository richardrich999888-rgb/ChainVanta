import { cookies } from 'next/headers';
import { api, sameOrigin, SESSION_COOKIE } from '../../../lib/api';
export async function POST(request: Request) {
  if (!sameOrigin(request)) return Response.json({ error: 'Invalid origin' }, { status: 403 });
  try {
    const form = await request.formData();
    const key = form.get('key');
    if (typeof key !== 'string' || key.length < 32 || key.length > 256)
      return Response.json({ error: 'Enter a valid API key' }, { status: 400 });
    const response = await api('/session', {}, key);
    if (!response.ok)
      return Response.json(
        { error: response.status === 401 ? 'API key was not accepted' : 'API is unavailable' },
        { status: response.status === 401 ? 401 : 503 },
      );
    (await cookies()).set(SESSION_COOKIE, key, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 3600,
    });
    return Response.json({ ok: true });
  } catch {
    return Response.json(
      { error: 'API is unavailable. Check the server connection.' },
      { status: 503 },
    );
  }
}
export async function DELETE(request: Request) {
  if (!sameOrigin(request)) return Response.json({ error: 'Invalid origin' }, { status: 403 });
  (await cookies()).delete(SESSION_COOKIE);
  return Response.json({ ok: true });
}
