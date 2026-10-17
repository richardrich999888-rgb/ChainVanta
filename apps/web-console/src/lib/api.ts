import 'server-only';
import { cookies } from 'next/headers';

export const SESSION_COOKIE = 'chainvanta_session';
export async function api(path: string, init: RequestInit = {}, key?: string) {
  const token = key ?? (await cookies()).get(SESSION_COOKIE)?.value;
  return fetch(`${process.env.API_BASE_URL ?? 'http://127.0.0.1:4000'}/v1${path}`, {
    ...init,
    cache: 'no-store',
    redirect: 'error',
    headers: {
      ...init.headers,
      'content-type': 'application/json',
      authorization: `Bearer ${token ?? ''}`,
    },
    signal: AbortSignal.timeout(180_000),
  });
}
export function sameOrigin(request: Request): boolean {
  const expected = process.env.WEB_ORIGIN ?? 'http://127.0.0.1:3000';
  return request.headers.get('origin') === expected;
}
