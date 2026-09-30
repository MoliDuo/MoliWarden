import { getRefreshTokenSlidingTtlMs } from '../../config/limits';

// The web vault keeps its refresh token in an HttpOnly cookie instead of
// JavaScript-readable storage. It opts in with a header on every token
// request; other clients get the token in the response body as usual.

const COOKIE = 'moliwarden_web_refresh';
const COOKIE_PATH = '/identity/connect';

export function isWebSession(request: Request): boolean {
  return request.headers.get('X-MoliWarden-Web-Session')?.trim() === '1';
}

export function sessionCookieToken(request: Request): string | null {
  for (const part of (request.headers.get('Cookie') ?? '').split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name !== COOKIE) continue;
    const value = rest.join('=').trim();
    try {
      return value ? decodeURIComponent(value) : null;
    } catch {
      return null;
    }
  }
  return null;
}

// A Set-Cookie value that stores `token`, or clears the cookie when null.
export function sessionCookie(request: Request, token: string | null): string {
  const maxAge = token ? Math.floor(getRefreshTokenSlidingTtlMs('web') / 1000) : 0;
  const parts = [`${COOKIE}=${encodeURIComponent(token ?? '')}`, `Path=${COOKIE_PATH}`, 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAge}`];
  if (new URL(request.url).protocol === 'https:') parts.push('Secure');
  return parts.join('; ');
}
