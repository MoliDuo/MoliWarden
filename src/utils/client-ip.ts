// Client address helpers for Vercel.
//
// Vercel's edge overwrites X-Forwarded-For / X-Real-IP with the real client
// address, so they can be trusted there. CF-Connecting-IP is NOT set by
// Vercel and would be fully client-controlled, so it is deliberately ignored.

export function getClientIp(request: Request): string | null {
  const candidates = [
    request.headers.get('X-Vercel-Forwarded-For')?.split(',')[0]?.trim(),
    request.headers.get('X-Real-IP')?.trim(),
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim(),
  ];
  for (const candidate of candidates) {
    if (candidate) return candidate;
  }
  return null;
}

export function getClientCountry(request: Request): string | null {
  return request.headers.get('X-Vercel-IP-Country') || null;
}
