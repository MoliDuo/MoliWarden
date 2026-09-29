import { Env } from './types';
import { AuthService } from './services/auth';
import { RateLimitService, getClientIdentifier } from './services/ratelimit';
import { errorResponse } from './utils/response';
import { LIMITS } from './config/limits';
import { handleAuthenticatedRoute } from './router-authenticated';
import { handlePublicRoute } from './router-public';

function jwtSecretUnsafeReason(env: Env): 'missing' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

// Imports and attachment uploads send one request per item, so they draw
// from a larger budget of their own.
function isBulkRequest(path: string, method: string): boolean {
  if (method !== 'POST') return false;
  return (
    path === '/api/ciphers/import' ||
    /^\/api\/ciphers\/[a-f0-9-]+\/attachment\/v2$/i.test(path) ||
    /^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path)
  );
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const clientId = getClientIdentifier(request);

  async function enforcePublicRateLimit(
    category: string = 'public',
    maxRequests: number = LIMITS.rateLimit.publicRequestsPerMinute
  ): Promise<Response | null> {
    if (!clientId) {
      return new Response(
        JSON.stringify({
          error: 'Forbidden',
          error_description: 'Client IP is required',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    const rateLimit = new RateLimitService(env.DB);
    const shouldUseStrictBudget = category === 'public-sensitive' || category === 'register';
    const check = shouldUseStrictBudget
      ? await rateLimit.consumeStrictBudget(`${clientId}:${category}`, maxRequests)
      : await rateLimit.consumeBudget(`${clientId}:${category}`, maxRequests);
    if (check.allowed) return null;

    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${check.retryAfterSeconds} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(check.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  try {
    if (jwtSecretUnsafeReason(env)) {
      return errorResponse('Server configuration error: JWT_SECRET is not set or too weak', 500);
    }

    const publicResponse = await handlePublicRoute(request, env, path, method, enforcePublicRateLimit);
    if (publicResponse) return publicResponse;

    const auth = new AuthService(env);
    const authHeader = request.headers.get('Authorization');
    const verified = await auth.verifyAccessTokenWithUser(authHeader);
    if (!verified) {
      return errorResponse('Unauthorized', 401);
    }
    const { payload, user: currentUser } = verified;

    // Handlers read the acting device from this header; never from the client.
    const actingHeaders = new Headers(request.headers);
    actingHeaders.delete('X-MoliWarden-Acting-Device-Id');
    const actingDeviceId = String(payload.did || '').trim();
    if (actingDeviceId) actingHeaders.set('X-MoliWarden-Acting-Device-Id', actingDeviceId);
    request = new Request(request, { headers: actingHeaders });

    const userId = payload.sub;
    if (currentUser.status !== 'active') {
      return errorResponse('Account is disabled', 403);
    }

    const bulk = isBulkRequest(path, method);
    const rateLimitCheck = await new RateLimitService(env.DB).consumeBudget(
      `${userId}:${bulk ? 'bulk' : 'api'}`,
      bulk ? 1000 : LIMITS.rateLimit.apiRequestsPerMinute
    );
    if (!rateLimitCheck.allowed) {
      return errorResponse(`Rate limit exceeded. Try again in ${rateLimitCheck.retryAfterSeconds} seconds.`, 429);
    }

    const authenticatedResponse = await handleAuthenticatedRoute(request, env, userId, currentUser, path, method);
    if (authenticatedResponse) return authenticatedResponse;

    return errorResponse('Route not found', 404);
  } catch (error) {
    console.error('Request error:', error);
    return errorResponse('Internal server error', 500);
  }
}
