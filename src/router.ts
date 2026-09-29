import { Env } from './types';
import { AuthService } from './services/auth';
import { RateLimitService } from './services/ratelimit';
import { errorResponse } from './utils/response';
import { LIMITS } from './config/limits';
import { handleAdminBackupRoute } from './router-admin-backup';

function jwtSecretUnsafeReason(env: Env): 'missing' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  try {
    if (jwtSecretUnsafeReason(env)) {
      return errorResponse('Server configuration error: JWT_SECRET is not set or too weak', 500);
    }

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

    const rateLimitCheck = await new RateLimitService(env.DB).consumeBudget(
      `${userId}:api`,
      LIMITS.rateLimit.apiRequestsPerMinute
    );
    if (!rateLimitCheck.allowed) {
      return errorResponse(`Rate limit exceeded. Try again in ${rateLimitCheck.retryAfterSeconds} seconds.`, 429);
    }

    if (path.startsWith('/api/admin/backup')) {
      if (currentUser.role !== 'admin') return errorResponse('Forbidden', 403);
      const response = await handleAdminBackupRoute(request, env, currentUser, path, method);
      if (response) return response;
    }

    return errorResponse('Route not found', 404);
  } catch (error) {
    console.error('Request error:', error);
    return errorResponse('Internal server error', 500);
  }
}
