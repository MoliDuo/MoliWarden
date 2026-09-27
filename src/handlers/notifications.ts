import type { Env } from '../types';
import { errorResponse } from '../utils/response';

// Vercel Functions cannot keep WebSocket connections open, so the SignalR
// notification hub is not available. Returning 404 from negotiate makes the
// official clients back off and rely on their periodic sync instead.

const UNAVAILABLE_MESSAGE = 'Realtime notifications are not available on this server.';

export async function handleNotificationsNegotiate(_request: Request, _env: Env): Promise<Response> {
  return errorResponse(UNAVAILABLE_MESSAGE, 404);
}

export async function handleNotificationsHub(_request: Request, _env: Env): Promise<Response> {
  return errorResponse(UNAVAILABLE_MESSAGE, 404);
}

export async function handleAnonymousNotificationsHub(_request: Request, _env: Env): Promise<Response> {
  return errorResponse(UNAVAILABLE_MESSAGE, 404);
}
