import { LIMITS } from './config/limits';
import {
  handleAccessSend,
  handleAccessSendFile,
  handleAccessSendV2,
  handleAccessSendFileV2,
  handleDownloadSendFile,
} from './handlers/sends';
import { handleKnownDevice } from './handlers/devices';
import {
  handleCreateAuthRequest,
  handleGetAuthRequestResponse,
} from './handlers/auth-requests';
import { handlePublicDownloadAttachment } from './handlers/attachments';
import { handlePublicUploadAttachment } from './handlers/attachments';
import {
  handleAnonymousNotificationsHub,
  handleNotificationsHub,
  handleNotificationsNegotiate,
} from './handlers/notifications';
import { handlePublicUploadSendFile } from './handlers/sends';
import { jsonResponse } from './utils/response';
import type { Env } from './types';

type PublicRateLimiter = (category?: string, maxRequests?: number) => Promise<Response | null>;

export async function handlePublicRoute(
  request: Request,
  env: Env,
  path: string,
  method: string,
  enforcePublicRateLimit: PublicRateLimiter
): Promise<Response | null> {
  const publicAttachmentMatch = path.match(/^\/api\/attachments\/([a-f0-9-]+)\/([a-f0-9-]+)$/i);
  if (publicAttachmentMatch && method === 'GET') {
    return handlePublicDownloadAttachment(request, env, publicAttachmentMatch[1], publicAttachmentMatch[2]);
  }

  const publicAttachmentUploadMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)\/attachment\/([a-f0-9-]+)$/i);
  if (publicAttachmentUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadAttachment(request, env, publicAttachmentUploadMatch[1], publicAttachmentUploadMatch[2]);
  }

  const publicSendUploadMatch = path.match(/^\/api\/sends\/([^/]+)\/file\/([^/]+)\/?$/i);
  if (publicSendUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadSendFile(request, env, publicSendUploadMatch[1], publicSendUploadMatch[2]);
  }

  const sendAccessMatch = path.match(/^\/api\/sends\/access\/([^/]+)$/i);
  if (sendAccessMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSend(request, env, sendAccessMatch[1]);
  }

  if (path === '/api/sends/access' && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendV2(request, env);
  }

  const sendAccessFileV2Match = path.match(/^\/api\/sends\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileV2Match && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFileV2(request, env, sendAccessFileV2Match[1]);
  }

  const sendAccessFileMatch = path.match(/^\/api\/sends\/([^/]+)\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFile(request, env, sendAccessFileMatch[1], sendAccessFileMatch[2]);
  }

  const sendDownloadMatch = path.match(/^\/api\/sends\/([^/]+)\/([^/]+)\/?$/i);
  if (sendDownloadMatch && method === 'GET') {
    return handleDownloadSendFile(request, env, sendDownloadMatch[1], sendDownloadMatch[2]);
  }

  if ((path === '/api/auth-requests' || path === '/api/auth-requests/' || path === '/auth-requests' || path === '/auth-requests/') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleCreateAuthRequest(request, env);
  }

  const authRequestResponseMatch = path.match(/^\/(?:api\/)?auth-requests\/([a-f0-9-]+)\/response$/i);
  if (authRequestResponseMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleGetAuthRequestResponse(request, env, authRequestResponseMatch[1]);
  }

  if (path === '/api/devices/knowndevice' && method === 'GET') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return jsonResponse(false);
    return handleKnownDevice(request, env);
  }

  if (path === '/notifications/hub/negotiate' && method === 'POST') {
    return handleNotificationsNegotiate(request, env);
  }

  if (path === '/notifications/hub' && method === 'GET') {
    return handleNotificationsHub(request, env);
  }

  if (path === '/notifications/anonymous-hub' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleAnonymousNotificationsHub(request, env);
  }
  return null;
}
