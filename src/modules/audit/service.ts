import { randomUUID } from 'node:crypto';
import { clientIp } from '../../http/client';
import type { Executor } from '../../platform/db';

// The audit log records security-relevant events for admins. Entries carry
// a whitelisted set of metadata keys; secrets never reach the log.

export type AuditCategory = 'auth' | 'security' | 'device' | 'data' | 'system';
export type AuditLevel = 'info' | 'warn' | 'error' | 'security';

export interface AuditEvent {
  actorUserId?: string | null;
  action: string;
  category: AuditCategory;
  level?: AuditLevel;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown>;
}

const ALLOWED_METADATA_KEYS = new Set([
  'method', 'path', 'ip', 'userAgent', 'email', 'targetEmail', 'grantType', 'webSession',
  'deviceIdentifier', 'deviceType', 'reason', 'status', 'verifyDevices', 'changed', 'removed',
  'updated', 'deleted', 'removedTrusted', 'removedSessions', 'removedDevices', 'requested',
  'count', 'requestedCount', 'type', 'folderId', 'cipherId', 'size', 'users', 'ciphers',
  'attachments', 'skippedAttachments', 'skippedReason', 'replaceExisting', 'provider',
  'prfStatus', 'fileName', 'fileBytes', 'bytes', 'compressedBytes', 'includesAttachments',
  'destinationName', 'destinationId', 'destinationType', 'destinationCount',
  'scheduledDestinationCount', 'retentionDays', 'maxEntries', 'remotePath', 'trigger',
  'prunedFileCount', 'pruneError', 'uploadVerificationAttempts', 'error', 'expiresInHours',
  'checksumMismatchAccepted',
]);
const SENSITIVE_KEY = /(token|secret|password|key|hash|code|private)/i;
const MAX_METADATA_BYTES = 2048;

function sanitize(metadata: Record<string, unknown>): string {
  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (!ALLOWED_METADATA_KEYS.has(key) || SENSITIVE_KEY.test(key)) continue;
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) clean[key] = value.length;
    else if (typeof value !== 'object') clean[key] = value;
  }
  const json = JSON.stringify(clean);
  return Buffer.byteLength(json) > MAX_METADATA_BYTES ? JSON.stringify({ truncated: true }) : json;
}

// Where a request came from, for the metadata of the events it causes.
export function requestMetadata(request: Request): Record<string, unknown> {
  return {
    method: request.method,
    path: new URL(request.url).pathname,
    ip: clientIp(request),
    userAgent: request.headers.get('User-Agent'),
  };
}

// Writes an entry. A failure is logged and never fails the request.
export async function recordAudit(db: Executor, event: AuditEvent): Promise<void> {
  try {
    await db
      .insertInto('audit_logs')
      .values({
        id: randomUUID(),
        actor_user_id: event.actorUserId ?? null,
        action: event.action,
        category: event.category,
        level: event.level ?? 'info',
        target_type: event.targetType ?? null,
        target_id: event.targetId ?? null,
        metadata: sanitize(event.metadata ?? {}),
        created_at: new Date().toISOString(),
      })
      .execute();
  } catch (error) {
    console.error('Audit log write failed:', error);
  }
}
