import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { clientIp } from '../../http/client';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import {
  clearAuditLogs,
  findAuditRetention,
  insertAuditLog,
  listAuditLogs,
  pruneAuditLogs,
  saveAuditRetention,
  type AuditRetention,
} from './repo';
import type { AuditLogQuery } from './schemas';

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
    await insertAuditLog(db, {
      id: randomUUID(),
      actorUserId: event.actorUserId ?? null,
      action: event.action,
      category: event.category,
      level: event.level ?? 'info',
      targetType: event.targetType ?? null,
      targetId: event.targetId ?? null,
      metadata: sanitize(event.metadata ?? {}),
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Audit log write failed:', error);
  }
}

// What admins do with the log.

const DEFAULT_RETENTION: AuditRetention = { retentionDays: 90, maxEntries: null };

function adminAudit(deps: Deps, caller: Caller, action: string, metadata: Record<string, unknown>) {
  return recordAudit(deps.db, {
    actorUserId: caller.user.id,
    action,
    category: 'system',
    targetType: 'auditLog',
    metadata: { ...metadata, ...requestMetadata(caller.request) },
  });
}

export async function auditLogs(deps: Deps, query: AuditLogQuery) {
  const { limit, offset, q, ...filter } = query;
  const { entries, total } = await listAuditLogs(deps.db, { ...filter, search: q }, { limit, offset });
  const hasMore = offset + entries.length < total;
  return {
    data: entries.map((entry) => ({ ...entry, object: 'auditLog' })),
    total,
    limit,
    offset,
    hasMore,
    object: 'list',
    continuationToken: hasMore ? String(offset + entries.length) : null,
  };
}

export async function auditRetention(deps: Deps): Promise<AuditRetention> {
  return (await findAuditRetention(deps.db)) ?? DEFAULT_RETENTION;
}

export async function setAuditRetention(deps: Deps, caller: Caller, retention: AuditRetention): Promise<AuditRetention> {
  await saveAuditRetention(deps.db, retention);
  await pruneAuditLogs(deps.db, retention);
  await adminAudit(deps, caller, 'admin.audit.settings.update', { ...retention });
  return retention;
}

// The entry recording the clearing is the first of the new log.
export async function clearAuditLog(deps: Deps, caller: Caller): Promise<number> {
  const deleted = await clearAuditLogs(deps.db);
  await adminAudit(deps, caller, 'admin.audit.clear', { deleted });
  return deleted;
}

// Run by the cron job.
export async function pruneAuditLog(deps: Deps, now: Date): Promise<number> {
  return pruneAuditLogs(deps.db, await auditRetention(deps), now.getTime());
}
