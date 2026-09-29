import { recordAudit, requestMetadata, type AuditEvent } from '../modules/audit/service';
import { createDb } from '../platform/db';
import type { PgD1Database } from '../platform/pg-d1';
import type { Env } from '../types';

// The legacy backup handlers' way to the audit log (src/modules/audit).

export const auditRequestMetadata = requestMetadata;

export async function writeAuditEvent(env: Env, event: AuditEvent): Promise<void> {
  await recordAudit(createDb((env.DB as unknown as PgD1Database).pool), event);
}
