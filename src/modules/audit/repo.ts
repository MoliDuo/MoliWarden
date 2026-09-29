import { sql } from 'kysely';
import type { Executor } from '../../platform/db';

// Audit log entries, and how long they are kept (in the config table).

export interface AuditLogRow {
  id: string;
  actorUserId: string | null;
  action: string;
  category: string;
  level: string;
  targetType: string | null;
  targetId: string | null;
  metadata: string | null;
  createdAt: string;
}

export interface AuditLogEntry extends AuditLogRow {
  actorEmail: string | null;
  targetUserEmail: string | null;
}

export interface AuditLogFilter {
  category?: string;
  level?: string;
  // Matched against the action, the ids and the emails of actor and target.
  search?: string;
  from?: string;
  to?: string;
}

// Either limit applies, never both; neither keeps everything.
export interface AuditRetention {
  retentionDays: number | null;
  maxEntries: number | null;
}

const RETENTION_KEY = 'audit.logs.settings.v1';

export async function insertAuditLog(db: Executor, entry: AuditLogRow): Promise<void> {
  await db
    .insertInto('audit_logs')
    .values({
      id: entry.id,
      actor_user_id: entry.actorUserId,
      action: entry.action,
      category: entry.category,
      level: entry.level,
      target_type: entry.targetType,
      target_id: entry.targetId,
      metadata: entry.metadata,
      created_at: entry.createdAt,
    })
    .execute();
}

function filtered(db: Executor, filter: AuditLogFilter) {
  let query = db
    .selectFrom('audit_logs as l')
    .leftJoin('users as actor', 'actor.id', 'l.actor_user_id')
    .leftJoin('users as target', (join) =>
      join.onRef('target.id', '=', 'l.target_id').on('l.target_type', '=', 'user'),
    );
  if (filter.from) query = query.where('l.created_at', '>=', filter.from);
  if (filter.to) query = query.where('l.created_at', '<=', filter.to);
  if (filter.category) query = query.where('l.category', '=', filter.category);
  if (filter.level) query = query.where('l.level', '=', filter.level);
  if (filter.search) {
    const like = `%${filter.search.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    query = query.where((eb) =>
      eb.or(
        [sql.ref('l.action'), sql.ref('l.actor_user_id'), sql.ref('l.target_type'), sql.ref('l.target_id'), sql.ref('actor.email'), sql.ref('target.email')].map(
          (column) => eb(sql`lower(coalesce(${column}, ''))`, 'like', like),
        ),
      ),
    );
  }
  return query;
}

// Newest first.
export async function listAuditLogs(
  db: Executor,
  filter: AuditLogFilter,
  page: { limit: number; offset: number },
): Promise<{ entries: AuditLogEntry[]; total: number }> {
  const [rows, count] = await Promise.all([
    filtered(db, filter)
      .select([
        'l.id',
        'l.actor_user_id',
        'actor.email as actor_email',
        'l.action',
        'l.category',
        'l.level',
        'l.target_type',
        'l.target_id',
        'target.email as target_email',
        'l.metadata',
        'l.created_at',
      ])
      .orderBy('l.created_at', 'desc')
      .orderBy('l.id', 'desc')
      .limit(page.limit)
      .offset(page.offset)
      .execute(),
    filtered(db, filter)
      .select((eb) => eb.fn.countAll<string>().as('count'))
      .executeTakeFirstOrThrow(),
  ]);
  return {
    total: Number(count.count),
    entries: rows.map((row) => ({
      id: row.id,
      actorUserId: row.actor_user_id,
      actorEmail: row.actor_email,
      action: row.action,
      category: row.category,
      level: row.level,
      targetType: row.target_type,
      targetId: row.target_id,
      targetUserEmail: row.target_email,
      metadata: row.metadata,
      createdAt: row.created_at,
    })),
  };
}

export async function clearAuditLogs(db: Executor): Promise<number> {
  const result = await db.deleteFrom('audit_logs').executeTakeFirst();
  return Number(result.numDeletedRows);
}

export async function pruneAuditLogs(db: Executor, retention: AuditRetention, now = Date.now()): Promise<number> {
  if (retention.retentionDays) {
    const before = new Date(now - retention.retentionDays * 86_400_000).toISOString();
    const result = await db.deleteFrom('audit_logs').where('created_at', '<', before).executeTakeFirst();
    return Number(result.numDeletedRows);
  }
  if (retention.maxEntries) {
    const result = await db
      .deleteFrom('audit_logs')
      .where('id', 'in', (eb) =>
        eb.selectFrom('audit_logs').select('id').orderBy('created_at', 'desc').orderBy('id', 'desc').offset(retention.maxEntries!),
      )
      .executeTakeFirst();
    return Number(result.numDeletedRows);
  }
  return 0;
}

// The stored retention, or null when there is none (or it is unreadable).
export async function findAuditRetention(db: Executor): Promise<AuditRetention | null> {
  const row = await db.selectFrom('config').select('value').where('key', '=', RETENTION_KEY).executeTakeFirst();
  if (!row) return null;
  try {
    const value = JSON.parse(row.value) as Partial<AuditRetention>;
    return {
      retentionDays: typeof value.retentionDays === 'number' ? value.retentionDays : null,
      maxEntries: typeof value.maxEntries === 'number' ? value.maxEntries : null,
    };
  } catch {
    return null;
  }
}

export async function saveAuditRetention(db: Executor, retention: AuditRetention): Promise<void> {
  const value = JSON.stringify(retention);
  await db
    .insertInto('config')
    .values({ key: RETENTION_KEY, value })
    .onConflict((oc) => oc.column('key').doUpdateSet({ value }))
    .execute();
}
