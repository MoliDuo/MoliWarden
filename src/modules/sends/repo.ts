import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';
import type { Send } from '../../types';

export function toSend(row: Row<'sends'>): Send {
  return {
    id: row.id,
    userId: row.user_id,
    type: row.type,
    name: row.name,
    notes: row.notes,
    data: row.data,
    key: row.key,
    passwordHash: row.password_hash,
    passwordSalt: row.password_salt,
    passwordIterations: row.password_iterations,
    authType: row.auth_type,
    emails: row.emails,
    maxAccessCount: row.max_access_count,
    accessCount: row.access_count,
    disabled: !!row.disabled,
    hideEmail: row.hide_email === null ? null : !!row.hide_email,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expirationDate: row.expiration_date,
    deletionDate: row.deletion_date,
  };
}

export async function listSends(db: Executor, userId: string): Promise<Send[]> {
  const rows = await db.selectFrom('sends').selectAll().where('user_id', '=', userId).orderBy('updated_at', 'desc').execute();
  return rows.map(toSend);
}
