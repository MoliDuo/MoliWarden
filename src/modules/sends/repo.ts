import type { Executor } from '../../platform/db';
import type { NewRow, Row } from '../../platform/db/schema';
import { SendType, type Send, type SendFile, type SendText } from './model';

// What clients encrypt (name, notes, the text or file details) is kept as
// JSON in `data`.

interface SendData {
  name: string;
  notes: string | null;
  text: SendText | null;
  file: SendFile | null;
}

function toSend(row: Row<'sends'>): Send {
  const data = row.data as unknown as SendData;
  const type = row.type === SendType.File ? SendType.File : SendType.Text;
  return {
    id: row.id,
    userId: row.user_id,
    type,
    name: data.name,
    notes: data.notes,
    key: row.key,
    text: type === SendType.Text ? (data.text ?? { text: null, hidden: false }) : null,
    file: type === SendType.File ? data.file : null,
    password: row.password_hash
      ? { hash: row.password_hash, salt: row.password_salt!, iterations: row.password_iterations ?? 1 }
      : null,
    maxAccessCount: row.max_access_count,
    accessCount: row.access_count,
    disabled: row.disabled,
    hideEmail: row.hide_email,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expirationDate: row.expiration_date,
    deletionDate: row.deletion_date,
  };
}

function toRow(send: Send): NewRow<'sends'> {
  const data: SendData = { name: send.name, notes: send.notes, text: send.text, file: send.file };
  return {
    id: send.id,
    user_id: send.userId,
    type: send.type,
    key: send.key,
    data: JSON.stringify(data),
    password_hash: send.password?.hash ?? null,
    password_salt: send.password?.salt ?? null,
    password_iterations: send.password?.iterations ?? null,
    max_access_count: send.maxAccessCount,
    access_count: send.accessCount,
    disabled: send.disabled,
    hide_email: send.hideEmail,
    created_at: send.createdAt,
    updated_at: send.updatedAt,
    expiration_date: send.expirationDate,
    deletion_date: send.deletionDate,
  };
}

export async function findSend(db: Executor, id: string): Promise<Send | null> {
  const row = await db.selectFrom('sends').selectAll().where('id', '=', id).executeTakeFirst();
  return row ? toSend(row) : null;
}

// Without a user: every Send on the server.
export async function listSends(db: Executor, userId: string | null, ids?: string[]): Promise<Send[]> {
  let query = db.selectFrom('sends').selectAll();
  if (userId) query = query.where('user_id', '=', userId);
  if (ids) query = query.where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))));
  const rows = await query.orderBy('updated_at', 'desc').execute();
  return rows.map(toSend);
}

// Access counts are left alone: recipients may open the Send meanwhile.
export async function saveSend(db: Executor, send: Send): Promise<void> {
  const { access_count: _count, ...row } = toRow(send);
  await db
    .insertInto('sends')
    .values(toRow(send))
    .onConflict((oc) => oc.column('id').doUpdateSet(row).where('sends.user_id', '=', send.userId))
    .execute();
}

export async function deleteSends(db: Executor, userId: string, ids: string[]): Promise<void> {
  if (!ids.length) return;
  await db
    .deleteFrom('sends')
    .where('user_id', '=', userId)
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
}

// Counts one access by a recipient, if the Send is still available then.
export async function countAccess(db: Executor, id: string, now: string): Promise<Send | null> {
  const row = await db
    .updateTable('sends')
    .set((eb) => ({ access_count: eb('access_count', '+', 1), updated_at: now }))
    .where('id', '=', id)
    .where('disabled', '=', false)
    .where((eb) =>
      eb.and([
        eb.or([eb('max_access_count', 'is', null), eb('access_count', '<', eb.ref('max_access_count'))]),
        eb.or([eb('expiration_date', 'is', null), eb('expiration_date', '>', now)]),
        eb('deletion_date', '>', now),
      ]),
    )
    .returningAll()
    .executeTakeFirst();
  return row ? toSend(row) : null;
}
