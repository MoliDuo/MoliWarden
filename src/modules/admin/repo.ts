import type { Executor } from '../../platform/db';
import type { User } from '../../types';
import { toUser } from '../accounts/rows';

// Accounts and invites as admins manage them.

export interface Invite {
  code: string;
  createdBy: string;
  usedBy: string | null;
  status: 'active' | 'used';
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

export async function listUsers(db: Executor): Promise<User[]> {
  const rows = await db.selectFrom('users').selectAll().orderBy('created_at').orderBy('id').execute();
  return rows.map(toUser);
}

export async function setUserStatus(db: Executor, id: string, status: User['status']): Promise<void> {
  await db.updateTable('users').set({ status, updated_at: new Date().toISOString() }).where('id', '=', id).execute();
}

// Everything of the user goes with it: ciphers, folders, Sends, devices,
// sessions and memberships.
export async function deleteUser(db: Executor, id: string): Promise<void> {
  await db.deleteFrom('users').where('id', '=', id).execute();
}

export async function insertInvite(db: Executor, invite: Invite): Promise<void> {
  await db
    .insertInto('invites')
    .values({
      code: invite.code,
      created_by: invite.createdBy,
      used_by: invite.usedBy,
      status: invite.status,
      expires_at: invite.expiresAt,
      created_at: invite.createdAt,
      updated_at: invite.updatedAt,
    })
    .execute();
}

// Newest first; without `all`, only the invites that can still be used.
export async function listInvites(db: Executor, all: boolean, now = new Date().toISOString()): Promise<Invite[]> {
  let query = db.selectFrom('invites').selectAll().orderBy('created_at', 'desc');
  if (!all) query = query.where('status', '=', 'active').where('expires_at', '>', now);
  const rows = await query.execute();
  return rows.map((row) => ({
    code: row.code,
    createdBy: row.created_by,
    usedBy: row.used_by,
    status: row.status === 'active' ? 'active' : 'used',
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

export async function deleteInvite(db: Executor, code: string): Promise<boolean> {
  const result = await db.deleteFrom('invites').where('code', '=', code).executeTakeFirst();
  return Number(result.numDeletedRows) > 0;
}

// Used or expired invites, or with `all` every invite.
export async function deleteInvites(db: Executor, all: boolean, now = new Date().toISOString()): Promise<number> {
  let query = db.deleteFrom('invites');
  if (!all) query = query.where((eb) => eb.or([eb('status', '!=', 'active'), eb('expires_at', '<=', now)]));
  const result = await query.executeTakeFirst();
  return Number(result.numDeletedRows);
}
