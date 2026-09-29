import type { Executor } from '../../platform/db';

// Login with a device: a new device asks, a signed-in device approves and
// hands over the vault key, and the new device then signs in once with the
// request's access code.

export const AUTH_REQUEST_TTL_MS = 15 * 60 * 1000;
const LOGIN_WITH_DEVICE = 0;

export interface ApprovedLoginRequest {
  id: string;
  accessCode: string;
  key: string;
}

// An approved request of the user's that has not been used to sign in yet.
export async function findApprovedLoginRequest(
  db: Executor,
  id: string,
  userId: string,
  now = Date.now(),
): Promise<ApprovedLoginRequest | null> {
  const row = await db
    .selectFrom('auth_requests')
    .select(['id', 'access_code', 'key'])
    .where('id', '=', id)
    .where('user_id', '=', userId)
    .where('type', '=', LOGIN_WITH_DEVICE)
    .where('approved', '=', 1)
    .where('response_date', 'is not', null)
    .where('authentication_date', 'is', null)
    .where('creation_date', '>', new Date(now - AUTH_REQUEST_TTL_MS).toISOString())
    .executeTakeFirst();
  return row?.key ? { id: row.id, accessCode: row.access_code, key: row.key } : null;
}

// Uses the request up. False when a concurrent login used it first.
export async function markAuthRequestUsed(db: Executor, id: string): Promise<boolean> {
  const result = await db
    .updateTable('auth_requests')
    .set({ authentication_date: new Date().toISOString() })
    .where('id', '=', id)
    .where('authentication_date', 'is', null)
    .executeTakeFirst();
  return result.numUpdatedRows > 0n;
}
