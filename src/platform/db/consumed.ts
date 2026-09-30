import type { Executor } from './index';

// Marks something that may be used once, such as a download token or a
// TOTP code, as used. False when it was used before. The mark is kept until
// `expiresAt`, when the thing is no longer accepted anyway.
export async function consumeOnce(db: Executor, key: string, expiresAt: Date): Promise<boolean> {
  const row = await db
    .insertInto('consumed_tokens')
    .values({ key, expires_at: expiresAt.toISOString() })
    .onConflict((oc) => oc.column('key').doNothing())
    .returning('key')
    .executeTakeFirst();
  return !!row;
}

export async function deleteExpiredConsumedTokens(db: Executor, now: Date): Promise<number> {
  const result = await db.deleteFrom('consumed_tokens').where('expires_at', '<', now.toISOString()).executeTakeFirst();
  return Number(result.numDeletedRows);
}
