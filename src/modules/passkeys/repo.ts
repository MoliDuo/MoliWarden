import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';
import type { AccountPasskeyChallengeScope, AccountPasskeyCredential } from '../../types';

export type Purpose = AccountPasskeyCredential['purpose'];

// A WebAuthn credential: a login passkey, or a security key for two-step
// login, which also has a KeyN slot number.
export interface Passkey extends AccountPasskeyCredential {
  slot: number | null;
}

function toPasskey(row: Row<'webauthn_credentials'>): Passkey {
  return {
    id: row.id,
    userId: row.user_id,
    purpose: row.purpose === 'twoFactor' ? 'twoFactor' : 'login',
    name: row.name,
    publicKey: row.public_key,
    credentialId: row.credential_id,
    counter: row.counter,
    type: row.type,
    aaGuid: row.aa_guid,
    transports: row.transports,
    encryptedUserKey: row.encrypted_user_key,
    encryptedPublicKey: row.encrypted_public_key,
    encryptedPrivateKey: row.encrypted_private_key,
    supportsPrf: row.supports_prf,
    slot: row.slot,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function listPasskeys(db: Executor, userId: string, purpose: Purpose): Promise<Passkey[]> {
  const rows = await db
    .selectFrom('webauthn_credentials')
    .selectAll()
    .where('user_id', '=', userId)
    .where('purpose', '=', purpose)
    .orderBy('created_at')
    .orderBy('id')
    .execute();
  return rows.map(toPasskey);
}

export async function findPasskeyByCredentialId(db: Executor, credentialId: string): Promise<Passkey | null> {
  const row = await db.selectFrom('webauthn_credentials').selectAll().where('credential_id', '=', credentialId).executeTakeFirst();
  return row ? toPasskey(row) : null;
}

export async function insertPasskey(db: Executor, passkey: Passkey): Promise<void> {
  await db
    .insertInto('webauthn_credentials')
    .values({
      id: passkey.id,
      user_id: passkey.userId,
      purpose: passkey.purpose,
      name: passkey.name,
      public_key: passkey.publicKey,
      credential_id: passkey.credentialId,
      counter: passkey.counter,
      type: passkey.type,
      aa_guid: passkey.aaGuid,
      transports: passkey.transports,
      encrypted_user_key: passkey.encryptedUserKey,
      encrypted_public_key: passkey.encryptedPublicKey,
      encrypted_private_key: passkey.encryptedPrivateKey,
      supports_prf: passkey.supportsPrf,
      slot: passkey.slot,
      created_at: passkey.createdAt,
      updated_at: passkey.updatedAt,
    })
    .execute();
}

export async function setPasskeySlot(db: Executor, id: string, slot: number): Promise<void> {
  await db.updateTable('webauthn_credentials').set({ slot }).where('id', '=', id).execute();
}

export async function updatePasskeyCounter(db: Executor, id: string, counter: number, now: string): Promise<void> {
  await db.updateTable('webauthn_credentials').set({ counter, updated_at: now }).where('id', '=', id).execute();
}

export async function updatePasskeyKeys(
  db: Executor,
  id: string,
  keys: { encryptedUserKey: string; encryptedPublicKey: string; encryptedPrivateKey: string },
  now: string,
): Promise<void> {
  await db
    .updateTable('webauthn_credentials')
    .set({
      encrypted_user_key: keys.encryptedUserKey,
      encrypted_public_key: keys.encryptedPublicKey,
      encrypted_private_key: keys.encryptedPrivateKey,
      supports_prf: true,
      updated_at: now,
    })
    .where('id', '=', id)
    .execute();
}

export async function deletePasskey(db: Executor, userId: string, purpose: Purpose, id: string): Promise<boolean> {
  const result = await db
    .deleteFrom('webauthn_credentials')
    .where('user_id', '=', userId)
    .where('purpose', '=', purpose)
    .where('id', '=', id)
    .executeTakeFirst();
  return result.numDeletedRows > 0n;
}

export async function deletePasskeys(db: Executor, userId: string, purpose: Purpose): Promise<void> {
  await db.deleteFrom('webauthn_credentials').where('user_id', '=', userId).where('purpose', '=', purpose).execute();
}

// Challenges are kept (hashed) until answered once, so a signed response
// cannot be replayed.

export async function saveChallenge(
  db: Executor,
  challengeHash: Buffer,
  scope: AccountPasskeyChallengeScope,
  userId: string | null,
  expiresAt: Date,
): Promise<void> {
  await db
    .insertInto('webauthn_challenges')
    .values({ challenge_hash: challengeHash, scope, user_id: userId, expires_at: expiresAt.toISOString(), used_at: null })
    .execute();
}

// Marks the challenge answered. False when it is unknown, expired, for
// another scope or user, or was answered before.
export async function consumeChallenge(
  db: Executor,
  challengeHash: Buffer,
  scope: AccountPasskeyChallengeScope,
  userId: string | null,
): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .updateTable('webauthn_challenges')
    .set({ used_at: now })
    .where('challenge_hash', '=', challengeHash)
    .where('scope', '=', scope)
    .where((eb) => (userId === null ? eb('user_id', 'is', null) : eb('user_id', '=', userId)))
    .where('used_at', 'is', null)
    .where('expires_at', '>=', now)
    .executeTakeFirst();
  return result.numUpdatedRows > 0n;
}

export async function deleteExpiredChallenges(db: Executor, now: Date): Promise<number> {
  const result = await db.deleteFrom('webauthn_challenges').where('expires_at', '<', now.toISOString()).executeTakeFirst();
  return Number(result.numDeletedRows);
}
