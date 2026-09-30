import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';
import { readCipherData, writeCipherData, type Cipher, type CipherType } from './model';

// Ciphers, and how each user keeps them: folder, favorite and archive
// state live in cipher_user_state, for personal and organization ciphers
// alike. A state row exists only while it differs from the default.

export interface UserState {
  folderId: string | null;
  favorite: boolean;
  archivedAt: string | null;
}

// What clients encrypt is kept in `data`: name, notes and the type's parts.
function toCipher(row: Row<'ciphers'>): Cipher {
  const { name, notes, ...data } = row.data;
  return {
    id: row.id,
    userId: row.user_id,
    organizationId: row.organization_id,
    type: row.type as CipherType,
    name: typeof name === 'string' ? name : '',
    notes: typeof notes === 'string' ? notes : null,
    key: row.key,
    reprompt: row.reprompt,
    data: readCipherData(data),
    folderId: null,
    favorite: false,
    archivedAt: null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at,
  };
}

const byRevision = (a: Cipher, b: Cipher) => b.updatedAt.localeCompare(a.updatedAt);

export async function findCiphers(db: Executor, ids: string[]): Promise<Cipher[]> {
  if (!ids.length) return [];
  const rows = await db
    .selectFrom('ciphers')
    .selectAll()
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
  return rows.map(toCipher).sort(byRevision);
}

// The user's own ciphers, all ciphers of the organizations given, and the
// organization ciphers in the collections given.
export async function listCiphers(
  db: Executor,
  scope: { userId?: string; orgIds?: string[]; collectionIds?: string[] },
): Promise<Cipher[]> {
  const { userId, orgIds = [], collectionIds = [] } = scope;
  if (!userId && !orgIds.length && !collectionIds.length) return [];
  const rows = await db
    .selectFrom('ciphers as c')
    .selectAll()
    .where((eb) =>
      eb.or([
        ...(userId ? [eb('c.user_id', '=', userId)] : []),
        ...(orgIds.length ? [eb('c.organization_id', '=', eb.fn.any(eb.val(orgIds)))] : []),
        ...(collectionIds.length
          ? [
              eb.exists(
                eb
                  .selectFrom('cipher_collections as cc')
                  .select('cc.cipher_id')
                  .whereRef('cc.cipher_id', '=', 'c.id')
                  .where('cc.collection_id', '=', eb.fn.any(eb.val(collectionIds))),
              ),
            ]
          : []),
      ]),
    )
    .orderBy('c.updated_at', 'desc')
    .execute();
  return rows.map(toCipher);
}

// The ciphers a user or an organization owns, by id only.
export async function listCipherIds(db: Executor, owner: { userId: string } | { orgId: string }): Promise<string[]> {
  const query = db.selectFrom('ciphers').select('id');
  const rows = await ('orgId' in owner
    ? query.where('organization_id', '=', owner.orgId)
    : query.where('user_id', '=', owner.userId).where('organization_id', 'is', null)
  ).execute();
  return rows.map((row) => row.id);
}

// The user's state of the ciphers given, where it is not the default.
export async function listUserStates(db: Executor, userId: string, cipherIds: string[]): Promise<Map<string, UserState>> {
  if (!cipherIds.length) return new Map();
  const rows = await db
    .selectFrom('cipher_user_state')
    .selectAll()
    .where('user_id', '=', userId)
    .where((eb) => eb('cipher_id', '=', eb.fn.any(eb.val(cipherIds))))
    .execute();
  return new Map(
    rows.map((row) => [row.cipher_id, { folderId: row.folder_id, favorite: row.favorite, archivedAt: row.archived_at }]),
  );
}

// The one way ciphers are written: created, or updated when the owner is
// unchanged. `movedFrom` lets a personal cipher of that user become an
// organization cipher. Returns the ids written; a cipher whose owner
// changed in the meantime is left alone and missing from them. The user
// state the ciphers carry is not written (see saveUserStates).
export async function saveCiphers(db: Executor, ciphers: Cipher[], options: { movedFrom?: string } = {}): Promise<Set<string>> {
  const written = new Set<string>();
  for (let i = 0; i < ciphers.length; i += 500) {
    const rows = await db
      .insertInto('ciphers')
      .values(
        ciphers.slice(i, i + 500).map((cipher) => ({
          id: cipher.id,
          user_id: cipher.organizationId ? null : cipher.userId,
          organization_id: cipher.organizationId,
          type: cipher.type,
          key: cipher.key,
          reprompt: cipher.reprompt,
          data: writeCipherData({ name: cipher.name, notes: cipher.notes }, cipher.data),
          created_at: cipher.createdAt,
          updated_at: cipher.updatedAt,
          deleted_at: cipher.deletedAt,
        })),
      )
      .onConflict((oc) =>
        oc
          .column('id')
          .doUpdateSet((eb) => ({
            user_id: eb.ref('excluded.user_id'),
            organization_id: eb.ref('excluded.organization_id'),
            type: eb.ref('excluded.type'),
            key: eb.ref('excluded.key'),
            reprompt: eb.ref('excluded.reprompt'),
            data: eb.ref('excluded.data'),
            updated_at: eb.ref('excluded.updated_at'),
            deleted_at: eb.ref('excluded.deleted_at'),
          }))
          .where(
            options.movedFrom
              ? sql<boolean>`(ciphers.organization_id IS NOT DISTINCT FROM excluded.organization_id AND ciphers.user_id IS NOT DISTINCT FROM excluded.user_id)
                  OR (ciphers.organization_id IS NULL AND ciphers.user_id = ${options.movedFrom})`
              : sql<boolean>`ciphers.organization_id IS NOT DISTINCT FROM excluded.organization_id AND ciphers.user_id IS NOT DISTINCT FROM excluded.user_id`,
          ),
      )
      .returning('id')
      .execute();
    for (const row of rows) written.add(row.id);
  }
  return written;
}

const isDefault = (state: UserState) => !state.folderId && !state.favorite && !state.archivedAt;

export async function saveUserStates(db: Executor, userId: string, states: Array<UserState & { cipherId: string }>): Promise<void> {
  const kept = states.filter((state) => !isDefault(state));
  const cleared = states.filter(isDefault).map((state) => state.cipherId);
  for (let i = 0; i < kept.length; i += 1000) {
    await db
      .insertInto('cipher_user_state')
      .values(
        kept.slice(i, i + 1000).map((state) => ({
          cipher_id: state.cipherId,
          user_id: userId,
          folder_id: state.folderId,
          favorite: state.favorite,
          archived_at: state.archivedAt,
        })),
      )
      .onConflict((oc) =>
        oc.columns(['cipher_id', 'user_id']).doUpdateSet((eb) => ({
          folder_id: eb.ref('excluded.folder_id'),
          favorite: eb.ref('excluded.favorite'),
          archived_at: eb.ref('excluded.archived_at'),
        })),
      )
      .execute();
  }
  if (cleared.length) {
    await db
      .deleteFrom('cipher_user_state')
      .where('user_id', '=', userId)
      .where((eb) => eb('cipher_id', '=', eb.fn.any(eb.val(cleared))))
      .execute();
  }
}

// Attachment rows go with them (the blobs are the caller's).
export async function deleteCiphers(db: Executor, ids: string[]): Promise<void> {
  if (!ids.length) return;
  await db
    .deleteFrom('ciphers')
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
}

// Marks a cipher changed, when something that belongs to it (an attachment)
// did.
export async function touchCiphers(db: Executor, ids: string[], date: string): Promise<void> {
  if (!ids.length) return;
  await db
    .updateTable('ciphers')
    .set({ updated_at: date })
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
}
