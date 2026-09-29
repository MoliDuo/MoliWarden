import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';
import { readCipherData, writeCipherData, type Cipher, type CipherType } from './model';

// Ciphers, and how each user keeps organization ciphers: their folder,
// favorite and archive state live in cipher_user_state, while a personal
// cipher keeps them on its own row.

export interface UserState {
  folderId: string | null;
  favorite: boolean;
  archivedAt: string | null;
}

function toCipher(row: Row<'ciphers'>): Cipher {
  return {
    id: row.id,
    userId: row.user_id,
    organizationId: row.organization_id,
    type: Number(row.type) as CipherType,
    name: row.name ?? '',
    notes: row.notes,
    key: row.key,
    reprompt: Number(row.reprompt) || 0,
    data: readCipherData(row.data),
    folderId: row.folder_id,
    favorite: !!row.favorite,
    archivedAt: row.archived_at,
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

// The user's folder, favorite and archive state of the organization ciphers given.
export async function listUserStates(db: Executor, userId: string, cipherIds: string[]): Promise<Map<string, UserState>> {
  if (!cipherIds.length) return new Map();
  const rows = await db
    .selectFrom('cipher_user_state')
    .selectAll()
    .where('user_id', '=', userId)
    .where((eb) => eb('cipher_id', '=', eb.fn.any(eb.val(cipherIds))))
    .execute();
  return new Map(
    rows.map((row) => [row.cipher_id, { folderId: row.folder_id, favorite: !!row.favorite, archivedAt: row.archived_at }]),
  );
}

// The one way ciphers are written: created, or updated when the owner is
// unchanged. `movedFrom` lets a personal cipher of that user become an
// organization cipher. Returns the ids written; a cipher whose owner
// changed in the meantime is left alone and missing from them.
export async function saveCiphers(db: Executor, ciphers: Cipher[], options: { movedFrom?: string } = {}): Promise<Set<string>> {
  const written = new Set<string>();
  for (let i = 0; i < ciphers.length; i += 500) {
    const rows = await db
      .insertInto('ciphers')
      .values(
        ciphers.slice(i, i + 500).map((cipher) => {
          // Per-user state of organization ciphers is kept elsewhere.
          const personal = !cipher.organizationId;
          return {
            id: cipher.id,
            user_id: personal ? cipher.userId : null,
            organization_id: cipher.organizationId,
            type: cipher.type,
            folder_id: personal ? cipher.folderId : null,
            name: cipher.name,
            notes: cipher.notes,
            favorite: personal && cipher.favorite ? 1 : 0,
            data: writeCipherData(cipher.data),
            reprompt: cipher.reprompt,
            key: cipher.key,
            created_at: cipher.createdAt,
            updated_at: cipher.updatedAt,
            archived_at: personal ? cipher.archivedAt : null,
            deleted_at: cipher.deletedAt,
          };
        }),
      )
      .onConflict((oc) =>
        oc
          .column('id')
          .doUpdateSet((eb) => ({
            user_id: eb.ref('excluded.user_id'),
            organization_id: eb.ref('excluded.organization_id'),
            type: eb.ref('excluded.type'),
            folder_id: eb.ref('excluded.folder_id'),
            name: eb.ref('excluded.name'),
            notes: eb.ref('excluded.notes'),
            favorite: eb.ref('excluded.favorite'),
            data: eb.ref('excluded.data'),
            reprompt: eb.ref('excluded.reprompt'),
            key: eb.ref('excluded.key'),
            updated_at: eb.ref('excluded.updated_at'),
            archived_at: eb.ref('excluded.archived_at'),
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

export async function saveUserStates(db: Executor, userId: string, states: Array<UserState & { cipherId: string }>): Promise<void> {
  for (let i = 0; i < states.length; i += 1000) {
    await db
      .insertInto('cipher_user_state')
      .values(
        states.slice(i, i + 1000).map((state) => ({
          cipher_id: state.cipherId,
          user_id: userId,
          folder_id: state.folderId,
          favorite: state.favorite ? 1 : 0,
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
}

// Attachment rows go with them (the blobs are the caller's).
export async function deleteCiphers(db: Executor, ids: string[]): Promise<void> {
  if (!ids.length) return;
  await db
    .deleteFrom('ciphers')
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
}

// Takes deleted folders out of the user's ciphers.
export async function unsetFolders(db: Executor, userId: string, folderIds: string[]): Promise<void> {
  if (!folderIds.length) return;
  await db
    .updateTable('ciphers')
    .set({ folder_id: null })
    .where('user_id', '=', userId)
    .where((eb) => eb('folder_id', '=', eb.fn.any(eb.val(folderIds))))
    .execute();
  await db
    .updateTable('cipher_user_state')
    .set({ folder_id: null })
    .where('user_id', '=', userId)
    .where((eb) => eb('folder_id', '=', eb.fn.any(eb.val(folderIds))))
    .execute();
}
