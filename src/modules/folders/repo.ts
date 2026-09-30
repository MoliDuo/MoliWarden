import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';

// Folders sort a user's own view of the vault; each is the user's alone.

export interface Folder {
  id: string;
  userId: string;
  // Encrypted.
  name: string;
  createdAt: string;
  updatedAt: string;
}

function toFolder(row: Row<'folders'>): Folder {
  return { id: row.id, userId: row.user_id, name: row.name, createdAt: row.created_at, updatedAt: row.updated_at };
}

export async function listFolders(db: Executor, userId: string): Promise<Folder[]> {
  const rows = await db.selectFrom('folders').selectAll().where('user_id', '=', userId).orderBy('created_at').execute();
  return rows.map(toFolder);
}

export async function findFolder(db: Executor, userId: string, id: string): Promise<Folder | null> {
  const row = await db.selectFrom('folders').selectAll().where('id', '=', id).where('user_id', '=', userId).executeTakeFirst();
  return row ? toFolder(row) : null;
}

export async function saveFolders(db: Executor, folders: Folder[]): Promise<void> {
  for (let i = 0; i < folders.length; i += 1000) {
    await db
      .insertInto('folders')
      .values(
        folders.slice(i, i + 1000).map((folder) => ({
          id: folder.id,
          user_id: folder.userId,
          name: folder.name,
          created_at: folder.createdAt,
          updated_at: folder.updatedAt,
        })),
      )
      .onConflict((oc) =>
        oc
          .column('id')
          .doUpdateSet((eb) => ({ name: eb.ref('excluded.name'), updated_at: eb.ref('excluded.updated_at') }))
          .whereRef('folders.user_id', '=', 'excluded.user_id'),
      )
      .execute();
  }
}

// Returns the ids deleted.
export async function deleteFolders(db: Executor, userId: string, ids: string[]): Promise<string[]> {
  if (!ids.length) return [];
  const rows = await db
    .deleteFrom('folders')
    .where('user_id', '=', userId)
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .returning('id')
    .execute();
  return rows.map((row) => row.id);
}
