import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import type { Deps } from '../../main/deps';
import { listFolders, saveFolders, type Folder } from '../folders/repo';
import { PushType } from '../push/service';
import { commit } from '../sync/changes';
import { saveCiphers } from './repo';
import type { ImportInput } from './schemas';
import { newCipher } from './writes';

// Imports into the personal vault, all or nothing. Large imports arrive in
// several requests: later ones may put items into the folders an earlier
// one created, by id.
export async function importCiphers(deps: Deps, caller: Caller, input: ImportInput) {
  const userId = caller.user.id;
  const date = new Date().toISOString();
  const folders: Folder[] = input.folders.map(({ name }) => ({ id: randomUUID(), userId, name, createdAt: date, updatedAt: date }));
  const existing = new Set((await listFolders(deps.db, userId)).map((folder) => folder.id));

  const folderOf = new Map<number, string>();
  for (const { key, value } of input.folderRelationships) {
    const folder = folders[value];
    if (folder) folderOf.set(key, folder.id);
  }
  const ciphers = input.ciphers.map((cipherInput, index) => {
    const folderId = folderOf.get(index) ?? (cipherInput.folderId && existing.has(cipherInput.folderId) ? cipherInput.folderId : null);
    return newCipher(cipherInput, { userId, organizationId: null }, date, folderId);
  });

  await commit(deps, caller, date, { orgIds: [], push: { type: PushType.SyncVault } }, async (tx) => {
    await saveFolders(tx, folders);
    await saveCiphers(tx, ciphers);
  });
  return {
    object: 'import-result',
    cipherMap: ciphers.map((cipher, index) => ({ index, sourceId: input.ciphers[index].id ?? null, id: cipher.id })),
  };
}
