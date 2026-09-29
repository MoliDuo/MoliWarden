import type { Caller } from '../../http/authenticate';
import { badRequest, forbidden } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { listAttachments, renameAttachments } from '../attachments/repo';
import { removeAttachmentFiles } from '../attachments/files';
import { recordAudit, requestMetadata } from '../audit/service';
import { FULL_ACCESS, loadOrgContext, orgCipherAccess } from '../organizations/access';
import { addCipherCollections } from '../organizations/repo';
import { PushType } from '../push/service';
import type { Cipher } from './model';
import { deleteCiphers, saveCiphers } from './repo';
import { cipherJson, listJson } from './responses';
import type { CipherBody } from './schemas';
import { canEdit, listViews, loadViews, requireView, viewJson, viewsJson, type CipherView } from './views';
import {
  applyUpdate,
  attachmentChanges,
  checkEncryptedFor,
  checkFolder,
  checkWritableCollections,
  commit,
  newCipher,
  pushItem,
  saveStates,
  saveView,
} from './writes';

// The vault items of one user: their own, and those of their organizations
// they can see. Moving items into organizations and the organization-wide
// operations are in sharing.ts.

const now = () => new Date().toISOString();

function audit(deps: Deps, caller: Caller, action: string, metadata: Record<string, unknown>, cipher?: Cipher) {
  return recordAudit(deps.db, {
    actorUserId: caller.user.id,
    action,
    category: 'data',
    level: 'security',
    targetType: 'cipher',
    targetId: cipher?.id ?? null,
    metadata: {
      ...(cipher ? { type: cipher.type, folderId: cipher.folderId } : {}),
      ...metadata,
      ...requestMetadata(caller.request),
    },
  });
}

function requireEditable(view: CipherView, message: string): void {
  if (!canEdit(view)) throw forbidden(message);
}

export async function ciphersJson(deps: Deps, caller: Caller, includeDeleted: boolean) {
  const views = await listViews(deps.db, await loadOrgContext(deps.db, caller.user.id));
  return listJson(await viewsJson(deps.db, includeDeleted ? views : views.filter((view) => !view.cipher.deletedAt)));
}

export async function cipherById(deps: Deps, caller: Caller, id: string) {
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  return viewJson(deps.db, await requireView(deps.db, ctx, id));
}

export async function createCipher(deps: Deps, caller: Caller, body: CipherBody) {
  const { cipher: input, collectionIds } = body;
  const userId = caller.user.id;
  checkEncryptedFor(input, userId);
  const orgId = input.organizationId ?? null;
  const ctx = await loadOrgContext(deps.db, userId);
  if (orgId) await checkWritableCollections(deps.db, ctx, orgId, collectionIds);
  await checkFolder(deps.db, userId, input.folderId);

  const date = now();
  const cipher = newCipher(input, { userId, organizationId: orgId }, date);
  await commit(
    deps,
    caller,
    date,
    { orgIds: [orgId], push: { type: PushType.SyncCipherCreate, item: pushItem(cipher, orgId ? collectionIds : null) } },
    async (tx) => {
      await saveView(tx, userId, cipher);
      await addCipherCollections(tx, orgId ? collectionIds.map((collectionId) => ({ cipherId: cipher.id, collectionId })) : []);
    },
  );
  const access = orgId ? orgCipherAccess(ctx, orgId, collectionIds) : FULL_ACCESS;
  return cipherJson(cipher, access ?? { ...FULL_ACCESS, collectionIds });
}

export async function updateCipher(deps: Deps, caller: Caller, id: string, body: CipherBody) {
  const { cipher: input } = body;
  const userId = caller.user.id;
  checkEncryptedFor(input, userId);
  const view = await requireView(deps.db, await loadOrgContext(deps.db, userId), id);
  requireEditable(view, 'You do not have permission to edit this item');
  // Items change owner only through sharing.
  if (input.organizationId !== undefined && (input.organizationId ?? null) !== view.cipher.organizationId) {
    throw badRequest('Organization mismatch. Use the share endpoint to move items into an organization.');
  }
  await checkFolder(deps.db, userId, input.folderId);

  const date = now();
  const cipher = applyUpdate(view.cipher, input, { now: date, preserveRevisionDate: !!body.preserveRevisionDate });
  await commit(
    deps,
    caller,
    date,
    { orgIds: [cipher.organizationId], push: { type: PushType.SyncCipherUpdate, item: pushItem(cipher, view.access.collectionIds) } },
    async (tx) => {
      await saveView(tx, userId, cipher);
      await renameAttachments(tx, cipher.id, attachmentChanges(input));
    },
  );
  return viewJson(deps.db, { ...view, cipher });
}

// Moves ciphers to the trash, or back out of it.
async function trash(deps: Deps, caller: Caller, views: CipherView[], deleted: boolean): Promise<Cipher[]> {
  const date = now();
  const changed = views
    .filter((view) => canEdit(view) && !!view.cipher.deletedAt !== deleted)
    .map((view) => ({ ...view.cipher, deletedAt: deleted ? date : null, updatedAt: date }));
  if (!changed.length) return changed;
  const push =
    changed.length === 1
      ? { type: PushType.SyncCipherUpdate, item: pushItem(changed[0]) }
      : { type: PushType.SyncCiphers };
  await commit(deps, caller, date, { orgIds: changed.map((cipher) => cipher.organizationId), push }, (tx) =>
    saveCiphers(tx, changed),
  );
  return changed;
}

export async function trashCipher(deps: Deps, caller: Caller, id: string, deleted: boolean) {
  const view = await requireView(deps.db, await loadOrgContext(deps.db, caller.user.id), id);
  requireEditable(view, deleted ? 'You do not have permission to delete this item' : 'You do not have permission to restore this item');
  const [changed] = await trash(deps, caller, [view], deleted);
  if (deleted) await audit(deps, caller, 'cipher.delete.soft', {}, view.cipher);
  return viewJson(deps.db, { ...view, cipher: changed ?? view.cipher });
}

export async function trashCiphers(deps: Deps, caller: Caller, ids: string[], deleted: boolean) {
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  const views = await loadViews(deps.db, ctx, ids);
  const changed = new Map((await trash(deps, caller, views, deleted)).map((cipher) => [cipher.id, cipher]));
  if (deleted && changed.size) await audit(deps, caller, 'cipher.delete.soft.bulk', { count: changed.size });
  return listJson(await viewsJson(deps.db, views.map((view) => ({ ...view, cipher: changed.get(view.cipher.id) ?? view.cipher }))));
}

async function purge(deps: Deps, caller: Caller, views: CipherView[]): Promise<Cipher[]> {
  const doomed = views.filter(canEdit).map((view) => view.cipher);
  if (!doomed.length) return doomed;
  const ids = doomed.map((cipher) => cipher.id);
  const attachments = [...(await listAttachments(deps.db, ids)).values()].flat();
  const push =
    doomed.length === 1
      ? { type: PushType.SyncCipherDelete, item: pushItem({ ...doomed[0], updatedAt: now() }) }
      : { type: PushType.SyncCiphers };
  await commit(deps, caller, now(), { orgIds: doomed.map((cipher) => cipher.organizationId), push }, (tx) =>
    deleteCiphers(tx, ids),
  );
  await removeAttachmentFiles(deps.blobs, attachments);
  return doomed;
}

export async function purgeCipher(deps: Deps, caller: Caller, id: string): Promise<void> {
  const view = await requireView(deps.db, await loadOrgContext(deps.db, caller.user.id), id);
  requireEditable(view, 'You do not have permission to delete this item');
  await purge(deps, caller, [view]);
  await audit(deps, caller, 'cipher.delete.permanent', {}, view.cipher);
}

export async function purgeCiphers(deps: Deps, caller: Caller, ids: string[]): Promise<void> {
  const views = await loadViews(deps.db, await loadOrgContext(deps.db, caller.user.id), ids);
  const purged = await purge(deps, caller, views);
  if (purged.length) {
    await audit(deps, caller, 'cipher.delete.permanent.bulk', { count: purged.length, requestedCount: ids.length });
  }
}

// Folder, favorite and archive state is the user's own; read access is
// enough to change it.
async function setStates(deps: Deps, caller: Caller, views: CipherView[], change: (cipher: Cipher) => Partial<Cipher>) {
  const date = now();
  const changed = views.map((view) => {
    const cipher = { ...view.cipher, ...change(view.cipher) };
    // A personal cipher's row changes with it.
    return cipher.organizationId ? cipher : { ...cipher, updatedAt: date };
  });
  if (!changed.length) return changed;
  const push =
    changed.length === 1
      ? { type: PushType.SyncCipherUpdate, item: pushItem(changed[0]) }
      : { type: PushType.SyncCiphers };
  // Nobody else sees the change.
  await commit(deps, caller, date, { orgIds: [], push }, (tx) => saveStates(tx, caller.user.id, changed));
  return changed;
}

export async function updateCipherState(
  deps: Deps,
  caller: Caller,
  id: string,
  input: { folderId?: string | null; favorite?: boolean | null },
) {
  const view = await requireView(deps.db, await loadOrgContext(deps.db, caller.user.id), id);
  await checkFolder(deps.db, caller.user.id, input.folderId);
  const [cipher] = await setStates(deps, caller, [view], (current) => ({
    folderId: input.folderId !== undefined ? input.folderId : current.folderId,
    favorite: input.favorite ?? current.favorite,
  }));
  return viewJson(deps.db, { ...view, cipher });
}

export async function moveCiphers(deps: Deps, caller: Caller, ids: string[], folderId: string | null): Promise<void> {
  await checkFolder(deps.db, caller.user.id, folderId);
  const views = await loadViews(deps.db, await loadOrgContext(deps.db, caller.user.id), ids);
  await setStates(deps, caller, views, () => ({ folderId }));
}

async function archive(deps: Deps, caller: Caller, views: CipherView[], archived: boolean) {
  const date = now();
  const changed = await setStates(
    deps,
    caller,
    views.filter((view) => !(archived && view.cipher.deletedAt)),
    () => ({ archivedAt: archived ? date : null }),
  );
  const byId = new Map(changed.map((cipher) => [cipher.id, cipher]));
  return viewsJson(deps.db, views.map((view) => ({ ...view, cipher: byId.get(view.cipher.id) ?? view.cipher })));
}

export async function archiveCiphers(deps: Deps, caller: Caller, ids: string[], archived: boolean) {
  const views = await loadViews(deps.db, await loadOrgContext(deps.db, caller.user.id), ids);
  return listJson(await archive(deps, caller, views, archived));
}

export async function archiveCipher(deps: Deps, caller: Caller, id: string, archived: boolean) {
  const view = await requireView(deps.db, await loadOrgContext(deps.db, caller.user.id), id);
  if (archived && view.cipher.deletedAt) throw badRequest('Cannot archive a deleted cipher');
  const [json] = await archive(deps, caller, [view], archived);
  return json;
}
