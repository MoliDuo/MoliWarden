import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, forbidden, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { isEncString } from '../../platform/enc-string';
import { listAttachments, renameAttachments } from '../attachments/repo';
import {
  canWriteCollection,
  hasFullAccessTo,
  isAdminType,
  loadOrgContext,
  type OrgContext,
} from '../organizations/access';
import {
  addCipherCollections,
  insertCollections,
  listCipherCollections,
  listCollections,
  MemberType,
  removeCipherCollections,
  type Collection,
} from '../organizations/repo';
import { PushType } from '../push/service';
import type { Cipher, CipherInput } from './model';
import { collectionJson } from '../organizations/responses';
import { findCiphers, listCiphers, saveCiphers } from './repo';
import { listJson, orgCipherJson } from './responses';
import type { OrgImportInput } from './schemas';
import { canEdit, loadViews, requireView, viewJson, viewsJson, type CipherView } from './views';
import {
  applyUpdate,
  attachmentChanges,
  checkEncryptedFor,
  checkWritableCollections,
  commit,
  newCipher,
  pushItem,
  saveView,
} from './writes';

// Organization ciphers: moving items into an organization, the collections
// that hold them, and what organization admins list and import.

const now = () => new Date().toISOString();

async function orgCollectionIds(db: Executor, orgId: string): Promise<Set<string>> {
  return new Set((await listCollections(db, [orgId])).map((collection) => collection.id));
}

// Moves the ciphers into an organization (or into more of its collections),
// with their content re-encrypted by the client for it. The user's folder
// and favorite stay with the user.
export async function shareCiphers(
  deps: Deps,
  caller: Caller,
  items: Array<{ id: string; input: CipherInput }>,
  collectionIds: string[],
) {
  const userId = caller.user.id;
  const ctx = await loadOrgContext(deps.db, userId);
  const views = new Map((await loadViews(deps.db, ctx, items.map((item) => item.id))).map((view) => [view.cipher.id, view]));
  const date = now();
  const shared: Array<{ view: CipherView; input: CipherInput; cipher: Cipher }> = [];
  for (const { id, input } of items) {
    const view = views.get(id);
    if (!view) throw notFound('Cipher not found');
    if (!canEdit(view)) throw forbidden('You do not have permission to share this item');
    checkEncryptedFor(input, userId);
    const orgId = input.organizationId;
    if (!orgId) throw badRequest('organizationId is required');
    if (view.cipher.organizationId && view.cipher.organizationId !== orgId) {
      throw badRequest('Organization mismatch. Please resync the client before updating the cipher');
    }
    if (!ctx.confirmed.has(orgId)) throw forbidden("You don't have permission to add item to organization");
    await checkWritableCollections(deps.db, ctx, orgId, collectionIds);
    const cipher = applyUpdate(view.cipher, input, { now: date, organizationId: orgId });
    shared.push({
      view,
      input,
      cipher: { ...cipher, folderId: view.cipher.folderId, favorite: view.cipher.favorite },
    });
  }

  const push =
    shared.length === 1
      ? { type: PushType.SyncCipherUpdate, item: pushItem(shared[0].cipher, collectionIds) }
      : { type: PushType.SyncCiphers };
  await commit(deps, caller, date, { orgIds: shared.map(({ cipher }) => cipher.organizationId), push }, async (tx) => {
    for (const { view, input, cipher } of shared) {
      await saveView(tx, userId, cipher, view.cipher.organizationId ? undefined : userId);
      await renameAttachments(tx, cipher.id, attachmentChanges(input));
    }
    await addCipherCollections(
      tx,
      shared.flatMap(({ cipher }) => collectionIds.map((collectionId) => ({ cipherId: cipher.id, collectionId }))),
    );
  });
  return viewsJson(deps.db, await loadViews(deps.db, ctx, shared.map(({ cipher }) => cipher.id)));
}

export type CollectionsVariant = 'v1' | 'v2' | 'admin';

// Sets the collections of a cipher. Only collections the user may write
// are added or removed; the others stay as they are. Returns null when the
// user can no longer see the cipher and the variant has nothing to say.
export async function setCipherCollections(
  deps: Deps,
  caller: Caller,
  id: string,
  collectionIds: string[],
  variant: CollectionsVariant,
) {
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  const view = await requireView(deps.db, ctx, id);
  const orgId = view.cipher.organizationId;
  if (!orgId) throw badRequest('Cipher is not in an organization');
  if (!canEdit(view)) throw forbidden('You do not have permission to change collections of this item');

  const posted = new Set(collectionIds);
  const existing = await orgCollectionIds(deps.db, orgId);
  const current = (await listCipherCollections(deps.db, [id])).get(id) ?? [];
  const added = [...posted].filter((collectionId) => !current.includes(collectionId));
  for (const collectionId of added) {
    if (!existing.has(collectionId)) throw badRequest('Invalid collection ID provided');
    if (!canWriteCollection(ctx, orgId, collectionId)) throw forbidden('No rights to modify the collection');
  }
  const dropped = current.filter((collectionId) => !posted.has(collectionId));
  const removed = dropped.filter((collectionId) => canWriteCollection(ctx, orgId, collectionId));
  const remaining = posted.size + dropped.length - removed.length;
  if (remaining === 0 && !hasFullAccessTo(ctx, orgId)) {
    throw badRequest('Items must remain in at least one collection you can access');
  }

  if (added.length || removed.length) {
    const date = now();
    const after = [...current.filter((collectionId) => !removed.includes(collectionId)), ...added];
    await commit(
      deps,
      caller,
      date,
      { orgIds: [orgId], push: { type: PushType.SyncCipherUpdate, item: pushItem(view.cipher, after) } },
      async (tx) => {
        await addCipherCollections(tx, added.map((collectionId) => ({ cipherId: id, collectionId })));
        await removeCipherCollections(tx, [id], removed);
      },
    );
  }

  if (variant === 'admin' && hasFullAccessTo(ctx, orgId)) {
    const [json] = await orgCiphersJson(deps.db, await findCiphers(deps.db, [id]));
    return json;
  }
  const [updated] = await loadViews(deps.db, ctx, [id]);
  const cipher = updated ? await viewJson(deps.db, updated) : null;
  if (variant === 'v2') return { object: 'optionalCipherDetails', unavailable: !cipher, cipher };
  return cipher;
}

// Adds ciphers to collections, or takes them out.
export async function setBulkCollections(
  deps: Deps,
  caller: Caller,
  input: { organizationId: string; cipherIds: string[]; collectionIds: string[]; removeCollections?: boolean | null },
): Promise<void> {
  const { organizationId: orgId, collectionIds } = input;
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  if (!ctx.confirmed.has(orgId)) throw notFound('Resource not found');
  const existing = await orgCollectionIds(deps.db, orgId);
  if (collectionIds.some((collectionId) => !existing.has(collectionId) || !canWriteCollection(ctx, orgId, collectionId))) {
    throw notFound('Resource not found');
  }
  const ids = (await loadViews(deps.db, ctx, input.cipherIds))
    .filter((view) => view.cipher.organizationId === orgId && canEdit(view))
    .map((view) => view.cipher.id);
  if (!ids.length || !collectionIds.length) return;

  const remove = !!input.removeCollections;
  // Members without full access may not leave an item in no collection.
  if (remove && !hasFullAccessTo(ctx, orgId)) {
    const links = await listCipherCollections(deps.db, ids);
    if (ids.some((id) => (links.get(id) ?? []).every((collectionId) => collectionIds.includes(collectionId)))) {
      throw badRequest('Items must remain in at least one collection');
    }
  }
  await commit(deps, caller, now(), { orgIds: [orgId], push: { type: PushType.SyncCiphers } }, (tx) =>
    remove
      ? removeCipherCollections(tx, ids, collectionIds)
      : addCipherCollections(tx, ids.flatMap((cipherId) => collectionIds.map((collectionId) => ({ cipherId, collectionId })))),
  );
}

// Organization ciphers as admins see them: nobody's folder or favorite.
async function orgCiphersJson(db: Executor, ciphers: Cipher[]) {
  const ids = ciphers.map((cipher) => cipher.id);
  const [links, attachments] = await Promise.all([listCipherCollections(db, ids), listAttachments(db, ids)]);
  return ciphers.map((cipher) => orgCipherJson(cipher, links.get(cipher.id) ?? [], attachments.get(cipher.id)));
}

// Every cipher of the organization, for its admins.
export async function organizationCiphersJson(db: Executor, orgId: string) {
  return orgCiphersJson(db, await listCiphers(db, { orgIds: [orgId] }));
}

// Owners, admins and managers who see every collection.
function canListAll(ctx: OrgContext, orgId: string): boolean {
  const membership = ctx.confirmed.get(orgId);
  return !!membership && hasFullAccessTo(ctx, orgId) && (isAdminType(membership.type) || membership.type === MemberType.Manager);
}

// Everything an organization holds, for its owners and admins to export.
export async function exportOrganization(deps: Deps, caller: Caller, orgId: string) {
  const membership = (await loadOrgContext(deps.db, caller.user.id)).confirmed.get(orgId);
  if (!membership || !isAdminType(membership.type)) throw notFound('Organization not found');
  const [collections, ciphers] = await Promise.all([listCollections(deps.db, [orgId]), organizationCiphersJson(deps.db, orgId)]);
  return { collections: collections.map(collectionJson), ciphers };
}

export async function organizationDetails(deps: Deps, caller: Caller, orgId: string) {
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  if (!canListAll(ctx, orgId)) throw notFound('Resource not found.');
  return listJson(await organizationCiphersJson(deps.db, orgId));
}

// Imports into an organization, creating the collections that do not exist
// yet. Members without full access import only into collections they may
// write, and every item must go into one.
export async function importOrganization(deps: Deps, caller: Caller, orgId: string, input: OrgImportInput): Promise<void> {
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  if (!ctx.confirmed.has(orgId)) throw notFound('Organization not found');
  const fullAccess = hasFullAccessTo(ctx, orgId);
  const existing = await orgCollectionIds(deps.db, orgId);
  const date = now();

  const created: Collection[] = [];
  const collectionIds = input.collections.map((collection) => {
    if (collection.id && existing.has(collection.id)) {
      if (!canWriteCollection(ctx, orgId, collection.id)) {
        throw forbidden("The current user isn't allowed to manage this collection");
      }
      return collection.id;
    }
    if (!fullAccess) throw forbidden("The current user isn't allowed to create new collections");
    if (!collection.name || !isEncString(collection.name)) throw badRequest('Collection names must be encrypted strings.');
    const id = randomUUID();
    created.push({ id, orgId, name: collection.name, externalId: null, createdAt: date, updatedAt: date });
    return id;
  });

  const assigned = new Map<number, string[]>();
  for (const { key, value } of input.collectionRelationships) {
    const collectionId = collectionIds[value];
    if (key >= input.ciphers.length || !collectionId) throw badRequest('Invalid collection relationship');
    assigned.set(key, [...(assigned.get(key) ?? []), collectionId]);
  }
  const ciphers = input.ciphers.map((cipherInput, index) => {
    if (!assigned.has(index) && !fullAccess) throw badRequest('Every imported item must be assigned to a collection');
    return newCipher(cipherInput, { userId: caller.user.id, organizationId: orgId }, date, null);
  });

  await commit(deps, caller, date, { orgIds: [orgId], push: { type: PushType.SyncVault } }, async (tx) => {
    await insertCollections(tx, created);
    await saveCiphers(tx, ciphers);
    await addCipherCollections(
      tx,
      ciphers.flatMap((cipher, index) => (assigned.get(index) ?? []).map((collectionId) => ({ cipherId: cipher.id, collectionId }))),
    );
  });
}
