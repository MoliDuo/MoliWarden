import type { Cipher, Env, User } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { readActingDeviceIdentifier } from '../utils/device';
import {
  canWriteCollection,
  hasFullOrgAccess,
  isOrgAdminType,
  loadUserOrgContext,
  type UserOrgContext,
} from '../services/org-access';
import { loadCipherView, saveOrgCipherForUser, type CipherView } from '../services/cipher-views';
import { getCiphersByOrgIds } from '../services/storage-cipher-repo';
import {
  addCipherCollectionStatement,
  getMembershipByOrgAndUser,
  listCipherCollectionIds,
  listCollectionsByOrg,
  ORG_MEMBER_STATUS,
  ORG_MEMBER_TYPE,
  removeCipherCollectionStatement,
  saveCollectionStatement,
  touchOrgMembersRevision,
} from '../services/storage-org-repo';
import { collectionJson, listJson } from '../services/org-json';
import { notifyOrgMembersSync } from '../services/org-notifications';
import {
  cipherResponseOptionsForRequest,
  cipherToResponse,
  mergeCipherUpdate,
  normalizeCipherForStorage,
  syncIncomingAttachmentMetadata,
  validateCipherEncryptedFieldsForCompatibility,
} from './ciphers';

// Organization-specific cipher endpoints: moving items into an organization
// (share), assigning collections, admin listings, org import / export.

function normalizeId(value: unknown): string {
  return String(value ?? '').trim().toLowerCase();
}

function parseIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value.map(normalizeId).filter(Boolean)));
}

async function readJson(request: Request): Promise<any | Response> {
  try {
    const text = await request.text();
    return text ? JSON.parse(text) : {};
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
}

function canWriteView(view: CipherView): boolean {
  return view.access.edit || view.access.manage;
}

async function orgCollectionIdSet(env: Env, orgId: string): Promise<Set<string>> {
  return new Set((await listCollectionsByOrg(env.DB, orgId)).map((collection) => collection.id));
}

function cipherJson(request: Request, view: CipherView, attachments: Awaited<ReturnType<StorageService['getAttachmentsByCipher']>>) {
  return cipherToResponse(view.cipher, attachments, { ...cipherResponseOptionsForRequest(request), access: view.access });
}

// Admin rendering (sync type "Organization"): no per-user fields.
function orgAdminCipherJson(cipher: Cipher, collectionIds: string[], attachments: Awaited<ReturnType<StorageService['getAttachmentsByCipher']>>) {
  const json = cipherToResponse(cipher, attachments, {
    access: { personal: false, orgId: cipher.organizationId ?? null, edit: true, viewPassword: true, manage: true, collectionIds },
  }) as unknown as Record<string, unknown>;
  delete json.folderId;
  delete json.favorite;
  delete json.archivedDate;
  delete json.edit;
  delete json.viewPassword;
  delete json.permissions;
  return json;
}

async function shareOne(
  request: Request,
  env: Env,
  user: User,
  cipherId: string,
  cipherData: any,
  collectionIds: string[],
  ctx: UserOrgContext
): Promise<{ view: CipherView } | Response> {
  const storage = new StorageService(env.DB);
  const view = await loadCipherView(env.DB, user.id, cipherId, ctx);
  if (!view) return errorResponse('Cipher not found', 404);
  if (!canWriteView(view)) return errorResponse('You do not have permission to share this item', 403);

  const orgId = normalizeId(cipherData?.organizationId ?? cipherData?.OrganizationId);
  if (!orgId) return errorResponse('organizationId is required', 400);
  // Checked before touching anything: an org item cannot hop to another org.
  if (view.cipher.organizationId && view.cipher.organizationId !== orgId) {
    return errorResponse("Organization mismatch. Please resync the client before updating the cipher", 400);
  }
  if (!ctx.confirmedByOrg.has(orgId)) {
    return errorResponse("You don't have permission to add item to organization", 403);
  }
  if (!collectionIds.length) {
    return errorResponse('Organization items must be assigned to at least one collection', 400);
  }
  const orgCollections = await orgCollectionIdSet(env, orgId);
  for (const collectionId of collectionIds) {
    if (!orgCollections.has(collectionId)) return errorResponse('Invalid collection ID provided', 400);
    if (!canWriteCollection(ctx, orgId, collectionId)) return errorResponse('No rights to add items to the collection', 403);
  }

  const merged = mergeCipherUpdate(view.cipher, cipherData, { organizationId: orgId });
  if (typeof merged === 'string') return errorResponse(merged, 400);
  merged.organizationId = orgId;
  merged.userId = null;
  // Folder / favorite of the sharer carry over into their per-user state.
  merged.folderId = view.cipher.folderId ?? null;
  merged.favorite = !!view.cipher.favorite;

  const takeoverFromUserId = view.cipher.organizationId ? null : user.id;
  await syncIncomingAttachmentMetadata(storage, merged.id, cipherData);
  const revisionDate = await saveOrgCipherForUser(env.DB, merged, user.id, {
    takeoverFromUserId,
    collectionStatements: collectionIds.map((collectionId) => addCipherCollectionStatement(env.DB, merged.id, collectionId)),
  });
  if (takeoverFromUserId) {
    // The item left the personal vault: bump the sharer as well (they are a member, so
    // touchOrgMembersRevision already covered it) and notify everyone in the org.
    notifyOrgMembersSync(env, orgId, revisionDate, readActingDeviceIdentifier(request));
  }
  const updated = await loadCipherView(env.DB, user.id, merged.id);
  return { view: updated || view };
}

// PUT/POST /api/ciphers/{id}/share   { cipher, collectionIds }
export async function handleShareCipher(request: Request, env: Env, user: User, cipherId: string): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const cipherData = body.cipher || body.Cipher;
  if (!cipherData || typeof cipherData !== 'object') return errorResponse('cipher is required', 400);
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const result = await shareOne(request, env, user, normalizeId(cipherId), cipherData, parseIds(body.collectionIds ?? body.CollectionIds), ctx);
  if (result instanceof Response) return result;
  const storage = new StorageService(env.DB);
  return jsonResponse(cipherJson(request, result.view, await storage.getAttachmentsByCipher(result.view.cipher.id)));
}

// PUT/POST /api/ciphers/share   { ciphers: [...], collectionIds }
export async function handleBulkShareCiphers(request: Request, env: Env, user: User): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const ciphers = Array.isArray(body.ciphers) ? body.ciphers : [];
  const collectionIds = parseIds(body.collectionIds);
  if (!ciphers.length) return errorResponse('You must select at least one cipher.', 400);
  if (!collectionIds.length) return errorResponse('You must select at least one collection.', 400);
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const storage = new StorageService(env.DB);
  const data = [];
  for (const cipherData of ciphers) {
    const id = normalizeId(cipherData?.id);
    if (!id) return errorResponse('Request missing ids field', 400);
    const result = await shareOne(request, env, user, id, cipherData, collectionIds, ctx);
    if (result instanceof Response) return result;
    data.push(cipherJson(request, result.view, await storage.getAttachmentsByCipher(id)));
  }
  return jsonResponse(listJson(data));
}

// PUT/POST /api/ciphers/{id}/collections | /collections_v2 | /collections-admin   { collectionIds }
// Only collections the caller can write are added or removed; others are kept.
export async function handleUpdateCipherCollections(
  request: Request,
  env: Env,
  user: User,
  cipherId: string,
  variant: 'v1' | 'v2' | 'admin'
): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const view = await loadCipherView(env.DB, user.id, normalizeId(cipherId), ctx);
  if (!view) return errorResponse('Cipher not found', 404);
  const orgId = view.cipher.organizationId;
  if (!orgId) return errorResponse('Cipher is not in an organization', 400);
  if (!canWriteView(view)) return errorResponse('You do not have permission to change collections of this item', 403);

  const posted = new Set(parseIds(body.collectionIds ?? body.CollectionIds));
  const orgCollections = await orgCollectionIdSet(env, orgId);
  const current = new Set((await listCipherCollectionIds(env.DB, [view.cipher.id])).get(view.cipher.id) || []);

  const statements: D1PreparedStatement[] = [];
  for (const collectionId of posted) {
    if (current.has(collectionId)) continue;
    if (!orgCollections.has(collectionId)) return errorResponse('Invalid collection ID provided', 400);
    if (!canWriteCollection(ctx, orgId, collectionId)) return errorResponse('No rights to modify the collection', 403);
    statements.push(addCipherCollectionStatement(env.DB, view.cipher.id, collectionId));
  }
  let remaining = posted.size;
  for (const collectionId of current) {
    if (posted.has(collectionId)) continue;
    // Read-only collections the caller cannot touch stay assigned.
    if (!canWriteCollection(ctx, orgId, collectionId)) {
      remaining++;
      continue;
    }
    statements.push(removeCipherCollectionStatement(env.DB, view.cipher.id, collectionId));
  }
  if (remaining === 0 && !hasFullOrgAccess(ctx.confirmedByOrg.get(orgId)!)) {
    return errorResponse('Items must remain in at least one collection you can access', 400);
  }
  if (statements.length) {
    await env.DB.batch(statements);
    const revisionDate = new Date().toISOString();
    await touchOrgMembersRevision(env.DB, orgId, revisionDate);
    notifyOrgMembersSync(env, orgId, revisionDate, readActingDeviceIdentifier(request));
  }

  const storage = new StorageService(env.DB);
  const attachments = await storage.getAttachmentsByCipher(view.cipher.id);
  if (variant === 'admin' && hasFullOrgAccess(ctx.confirmedByOrg.get(orgId)!)) {
    const links = await listCipherCollectionIds(env.DB, [view.cipher.id]);
    return jsonResponse(orgAdminCipherJson(view.cipher, links.get(view.cipher.id) || [], attachments));
  }
  const updated = await loadCipherView(env.DB, user.id, view.cipher.id);
  if (!updated) {
    // The caller removed their own last collection and can no longer see the item.
    return variant === 'v2'
      ? jsonResponse({ object: 'optionalCipherDetails', unavailable: true, cipher: null })
      : new Response(null, { status: 200 });
  }
  const cipher = cipherJson(request, updated, attachments);
  if (variant === 'v2') {
    return jsonResponse({ object: 'optionalCipherDetails', unavailable: false, cipher });
  }
  return jsonResponse(cipher);
}

// POST /api/ciphers/bulk-collections  { organizationId, cipherIds, collectionIds, removeCollections }
export async function handleBulkCipherCollections(request: Request, env: Env, user: User): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const orgId = normalizeId(body.organizationId);
  const ctx = await loadUserOrgContext(env.DB, user.id);
  if (!ctx.confirmedByOrg.has(orgId)) return errorResponse('Resource not found', 404);
  const orgCollections = await orgCollectionIdSet(env, orgId);
  const collectionIds = parseIds(body.collectionIds);
  for (const collectionId of collectionIds) {
    if (!orgCollections.has(collectionId) || !canWriteCollection(ctx, orgId, collectionId)) {
      return errorResponse('Resource not found', 404);
    }
  }
  const remove = body.removeCollections === true;
  const fullAccess = hasFullOrgAccess(ctx.confirmedByOrg.get(orgId)!);
  const statements: D1PreparedStatement[] = [];
  for (const cipherId of parseIds(body.cipherIds)) {
    const view = await loadCipherView(env.DB, user.id, cipherId, ctx);
    if (!view || view.cipher.organizationId !== orgId || !canWriteView(view)) continue;
    if (remove && !fullAccess) {
      // Same rule as the single-item endpoint: limited members may not orphan an item.
      const current = (await listCipherCollectionIds(env.DB, [cipherId])).get(cipherId) || [];
      const remaining = current.filter((id) => !collectionIds.includes(id));
      if (!remaining.length) return errorResponse('Items must remain in at least one collection', 400);
    }
    for (const collectionId of collectionIds) {
      statements.push(
        remove
          ? removeCipherCollectionStatement(env.DB, cipherId, collectionId)
          : addCipherCollectionStatement(env.DB, cipherId, collectionId)
      );
    }
  }
  if (statements.length) {
    await env.DB.batch(statements);
    const revisionDate = new Date().toISOString();
    await touchOrgMembersRevision(env.DB, orgId, revisionDate);
    notifyOrgMembersSync(env, orgId, revisionDate, readActingDeviceIdentifier(request));
  }
  return new Response(null, { status: 200 });
}

async function requireFullAccessMember(env: Env, userId: string, orgId: string): Promise<Response | null> {
  const membership = await getMembershipByOrgAndUser(env.DB, orgId, userId);
  if (
    !membership ||
    membership.status !== ORG_MEMBER_STATUS.CONFIRMED ||
    !(isOrgAdminType(membership.type) || membership.type === ORG_MEMBER_TYPE.MANAGER) ||
    !hasFullOrgAccess(membership)
  ) {
    return errorResponse('Resource not found.', 404);
  }
  return null;
}

async function orgAdminCipherList(env: Env, orgId: string): Promise<Record<string, unknown>[]> {
  const storage = new StorageService(env.DB);
  const ciphers = await getCiphersByOrgIds(env.DB, [orgId]);
  const ids = ciphers.map((cipher) => cipher.id);
  const [links, attachments] = await Promise.all([listCipherCollectionIds(env.DB, ids), storage.getAttachmentsByCipherIds(ids)]);
  return ciphers.map((cipher) => orgAdminCipherJson(cipher, links.get(cipher.id) || [], attachments.get(cipher.id) || []));
}

// GET /api/ciphers/organization-details?organizationId=
export async function handleOrganizationCipherDetails(request: Request, env: Env, user: User): Promise<Response> {
  const orgId = normalizeId(new URL(request.url).searchParams.get('organizationId'));
  const denied = await requireFullAccessMember(env, user.id, orgId);
  if (denied) return denied;
  return jsonResponse(listJson(await orgAdminCipherList(env, orgId)));
}

// GET /api/organizations/{id}/export  (owners and admins)
export async function handleExportOrganization(env: Env, user: User, orgId: string): Promise<Response> {
  const membership = await getMembershipByOrgAndUser(env.DB, orgId, user.id);
  if (!membership || membership.status !== ORG_MEMBER_STATUS.CONFIRMED || !isOrgAdminType(membership.type)) {
    return errorResponse('Organization not found', 404);
  }
  const collections = await listCollectionsByOrg(env.DB, orgId);
  return jsonResponse({
    collections: collections.map(collectionJson),
    ciphers: await orgAdminCipherList(env, orgId),
  });
}

// POST /api/ciphers/import-organization?organizationId=
// { ciphers: [...], collections: [{ name, id? }], collectionRelationships: [{ key: cipherIndex, value: collectionIndex }] }
export async function handleImportOrganization(request: Request, env: Env, user: User): Promise<Response> {
  const orgId = normalizeId(new URL(request.url).searchParams.get('organizationId'));
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const membership = ctx.confirmedByOrg.get(orgId);
  if (!membership) return errorResponse('Organization not found', 404);
  const body = await readJson(request);
  if (body instanceof Response) return body;

  const ciphers: any[] = Array.isArray(body.ciphers) ? body.ciphers : [];
  const collections: any[] = Array.isArray(body.collections) ? body.collections : [];
  const relationships: any[] = Array.isArray(body.collectionRelationships) ? body.collectionRelationships : [];
  if (ciphers.length > 5000) return errorResponse('Too many items in one import', 400);

  const existing = await orgCollectionIdSet(env, orgId);
  const now = new Date().toISOString();
  const statements: D1PreparedStatement[] = [];
  const collectionIds: string[] = [];
  for (const item of collections) {
    const id = normalizeId(item?.id);
    if (id && existing.has(id)) {
      if (!canWriteCollection(ctx, orgId, id)) {
        return errorResponse("The current user isn't allowed to manage this collection", 403);
      }
      collectionIds.push(id);
      continue;
    }
    if (!hasFullOrgAccess(membership)) {
      return errorResponse("The current user isn't allowed to create new collections", 403);
    }
    const name = String(item?.name ?? '').trim();
    if (!name) return errorResponse('Collection name is required', 400);
    const collection = { id: generateUUID(), orgId, name, externalId: null, createdAt: now, updatedAt: now };
    statements.push(saveCollectionStatement(env.DB, collection));
    collectionIds.push(collection.id);
  }

  const cipherCollections = new Map<number, string[]>();
  for (const relation of relationships) {
    const cipherIndex = Number(relation?.key);
    const collectionIndex = Number(relation?.value);
    const collectionId = collectionIds[collectionIndex];
    if (!Number.isInteger(cipherIndex) || cipherIndex < 0 || cipherIndex >= ciphers.length || !collectionId) {
      return errorResponse('Invalid collection relationship', 400);
    }
    const list = cipherCollections.get(cipherIndex) || [];
    list.push(collectionId);
    cipherCollections.set(cipherIndex, list);
  }

  const safeBind = (stmt: D1PreparedStatement, ...values: unknown[]) => stmt.bind(...values.map((v) => (v === undefined ? null : v)));
  const { saveOrgCipherStatement } = await import('../services/storage-cipher-repo');
  for (let index = 0; index < ciphers.length; index++) {
    const assigned = cipherCollections.get(index) || [];
    if (!assigned.length && !hasFullOrgAccess(membership)) {
      return errorResponse('Every imported item must be assigned to a collection', 400);
    }
    const source = ciphers[index] || {};
    const cipher = {
      ...source,
      id: generateUUID(),
      userId: null,
      organizationId: orgId,
      type: Number(source.type) || 1,
      folderId: null,
      favorite: false,
      reprompt: source.reprompt || 0,
      createdAt: now,
      updatedAt: now,
      archivedAt: null,
      deletedAt: null,
    } as Cipher;
    normalizeCipherForStorage(cipher);
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) return errorResponse(`Item ${index + 1}: ${compatibilityError}`, 400);
    statements.push(saveOrgCipherStatement(env.DB, safeBind, cipher));
    for (const collectionId of assigned) statements.push(addCipherCollectionStatement(env.DB, cipher.id, collectionId));
  }

  for (let i = 0; i < statements.length; i += 200) {
    await env.DB.batch(statements.slice(i, i + 200));
  }
  const revisionDate = new Date().toISOString();
  await touchOrgMembersRevision(env.DB, orgId, revisionDate);
  notifyOrgMembersSync(env, orgId, revisionDate, readActingDeviceIdentifier(request));
  return new Response(null, { status: 200 });
}
