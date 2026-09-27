import type { Cipher } from '../types';
import {
  type CipherAccess,
  type UserOrgContext,
  computeCipherAccess,
  fullAccessOrgIds,
  grantedCollectionIds,
  loadUserOrgContext,
} from './org-access';
import {
  getAllCiphers,
  getCipher,
  getCiphersByCollectionIds,
  getCiphersByOrgIds,
  saveOrgCipherStatement,
} from './storage-cipher-repo';
import {
  type CipherUserState,
  listCipherCollectionIds,
  listCipherUserStates,
  saveCipherUserStateStatement,
  touchOrgMembersRevision,
} from './storage-org-repo';

// A cipher as seen by one user: organization ciphers carry that user's
// folder / favorite / archive state and the user's computed permissions.

export interface CipherView {
  cipher: Cipher;
  access: CipherAccess;
}

function safeBind(stmt: D1PreparedStatement, ...values: unknown[]): D1PreparedStatement {
  return stmt.bind(...values.map((value) => (value === undefined ? null : value)));
}

function applyUserState(cipher: Cipher, state: CipherUserState | undefined): Cipher {
  return {
    ...cipher,
    folderId: state?.folderId ?? null,
    favorite: !!state?.favorite,
    archivedAt: state?.archivedAt ?? null,
  };
}

export async function listVisibleCipherViews(
  db: D1Database,
  userId: string,
  ctx?: UserOrgContext
): Promise<{ views: CipherView[]; ctx: UserOrgContext }> {
  const orgCtx = ctx || (await loadUserOrgContext(db, userId));
  const [personal, fullOrgCiphers, collectionCiphers] = await Promise.all([
    getAllCiphers(db, userId),
    getCiphersByOrgIds(db, fullAccessOrgIds(orgCtx)),
    getCiphersByCollectionIds(db, grantedCollectionIds(orgCtx)),
  ]);

  const orgCiphers = new Map<string, Cipher>();
  for (const cipher of [...fullOrgCiphers, ...collectionCiphers]) orgCiphers.set(cipher.id, cipher);
  const orgIds = Array.from(orgCiphers.keys());
  const [links, states] = await Promise.all([
    listCipherCollectionIds(db, orgIds),
    listCipherUserStates(db, userId, orgIds),
  ]);

  const views: CipherView[] = [];
  for (const cipher of personal) {
    views.push({ cipher, access: computeCipherAccess(orgCtx, cipher, [])! });
  }
  for (const cipher of orgCiphers.values()) {
    const access = computeCipherAccess(orgCtx, cipher, links.get(cipher.id) || []);
    if (!access) continue;
    views.push({ cipher: applyUserState(cipher, states.get(cipher.id)), access });
  }
  views.sort((a, b) => (a.cipher.updatedAt < b.cipher.updatedAt ? 1 : -1));
  return { views, ctx: orgCtx };
}

export async function loadCipherView(
  db: D1Database,
  userId: string,
  cipherId: string,
  ctx?: UserOrgContext
): Promise<CipherView | null> {
  const cipher = await getCipher(db, cipherId);
  if (!cipher) return null;
  if (!cipher.organizationId) {
    return cipher.userId === userId
      ? { cipher, access: { personal: true, orgId: null, edit: true, viewPassword: true, manage: true, collectionIds: [] } }
      : null;
  }
  const orgCtx = ctx || (await loadUserOrgContext(db, userId));
  const [links, states] = await Promise.all([
    listCipherCollectionIds(db, [cipher.id]),
    listCipherUserStates(db, userId, [cipher.id]),
  ]);
  const access = computeCipherAccess(orgCtx, cipher, links.get(cipher.id) || []);
  if (!access) return null;
  return { cipher: applyUserState(cipher, states.get(cipher.id)), access };
}

export async function loadCipherViews(
  db: D1Database,
  userId: string,
  cipherIds: string[]
): Promise<CipherView[]> {
  const ctx = await loadUserOrgContext(db, userId);
  const views: CipherView[] = [];
  for (const id of cipherIds) {
    const view = await loadCipherView(db, userId, id, ctx);
    if (view) views.push(view);
  }
  return views;
}

// Writing an org cipher: `edit` rights are the caller's responsibility.
// Returns the new revision date (bumped for every member of the org).
export async function saveOrgCipherForUser(
  db: D1Database,
  cipher: Cipher,
  userId: string,
  options: { takeoverFromUserId?: string | null; collectionStatements?: D1PreparedStatement[] } = {}
): Promise<string> {
  const statements = [
    saveOrgCipherStatement(db, safeBind, cipher, { takeoverFromUserId: options.takeoverFromUserId }),
    ...(options.collectionStatements || []),
    saveCipherUserStateStatement(db, {
      cipherId: cipher.id,
      userId,
      folderId: cipher.folderId ?? null,
      favorite: !!cipher.favorite,
      archivedAt: cipher.archivedAt ?? null,
    }),
  ];
  const results = await db.batch(statements);
  if ((results[0]?.meta.changes ?? 0) === 0) {
    throw new Error('Cipher ownership changed concurrently');
  }
  const revisionDate = new Date().toISOString();
  await touchOrgMembersRevision(db, cipher.organizationId!, revisionDate);
  return revisionDate;
}

export async function saveUserStateOnly(db: D1Database, cipher: Cipher, userId: string): Promise<void> {
  await saveCipherUserStateStatement(db, {
    cipherId: cipher.id,
    userId,
    folderId: cipher.folderId ?? null,
    favorite: !!cipher.favorite,
    archivedAt: cipher.archivedAt ?? null,
  }).run();
}
