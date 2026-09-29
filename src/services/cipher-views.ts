import type { Cipher } from '../types';
import {
  type CipherAccess,
  type UserOrgContext,
  computeCipherAccess,
  loadUserOrgContext,
} from './org-access';
import {
  getCipher,
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

