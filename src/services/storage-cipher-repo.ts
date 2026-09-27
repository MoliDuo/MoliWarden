import type { Cipher } from '../types';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

interface CipherRow {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  type: number | null;
  folder_id: string | null;
  name: string | null;
  notes: string | null;
  favorite: number | null;
  data: string;
  reprompt: number | null;
  key: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  deleted_at: string | null;
}

const CIPHER_SCALAR_DATA_KEYS = new Set([
  'id',
  'userId',
  'user_id',
  // Server-computed (organization ownership and per-user permissions); never
  // trusted from client payloads.
  'organizationId',
  'OrganizationId',
  'organization_id',
  'organizationUseTotp',
  'collectionIds',
  'CollectionIds',
  'edit',
  'viewPassword',
  'permissions',
  'object',
  'type',
  'folderId',
  'folder_id',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'Attachments',
  'attachments2',
  'Attachments2',
  'createdAt',
  'created_at',
  'creationDate',
  'updatedAt',
  'updated_at',
  'revisionDate',
  'archivedAt',
  'archived_at',
  'archivedDate',
  'deletedAt',
  'deleted_at',
  'deletedDate',
]);

// Server-owned cipher fields in any letter case. Official clients read the
// PascalCase variant first, so a client-stored "Edit" or "ViewPassword" would
// otherwise override the server-computed value for every other member.
export const SERVER_OWNED_CIPHER_KEYS_LOWER = new Set([
  'id',
  'userid',
  'organizationid',
  'organizationusetotp',
  'collectionids',
  'edit',
  'viewpassword',
  'permissions',
  'folderid',
  'favorite',
  'type',
  'key',
  'reprompt',
  'creationdate',
  'revisiondate',
  'deleteddate',
  'archiveddate',
  'object',
]);

function buildCipherData(cipher: Cipher, folderId: string | null): string {
  const payload: Record<string, unknown> = {
    ...cipher,
    folderId,
  };
  for (const key of CIPHER_SCALAR_DATA_KEYS) {
    delete payload[key];
  }
  for (const key of Object.keys(payload)) {
    if (SERVER_OWNED_CIPHER_KEYS_LOWER.has(key.toLowerCase())) delete payload[key];
  }
  return JSON.stringify(payload);
}

function parseCipherRow(row: CipherRow | null | undefined): Cipher | null {
  if (!row?.data) return null;
  try {
    const parsed = JSON.parse(row.data) as Cipher;
    const folderId = normalizeOptionalId(row.folder_id ?? parsed.folderId ?? null);
    return {
      ...parsed,
      id: row.id,
      userId: row.user_id,
      organizationId: row.organization_id ?? null,
      type: Number(row.type) || Number(parsed.type) || 1,
      folderId,
      name: row.name ?? parsed.name ?? null,
      notes: row.notes ?? parsed.notes ?? null,
      favorite: row.favorite != null ? !!row.favorite : !!parsed.favorite,
      reprompt: row.reprompt ?? parsed.reprompt ?? 0,
      key: row.key ?? parsed.key ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      archivedAt: row.archived_at ?? parsed.archivedAt ?? parsed.archivedDate ?? null,
      deletedAt: row.deleted_at ?? parsed.deletedAt ?? parsed.deletedDate ?? null,
    };
  } catch {
    console.error('Corrupted cipher data, id:', row.id);
    return null;
  }
}

function selectCipherColumns(): string {
  return 'id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at';
}

export async function getCipher(db: D1Database, id: string): Promise<Cipher | null> {
  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ?`)
    .bind(id)
    .first<CipherRow>();
  return parseCipherRow(row);
}

export async function getCipherForUser(db: D1Database, id: string, userId: string): Promise<Cipher | null> {
  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ? AND user_id = ?`)
    .bind(id, userId)
    .first<CipherRow>();
  return parseCipherRow(row);
}

// Personal ciphers only: the upsert refuses to touch a row owned by another
// user or by an organization.
export async function saveCipher(db: D1Database, safeBind: SafeBind, cipher: Cipher): Promise<void> {
  await saveCipherStatement(db, safeBind, cipher).run();
}

export function saveCipherStatement(db: D1Database, safeBind: SafeBind, cipher: Cipher): D1PreparedStatement {
  if (!cipher.userId) {
    throw new Error('saveCipher requires a personal cipher; use saveOrgCipherStatement for organization ciphers');
  }
  const folderId = normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const stmt = db.prepare(
    'INSERT INTO ciphers(id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) ' +
    'VALUES(?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, archived_at=excluded.archived_at, deleted_at=excluded.deleted_at ' +
    'WHERE ciphers.user_id=excluded.user_id AND ciphers.organization_id IS NULL'
  );
  return safeBind(
    stmt,
    cipher.id,
    cipher.userId,
    Number(cipher.type) || 1,
    folderId,
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    data,
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.createdAt,
    cipher.updatedAt,
    cipher.archivedAt ?? null,
    cipher.deletedAt
  );
}

// Organization ciphers. Folder / favorite / archive are per user and live in
// cipher_user_state, so the row keeps them empty. `allowTakeover` lets a
// personal cipher row be converted into an organization cipher (share).
export function saveOrgCipherStatement(
  db: D1Database,
  safeBind: SafeBind,
  cipher: Cipher,
  options: { takeoverFromUserId?: string | null } = {}
): D1PreparedStatement {
  const orgId = normalizeOptionalId(cipher.organizationId);
  if (!orgId) {
    throw new Error('saveOrgCipherStatement requires an organization cipher');
  }
  const data = buildCipherData({ ...cipher, folderId: null, favorite: false, archivedAt: null }, null);
  const guard = options.takeoverFromUserId
    ? '(ciphers.organization_id = excluded.organization_id OR (ciphers.organization_id IS NULL AND ciphers.user_id = ?))'
    : 'ciphers.organization_id = excluded.organization_id';
  const stmt = db.prepare(
    'INSERT INTO ciphers(id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) ' +
    'VALUES(?, NULL, ?, ?, NULL, ?, ?, 0, ?, ?, ?, ?, ?, NULL, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'user_id=NULL, organization_id=excluded.organization_id, type=excluded.type, folder_id=NULL, name=excluded.name, notes=excluded.notes, favorite=0, ' +
    'data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, archived_at=NULL, deleted_at=excluded.deleted_at ' +
    `WHERE ${guard}`
  );
  const values: unknown[] = [
    cipher.id,
    orgId,
    Number(cipher.type) || 1,
    cipher.name,
    cipher.notes,
    data,
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.createdAt,
    cipher.updatedAt,
    cipher.deletedAt,
  ];
  if (options.takeoverFromUserId) values.push(options.takeoverFromUserId);
  return safeBind(stmt, ...values);
}

export async function getCiphersByOrgIds(db: D1Database, orgIds: string[]): Promise<Cipher[]> {
  if (!orgIds.length) return [];
  const res = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE organization_id IN (${orgIds.map(() => '?').join(', ')}) ORDER BY updated_at DESC`)
    .bind(...orgIds)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersByCollectionIds(db: D1Database, collectionIds: string[]): Promise<Cipher[]> {
  if (!collectionIds.length) return [];
  const out = new Map<string, Cipher>();
  for (let i = 0; i < collectionIds.length; i += 90) {
    const chunk = collectionIds.slice(i, i + 90);
    const res = await db
      .prepare(
        `SELECT ${selectCipherColumns().split(', ').map((column) => `c.${column}`).join(', ')} FROM ciphers c ` +
        `WHERE c.organization_id IS NOT NULL AND EXISTS (SELECT 1 FROM cipher_collections cc WHERE cc.cipher_id = c.id AND cc.collection_id IN (${chunk.map(() => '?').join(', ')}))`
      )
      .bind(...chunk)
      .all<CipherRow>();
    for (const row of res.results || []) {
      const cipher = parseCipherRow(row);
      if (cipher) out.set(cipher.id, cipher);
    }
  }
  return Array.from(out.values());
}

function sanitizeIds(ids: string[]): string[] {
  return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

export async function deleteCipher(db: D1Database, id: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM ciphers WHERE id = ? AND user_id = ?').bind(id, userId).run();
}

export async function bulkSoftDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = ?, updated_at = ?,
             data = (data::jsonb - ARRAY['deletedAt', 'deletedDate', 'updatedAt', 'revisionDate'])::text
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkRestoreCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(2);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = NULL, updated_at = ?,
             data = (data::jsonb - ARRAY['deletedAt', 'deletedDate', 'updatedAt', 'revisionDate'])::text
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const chunkSize = sqlChunkSize(1);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`).bind(userId, ...chunk).run();
  }

  return updateRevisionDate(userId);
}

export async function getAllCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const res = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE user_id = ? ORDER BY updated_at DESC`)
    .bind(userId)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersPage(
  db: D1Database,
  userId: string,
  includeDeleted: boolean,
  limit: number,
  offset: number
): Promise<Cipher[]> {
  const whereDeleted = includeDeleted
    ? ''
    : "AND deleted_at IS NULL AND (data::jsonb ->> 'deletedAt') IS NULL AND (data::jsonb ->> 'deletedDate') IS NULL";
  const res = await db
    .prepare(
      `SELECT ${selectCipherColumns()} FROM ciphers
       WHERE user_id = ?
       ${whereDeleted}
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`
    )
    .bind(userId, limit, offset)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  if (ids.length === 0) return [];
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return [];

  const chunkSize = sqlChunkSize(1);
  const out: Cipher[] = [];
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const stmt = db.prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`);
    const res = await stmt.bind(userId, ...chunk).all<CipherRow>();
    out.push(
      ...(res.results || []).flatMap((row) => {
        const cipher = parseCipherRow(row);
        return cipher ? [cipher] : [];
      })
    );
  }
  return out;
}

export async function bulkMoveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  folderId: string | null,
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const now = new Date().toISOString();
  const normalizedFolderId = normalizeOptionalId(folderId);
  const uniqueIds = sanitizeIds(ids);
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET folder_id = ?, updated_at = ?,
             data = (data::jsonb - ARRAY['folderId', 'folder_id', 'updatedAt', 'revisionDate'])::text
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(normalizedFolderId, now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkArchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = ?, updated_at = ?,
             data = (data::jsonb - ARRAY['archivedAt', 'archivedDate', 'updatedAt', 'revisionDate'])::text
         WHERE user_id = ? AND id IN (${placeholders})
           AND deleted_at IS NULL
           AND (data::jsonb ->> 'deletedAt') IS NULL
           AND (data::jsonb ->> 'deletedDate') IS NULL`
      )
      .bind(now, now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkUnarchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(2);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = NULL, updated_at = ?,
             data = (data::jsonb - ARRAY['archivedAt', 'archivedDate', 'updatedAt', 'revisionDate'])::text
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}
