// Organization / membership / collection persistence.
//
// Access decisions live in src/services/org-access.ts; this module is plain SQL.

export const ORG_MEMBER_STATUS = {
  REVOKED: -1,
  INVITED: 0,
  ACCEPTED: 1,
  CONFIRMED: 2,
} as const;

export const ORG_MEMBER_TYPE = {
  OWNER: 0,
  ADMIN: 1,
  USER: 2,
  MANAGER: 3,
  // Bitwarden's "Custom" role; stored as MANAGER (see normalizeMemberType).
  CUSTOM: 4,
} as const;

export interface Organization {
  id: string;
  name: string;
  billingEmail: string;
  publicKey: string | null;
  privateKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OrgMembership {
  id: string;
  orgId: string;
  userId: string;
  status: number;
  type: number;
  accessAll: boolean;
  akey: string | null;
  revokedStatus: number | null;
  invitedBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OrgMembershipWithUser extends OrgMembership {
  email: string;
  name: string | null;
  publicKey: string | null;
  hasTwoFactor: boolean;
}

export interface Collection {
  id: string;
  orgId: string;
  name: string;
  externalId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CollectionGrant {
  collectionId: string;
  membershipId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

interface OrganizationRow {
  id: string;
  name: string;
  billing_email: string;
  public_key: string | null;
  private_key: string | null;
  created_at: string;
  updated_at: string;
}

interface MembershipRow {
  id: string;
  org_id: string;
  user_id: string;
  status: number;
  type: number;
  access_all: number;
  akey: string | null;
  revoked_status: number | null;
  invited_by: string | null;
  created_at: string;
  updated_at: string;
}

interface CollectionRow {
  id: string;
  org_id: string;
  name: string;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

interface GrantRow {
  collection_id: string;
  membership_id: string;
  read_only: number;
  hide_passwords: number;
  manage: number;
}

const MEMBERSHIP_COLUMNS =
  'm.id, m.org_id, m.user_id, m.status, m.type, m.access_all, m.akey, m.revoked_status, m.invited_by, m.created_at, m.updated_at';

function toOrganization(row: OrganizationRow): Organization {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email,
    publicKey: row.public_key,
    privateKey: row.private_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toMembership(row: MembershipRow): OrgMembership {
  return {
    id: row.id,
    orgId: row.org_id,
    userId: row.user_id,
    status: Number(row.status),
    type: Number(row.type),
    accessAll: !!row.access_all,
    akey: row.akey,
    revokedStatus: row.revoked_status === null ? null : Number(row.revoked_status),
    invitedBy: row.invited_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toCollection(row: CollectionRow): Collection {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toGrant(row: GrantRow): CollectionGrant {
  return {
    collectionId: row.collection_id,
    membershipId: row.membership_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  };
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => '?').join(', ');
}

// --- Organizations ---

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db
    .prepare('SELECT id, name, billing_email, public_key, private_key, created_at, updated_at FROM organizations WHERE id = ?')
    .bind(id)
    .first<OrganizationRow>();
  return row ? toOrganization(row) : null;
}

export async function getOrganizationsByIds(db: D1Database, ids: string[]): Promise<Organization[]> {
  if (!ids.length) return [];
  const res = await db
    .prepare(`SELECT id, name, billing_email, public_key, private_key, created_at, updated_at FROM organizations WHERE id IN (${placeholders(ids.length)})`)
    .bind(...ids)
    .all<OrganizationRow>();
  return (res.results || []).map(toOrganization);
}

export function saveOrganizationStatement(db: D1Database, org: Organization): D1PreparedStatement {
  return db
    .prepare(
      'INSERT INTO organizations(id, name, billing_email, public_key, private_key, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name = excluded.name, billing_email = excluded.billing_email, ' +
      'public_key = excluded.public_key, private_key = excluded.private_key, updated_at = excluded.updated_at'
    )
    .bind(org.id, org.name, org.billingEmail, org.publicKey, org.privateKey, org.createdAt, org.updatedAt);
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  // ON DELETE CASCADE removes memberships, collections, grants and org ciphers
  // (and through ciphers: attachments rows, cipher_collections, cipher_user_state).
  await db.prepare('DELETE FROM organizations WHERE id = ?').bind(id).run();
}

// --- Memberships ---

export async function getMembership(db: D1Database, id: string): Promise<OrgMembership | null> {
  const row = await db
    .prepare(`SELECT ${MEMBERSHIP_COLUMNS} FROM org_memberships m WHERE m.id = ?`)
    .bind(id)
    .first<MembershipRow>();
  return row ? toMembership(row) : null;
}

export async function getMembershipByOrgAndUser(db: D1Database, orgId: string, userId: string): Promise<OrgMembership | null> {
  const row = await db
    .prepare(`SELECT ${MEMBERSHIP_COLUMNS} FROM org_memberships m WHERE m.org_id = ? AND m.user_id = ?`)
    .bind(orgId, userId)
    .first<MembershipRow>();
  return row ? toMembership(row) : null;
}

export async function listMembershipsByUser(db: D1Database, userId: string): Promise<OrgMembership[]> {
  const res = await db
    .prepare(`SELECT ${MEMBERSHIP_COLUMNS} FROM org_memberships m WHERE m.user_id = ? ORDER BY m.created_at ASC`)
    .bind(userId)
    .all<MembershipRow>();
  return (res.results || []).map(toMembership);
}

export async function listMembershipsByOrg(db: D1Database, orgId: string): Promise<OrgMembershipWithUser[]> {
  const res = await db
    .prepare(
      `SELECT ${MEMBERSHIP_COLUMNS}, u.email, u.name, u.public_key AS user_public_key, ` +
      '(u.totp_secret IS NOT NULL OR u.yubikey_key1 IS NOT NULL OR EXISTS (' +
      "SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id AND w.purpose <> 'login')) AS has_two_factor " +
      'FROM org_memberships m INNER JOIN users u ON u.id = m.user_id WHERE m.org_id = ? ORDER BY m.created_at ASC'
    )
    .bind(orgId)
    .all<MembershipRow & { email: string; name: string | null; user_public_key: string | null; has_two_factor: boolean }>();
  return (res.results || []).map((row) => ({
    ...toMembership(row),
    email: row.email,
    name: row.name,
    publicKey: row.user_public_key,
    hasTwoFactor: !!row.has_two_factor,
  }));
}

export async function listMemberUserIds(db: D1Database, orgId: string): Promise<string[]> {
  const res = await db
    .prepare('SELECT user_id FROM org_memberships WHERE org_id = ?')
    .bind(orgId)
    .all<{ user_id: string }>();
  return (res.results || []).map((row) => row.user_id);
}

export async function countOwners(db: D1Database, orgId: string): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM org_memberships WHERE org_id = ? AND type = ? AND status = ?')
    .bind(orgId, ORG_MEMBER_TYPE.OWNER, ORG_MEMBER_STATUS.CONFIRMED)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}

export function saveMembershipStatement(db: D1Database, membership: OrgMembership): D1PreparedStatement {
  return db
    .prepare(
      'INSERT INTO org_memberships(id, org_id, user_id, status, type, access_all, akey, revoked_status, invited_by, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET status = excluded.status, type = excluded.type, access_all = excluded.access_all, ' +
      'akey = excluded.akey, revoked_status = excluded.revoked_status, updated_at = excluded.updated_at'
    )
    .bind(
      membership.id,
      membership.orgId,
      membership.userId,
      membership.status,
      membership.type,
      membership.accessAll ? 1 : 0,
      membership.akey,
      membership.revokedStatus,
      membership.invitedBy,
      membership.createdAt,
      membership.updatedAt
    );
}

export async function deleteMembership(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM org_memberships WHERE id = ?').bind(id).run();
}

// --- Collections ---

export async function getCollection(db: D1Database, id: string): Promise<Collection | null> {
  const row = await db
    .prepare('SELECT id, org_id, name, external_id, created_at, updated_at FROM collections WHERE id = ?')
    .bind(id)
    .first<CollectionRow>();
  return row ? toCollection(row) : null;
}

export async function listCollectionsByOrg(db: D1Database, orgId: string): Promise<Collection[]> {
  const res = await db
    .prepare('SELECT id, org_id, name, external_id, created_at, updated_at FROM collections WHERE org_id = ? ORDER BY created_at ASC')
    .bind(orgId)
    .all<CollectionRow>();
  return (res.results || []).map(toCollection);
}

export async function listCollectionsByOrgIds(db: D1Database, orgIds: string[]): Promise<Collection[]> {
  if (!orgIds.length) return [];
  const res = await db
    .prepare(`SELECT id, org_id, name, external_id, created_at, updated_at FROM collections WHERE org_id IN (${placeholders(orgIds.length)}) ORDER BY created_at ASC`)
    .bind(...orgIds)
    .all<CollectionRow>();
  return (res.results || []).map(toCollection);
}

export function saveCollectionStatement(db: D1Database, collection: Collection): D1PreparedStatement {
  return db
    .prepare(
      'INSERT INTO collections(id, org_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name = excluded.name, external_id = excluded.external_id, updated_at = excluded.updated_at ' +
      'WHERE collections.org_id = excluded.org_id'
    )
    .bind(collection.id, collection.orgId, collection.name, collection.externalId, collection.createdAt, collection.updatedAt);
}

export function deleteCollectionStatement(db: D1Database, orgId: string, id: string): D1PreparedStatement {
  return db.prepare('DELETE FROM collections WHERE id = ? AND org_id = ?').bind(id, orgId);
}

// --- Collection grants ---

export async function listGrantsByMemberships(db: D1Database, membershipIds: string[]): Promise<CollectionGrant[]> {
  if (!membershipIds.length) return [];
  const res = await db
    .prepare(
      `SELECT collection_id, membership_id, read_only, hide_passwords, manage FROM collection_members WHERE membership_id IN (${placeholders(membershipIds.length)})`
    )
    .bind(...membershipIds)
    .all<GrantRow>();
  return (res.results || []).map(toGrant);
}

export async function listGrantsByOrg(db: D1Database, orgId: string): Promise<CollectionGrant[]> {
  const res = await db
    .prepare(
      'SELECT g.collection_id, g.membership_id, g.read_only, g.hide_passwords, g.manage FROM collection_members g ' +
      'INNER JOIN collections c ON c.id = g.collection_id WHERE c.org_id = ?'
    )
    .bind(orgId)
    .all<GrantRow>();
  return (res.results || []).map(toGrant);
}

export function replaceMembershipGrantsStatements(
  db: D1Database,
  membershipId: string,
  grants: Array<Omit<CollectionGrant, 'membershipId'>>
): D1PreparedStatement[] {
  return [
    db.prepare('DELETE FROM collection_members WHERE membership_id = ?').bind(membershipId),
    ...grants.map((grant) => insertGrantStatement(db, { ...grant, membershipId })),
  ];
}

export function replaceCollectionGrantsStatements(
  db: D1Database,
  collectionId: string,
  grants: Array<Omit<CollectionGrant, 'collectionId'>>
): D1PreparedStatement[] {
  return [
    db.prepare('DELETE FROM collection_members WHERE collection_id = ?').bind(collectionId),
    ...grants.map((grant) => insertGrantStatement(db, { ...grant, collectionId })),
  ];
}

export function insertGrantStatement(db: D1Database, grant: CollectionGrant): D1PreparedStatement {
  return db
    .prepare(
      'INSERT INTO collection_members(collection_id, membership_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(collection_id, membership_id) DO UPDATE SET read_only = excluded.read_only, ' +
      'hide_passwords = excluded.hide_passwords, manage = excluded.manage'
    )
    .bind(grant.collectionId, grant.membershipId, grant.readOnly ? 1 : 0, grant.hidePasswords ? 1 : 0, grant.manage ? 1 : 0);
}

// --- Cipher <-> collection links ---

export async function listCipherCollectionIds(db: D1Database, cipherIds: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  for (let i = 0; i < cipherIds.length; i += 90) {
    const chunk = cipherIds.slice(i, i + 90);
    const res = await db
      .prepare(`SELECT cipher_id, collection_id FROM cipher_collections WHERE cipher_id IN (${placeholders(chunk.length)})`)
      .bind(...chunk)
      .all<{ cipher_id: string; collection_id: string }>();
    for (const row of res.results || []) {
      const list = out.get(row.cipher_id) || [];
      list.push(row.collection_id);
      out.set(row.cipher_id, list);
    }
  }
  return out;
}

export function replaceCipherCollectionsStatements(db: D1Database, cipherId: string, collectionIds: string[]): D1PreparedStatement[] {
  return [
    db.prepare('DELETE FROM cipher_collections WHERE cipher_id = ?').bind(cipherId),
    ...collectionIds.map((collectionId) =>
      db
        .prepare('INSERT INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?) ON CONFLICT DO NOTHING')
        .bind(cipherId, collectionId)
    ),
  ];
}

export function addCipherCollectionStatement(db: D1Database, cipherId: string, collectionId: string): D1PreparedStatement {
  return db
    .prepare('INSERT INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?) ON CONFLICT DO NOTHING')
    .bind(cipherId, collectionId);
}

export function removeCipherCollectionStatement(db: D1Database, cipherId: string, collectionId: string): D1PreparedStatement {
  return db
    .prepare('DELETE FROM cipher_collections WHERE cipher_id = ? AND collection_id = ?')
    .bind(cipherId, collectionId);
}

// --- Per-user state of org ciphers ---

export interface CipherUserState {
  cipherId: string;
  userId: string;
  folderId: string | null;
  favorite: boolean;
  archivedAt: string | null;
}

export async function listCipherUserStates(db: D1Database, userId: string, cipherIds: string[]): Promise<Map<string, CipherUserState>> {
  const out = new Map<string, CipherUserState>();
  for (let i = 0; i < cipherIds.length; i += 90) {
    const chunk = cipherIds.slice(i, i + 90);
    const res = await db
      .prepare(
        `SELECT cipher_id, user_id, folder_id, favorite, archived_at FROM cipher_user_state WHERE user_id = ? AND cipher_id IN (${placeholders(chunk.length)})`
      )
      .bind(userId, ...chunk)
      .all<{ cipher_id: string; user_id: string; folder_id: string | null; favorite: number; archived_at: string | null }>();
    for (const row of res.results || []) {
      out.set(row.cipher_id, {
        cipherId: row.cipher_id,
        userId: row.user_id,
        folderId: row.folder_id,
        favorite: !!row.favorite,
        archivedAt: row.archived_at,
      });
    }
  }
  return out;
}

export function saveCipherUserStateStatement(db: D1Database, state: CipherUserState): D1PreparedStatement {
  return db
    .prepare(
      'INSERT INTO cipher_user_state(cipher_id, user_id, folder_id, favorite, archived_at) VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(cipher_id, user_id) DO UPDATE SET folder_id = excluded.folder_id, favorite = excluded.favorite, archived_at = excluded.archived_at'
    )
    .bind(state.cipherId, state.userId, state.folderId, state.favorite ? 1 : 0, state.archivedAt);
}

// Revision dates: every member of the org re-syncs after an org change.
export async function touchOrgMembersRevision(db: D1Database, orgId: string, date: string): Promise<string[]> {
  const userIds = await listMemberUserIds(db, orgId);
  if (!userIds.length) return [];
  await db.batch(
    userIds.map((userId) =>
      db
        .prepare(
          'INSERT INTO user_revisions(user_id, revision_date) VALUES(?, ?) ' +
          'ON CONFLICT(user_id) DO UPDATE SET revision_date = excluded.revision_date'
        )
        .bind(userId, date)
    )
  );
  return userIds;
}
