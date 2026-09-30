import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';

// Organizations, their members and collections, and which collections hold
// which ciphers.

export const MemberStatus = { Revoked: -1, Invited: 0, Accepted: 1, Confirmed: 2 } as const;
export const MemberType = { Owner: 0, Admin: 1, User: 2, Manager: 3 } as const;

export interface Organization {
  id: string;
  name: string;
  billingEmail: string;
  publicKey: string | null;
  // Encrypted with the organization key.
  privateKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Membership {
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

// A membership as the organization's admins see it.
export interface Member extends Membership {
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

// What a member may do with the ciphers of one collection.
export interface CollectionGrant {
  collectionId: string;
  membershipId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

function toOrganization(row: Row<'organizations'>): Organization {
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

export function toMembership(row: Row<'memberships'>): Membership {
  return {
    id: row.id,
    orgId: row.organization_id,
    userId: row.user_id,
    status: row.status,
    type: row.type,
    accessAll: row.access_all,
    akey: row.key,
    revokedStatus: row.revoked_status,
    invitedBy: row.invited_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toCollection(row: Row<'collections'>): Collection {
  return {
    id: row.id,
    orgId: row.organization_id,
    name: row.name,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toGrant(row: Row<'collection_grants'>): CollectionGrant {
  return {
    collectionId: row.collection_id,
    membershipId: row.membership_id,
    readOnly: row.read_only,
    hidePasswords: row.hide_passwords,
    manage: row.manage,
  };
}

// --- Organizations ---

export async function findOrganization(db: Executor, id: string): Promise<Organization | null> {
  const row = await db.selectFrom('organizations').selectAll().where('id', '=', id).executeTakeFirst();
  return row ? toOrganization(row) : null;
}

export async function listOrganizations(db: Executor, ids: string[]): Promise<Organization[]> {
  if (!ids.length) return [];
  const rows = await db
    .selectFrom('organizations')
    .selectAll()
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
  return rows.map(toOrganization);
}

export async function saveOrganization(db: Executor, org: Organization): Promise<void> {
  const values = {
    name: org.name,
    billing_email: org.billingEmail,
    public_key: org.publicKey,
    private_key: org.privateKey,
    updated_at: org.updatedAt,
  };
  await db
    .insertInto('organizations')
    .values({ id: org.id, created_at: org.createdAt, ...values })
    .onConflict((oc) => oc.column('id').doUpdateSet(values))
    .execute();
}

// Memberships, collections, grants and the organization's ciphers go with it.
export async function deleteOrganization(db: Executor, id: string): Promise<void> {
  await db.deleteFrom('organizations').where('id', '=', id).execute();
}

// --- Memberships ---

export async function findMembership(db: Executor, id: string): Promise<Membership | null> {
  const row = await db.selectFrom('memberships').selectAll().where('id', '=', id).executeTakeFirst();
  return row ? toMembership(row) : null;
}

export async function findMembershipOf(db: Executor, orgId: string, userId: string): Promise<Membership | null> {
  const row = await db
    .selectFrom('memberships')
    .selectAll()
    .where('organization_id', '=', orgId)
    .where('user_id', '=', userId)
    .executeTakeFirst();
  return row ? toMembership(row) : null;
}

export async function listMembers(db: Executor, orgId: string): Promise<Member[]> {
  const rows = await db
    .selectFrom('memberships as m')
    .innerJoin('users as u', 'u.id', 'm.user_id')
    .selectAll('m')
    .select((eb) => [
      'u.email',
      'u.name',
      'u.public_key as user_public_key',
      eb
        .or([
          eb.exists(eb.selectFrom('two_factor_providers as p').select('p.user_id').whereRef('p.user_id', '=', 'u.id')),
          eb.exists(
            eb
              .selectFrom('webauthn_credentials as w')
              .select('w.id')
              .whereRef('w.user_id', '=', 'u.id')
              .where('w.purpose', '=', 'twoFactor'),
          ),
        ])
        .as('has_two_factor'),
    ])
    .where('m.organization_id', '=', orgId)
    .orderBy('m.created_at')
    .execute();
  return rows.map((row) => ({
    ...toMembership(row),
    email: row.email,
    name: row.name,
    publicKey: row.user_public_key,
    hasTwoFactor: row.has_two_factor === true,
  }));
}

export async function countOwners(db: Executor, orgId: string): Promise<number> {
  const row = await db
    .selectFrom('memberships')
    .select((eb) => eb.fn.countAll<string>().as('count'))
    .where('organization_id', '=', orgId)
    .where('type', '=', MemberType.Owner)
    .where('status', '=', MemberStatus.Confirmed)
    .executeTakeFirstOrThrow();
  return Number(row.count);
}

export async function saveMemberships(db: Executor, memberships: Membership[]): Promise<void> {
  if (!memberships.length) return;
  await db
    .insertInto('memberships')
    .values(
      memberships.map((membership) => ({
        id: membership.id,
        organization_id: membership.orgId,
        user_id: membership.userId,
        status: membership.status,
        type: membership.type,
        access_all: membership.accessAll,
        key: membership.akey,
        revoked_status: membership.revokedStatus,
        invited_by: membership.invitedBy,
        created_at: membership.createdAt,
        updated_at: membership.updatedAt,
      })),
    )
    .onConflict((oc) =>
      oc.column('id').doUpdateSet((eb) => ({
        status: eb.ref('excluded.status'),
        type: eb.ref('excluded.type'),
        access_all: eb.ref('excluded.access_all'),
        key: eb.ref('excluded.key'),
        revoked_status: eb.ref('excluded.revoked_status'),
        updated_at: eb.ref('excluded.updated_at'),
      })),
    )
    .execute();
}

export async function deleteMembership(db: Executor, id: string): Promise<void> {
  await db.deleteFrom('memberships').where('id', '=', id).execute();
}

export async function listUserMemberships(db: Executor, userId: string): Promise<Membership[]> {
  const rows = await db.selectFrom('memberships').selectAll().where('user_id', '=', userId).orderBy('created_at').execute();
  return rows.map(toMembership);
}

// --- Collections and grants ---

export async function findCollection(db: Executor, orgId: string, id: string): Promise<Collection | null> {
  const row = await db.selectFrom('collections').selectAll().where('id', '=', id).where('organization_id', '=', orgId).executeTakeFirst();
  return row ? toCollection(row) : null;
}

export async function listOrgGrants(db: Executor, orgId: string): Promise<CollectionGrant[]> {
  const rows = await db
    .selectFrom('collection_grants as g')
    .innerJoin('collections as c', 'c.id', 'g.collection_id')
    .selectAll('g')
    .where('c.organization_id', '=', orgId)
    .execute();
  return rows.map(toGrant);
}

export async function listGrants(db: Executor, membershipIds: string[]): Promise<CollectionGrant[]> {
  if (!membershipIds.length) return [];
  const rows = await db
    .selectFrom('collection_grants')
    .selectAll()
    .where((eb) => eb('membership_id', '=', eb.fn.any(eb.val(membershipIds))))
    .execute();
  return rows.map(toGrant);
}

export async function listCollections(db: Executor, orgIds: string[]): Promise<Collection[]> {
  if (!orgIds.length) return [];
  const rows = await db
    .selectFrom('collections')
    .selectAll()
    .where((eb) => eb('organization_id', '=', eb.fn.any(eb.val(orgIds))))
    .orderBy('created_at')
    .execute();
  return rows.map(toCollection);
}

export async function insertCollections(db: Executor, collections: Collection[]): Promise<void> {
  if (!collections.length) return;
  await db
    .insertInto('collections')
    .values(
      collections.map((collection) => ({
        id: collection.id,
        organization_id: collection.orgId,
        name: collection.name,
        external_id: collection.externalId,
        created_at: collection.createdAt,
        updated_at: collection.updatedAt,
      })),
    )
    .execute();
}

export async function saveCollection(db: Executor, collection: Collection): Promise<void> {
  const values = { name: collection.name, external_id: collection.externalId, updated_at: collection.updatedAt };
  await db
    .insertInto('collections')
    .values({ id: collection.id, organization_id: collection.orgId, created_at: collection.createdAt, ...values })
    .onConflict((oc) => oc.column('id').doUpdateSet(values).where('collections.organization_id', '=', collection.orgId))
    .execute();
}

// Ciphers stay in the organization; only their links to the collections go.
export async function deleteCollections(db: Executor, orgId: string, ids: string[]): Promise<void> {
  if (!ids.length) return;
  await db
    .deleteFrom('collections')
    .where('organization_id', '=', orgId)
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .execute();
}

// Replaces the grants of the given memberships (or collections) with
// `grants`. A grant only links a collection and a membership of the same
// organization.
export async function replaceGrants(
  db: Executor,
  scope: { membershipIds: string[] } | { collectionIds: string[] },
  grants: CollectionGrant[],
): Promise<void> {
  const [column, ids] =
    'membershipIds' in scope ? (['membership_id', scope.membershipIds] as const) : (['collection_id', scope.collectionIds] as const);
  if (ids.length) {
    await db
      .deleteFrom('collection_grants')
      .where((eb) => eb(column, '=', eb.fn.any(eb.val(ids))))
      .execute();
  }
  if (!grants.length) return;
  await sql`
    INSERT INTO collection_grants (collection_id, membership_id, read_only, hide_passwords, manage)
    SELECT col.id, m.id, g.read_only, g.hide_passwords, g.manage
    FROM unnest(
      ${grants.map((grant) => grant.collectionId)}::uuid[],
      ${grants.map((grant) => grant.membershipId)}::uuid[],
      ${grants.map((grant) => grant.readOnly)}::boolean[],
      ${grants.map((grant) => grant.hidePasswords)}::boolean[],
      ${grants.map((grant) => grant.manage)}::boolean[]
    ) AS g(collection_id, membership_id, read_only, hide_passwords, manage)
    JOIN collections col ON col.id = g.collection_id
    JOIN memberships m ON m.id = g.membership_id AND m.organization_id = col.organization_id
    ON CONFLICT (collection_id, membership_id) DO UPDATE SET
      read_only = excluded.read_only, hide_passwords = excluded.hide_passwords, manage = excluded.manage`.execute(db);
}

// cipher id -> the collections holding it.
export async function listCipherCollections(db: Executor, cipherIds: string[]): Promise<Map<string, string[]>> {
  const links = new Map<string, string[]>();
  if (!cipherIds.length) return links;
  const rows = await db
    .selectFrom('cipher_collections')
    .select(['cipher_id', 'collection_id'])
    .where((eb) => eb('cipher_id', '=', eb.fn.any(eb.val(cipherIds))))
    .orderBy('collection_id')
    .execute();
  for (const row of rows) {
    const list = links.get(row.cipher_id);
    if (list) list.push(row.collection_id);
    else links.set(row.cipher_id, [row.collection_id]);
  }
  return links;
}

// Links a cipher only to collections of the organization owning it at write
// time, so a racing move to another organization cannot cross-link them.
export async function addCipherCollections(db: Executor, links: Array<{ cipherId: string; collectionId: string }>): Promise<void> {
  if (!links.length) return;
  const cipherIds = links.map((link) => link.cipherId);
  const collectionIds = links.map((link) => link.collectionId);
  await sql`
    INSERT INTO cipher_collections (cipher_id, collection_id)
    SELECT c.id, col.id
    FROM unnest(${cipherIds}::uuid[], ${collectionIds}::uuid[]) AS link(cipher_id, collection_id)
    JOIN ciphers c ON c.id = link.cipher_id
    JOIN collections col ON col.id = link.collection_id AND col.organization_id = c.organization_id
    ON CONFLICT DO NOTHING`.execute(db);
}

export async function removeCipherCollections(db: Executor, cipherIds: string[], collectionIds: string[]): Promise<void> {
  if (!cipherIds.length || !collectionIds.length) return;
  await db
    .deleteFrom('cipher_collections')
    .where((eb) => eb.and([eb('cipher_id', '=', eb.fn.any(eb.val(cipherIds))), eb('collection_id', '=', eb.fn.any(eb.val(collectionIds)))]))
    .execute();
}

// Everyone who can see the organization's ciphers resyncs after a change.
export async function touchMemberRevisions(db: Executor, orgId: string, date: string): Promise<string[]> {
  const rows = await db
    .updateTable('users')
    .set({ revision_date: date })
    .from('memberships')
    .whereRef('memberships.user_id', '=', 'users.id')
    .where('memberships.organization_id', '=', orgId)
    .where('memberships.status', '=', MemberStatus.Confirmed)
    .returning('users.id')
    .execute();
  return rows.map((row) => row.id);
}
