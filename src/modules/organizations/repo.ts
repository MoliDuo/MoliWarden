import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';

// Organizations, their members and collections, and which collections hold
// which ciphers.

export const MemberStatus = { Revoked: -1, Invited: 0, Accepted: 1, Confirmed: 2 } as const;
export const MemberType = { Owner: 0, Admin: 1, User: 2, Manager: 3 } as const;

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

export function toMembership(row: Row<'org_memberships'>): Membership {
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

function toCollection(row: Row<'collections'>): Collection {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toGrant(row: Row<'collection_members'>): CollectionGrant {
  return {
    collectionId: row.collection_id,
    membershipId: row.membership_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  };
}

export async function listUserMemberships(db: Executor, userId: string): Promise<Membership[]> {
  const rows = await db.selectFrom('org_memberships').selectAll().where('user_id', '=', userId).orderBy('created_at').execute();
  return rows.map(toMembership);
}

export async function listGrants(db: Executor, membershipIds: string[]): Promise<CollectionGrant[]> {
  if (!membershipIds.length) return [];
  const rows = await db
    .selectFrom('collection_members')
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
    .where((eb) => eb('org_id', '=', eb.fn.any(eb.val(orgIds))))
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
        org_id: collection.orgId,
        name: collection.name,
        external_id: collection.externalId,
        created_at: collection.createdAt,
        updated_at: collection.updatedAt,
      })),
    )
    .execute();
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
    FROM unnest(${cipherIds}::text[], ${collectionIds}::text[]) AS link(cipher_id, collection_id)
    JOIN ciphers c ON c.id = link.cipher_id
    JOIN collections col ON col.id = link.collection_id AND col.org_id = c.organization_id
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
    .insertInto('user_revisions')
    .columns(['user_id', 'revision_date'])
    .expression((eb) =>
      eb
        .selectFrom('org_memberships')
        .select(['user_id', eb.val(date).as('revision_date')])
        .where('org_id', '=', orgId)
        .where('status', '=', MemberStatus.Confirmed),
    )
    .onConflict((oc) => oc.column('user_id').doUpdateSet({ revision_date: date }))
    .returning('user_id')
    .execute();
  return rows.map((row) => row.user_id);
}
