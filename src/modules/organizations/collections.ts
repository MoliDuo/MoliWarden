import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, forbidden, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { commit } from '../sync/changes';
import { canManageCollection, hasFullAccess, loadOrgContext, visibleCollections, type OrgContext } from './access';
import {
  deleteCollections,
  findCollection,
  listCollections,
  listMembers,
  listOrgGrants,
  MemberStatus,
  MemberType,
  replaceGrants,
  saveCollection,
  type Collection,
  type CollectionGrant,
  type Member,
} from './repo';
import { collectionDetailsJson, collectionJson, grantJson } from './responses';
import type { CollectionInput, CollectionUpdate, GrantInput } from './schemas';
import { now, orgChange, requireOrg } from './service';

// Collections and who may use them. Owners, admins and members with
// "access all" reach every collection, so grants name only the others.

const COLLECTION_NOT_FOUND = 'Collection not found';

// The collections the caller sees, across organizations.
export async function myCollections(deps: Deps, caller: Caller) {
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  return (await visibleCollections(deps.db, ctx)).map(collectionJson);
}

export async function orgCollections(deps: Deps, caller: Caller, orgId: string) {
  const { membership } = await requireOrg(deps.db, caller.user.id, orgId, 'manager');
  if (!hasFullAccess(membership)) throw notFound('Resource not found.');
  return (await listCollections(deps.db, [orgId])).map(collectionJson);
}

// A collection with its access list: the members granted it and, when
// `withFullAccess`, those who reach every collection.
function accessDetailsJson(
  collection: Collection,
  ctx: OrgContext,
  members: Member[],
  grants: CollectionGrant[],
  assigned: boolean,
  withFullAccess: boolean,
) {
  const typeOf = new Map(members.map((member) => [member.id, member.type]));
  const users = grants
    .filter((grant) => grant.collectionId === collection.id)
    .map((grant) => grantJson(grant, typeOf.get(grant.membershipId) ?? MemberType.User, 'member'));
  if (withFullAccess) {
    const listed = new Set(users.map((user) => user.id));
    for (const member of members) {
      if (listed.has(member.id) || member.status !== MemberStatus.Confirmed || !member.accessAll) continue;
      if (member.type !== MemberType.User) users.push({ id: member.id, readOnly: false, hidePasswords: false, manage: true });
    }
  }
  return { ...collectionDetailsJson(collection, ctx), assigned, users, groups: [], object: 'collectionAccessDetails' };
}

// Access lists are shown only for the collections the caller manages.
export async function orgCollectionDetails(deps: Deps, caller: Caller, orgId: string) {
  const { membership } = await requireOrg(deps.db, caller.user.id, orgId, 'manager');
  const [ctx, collections, members, grants] = await Promise.all([
    loadOrgContext(deps.db, caller.user.id),
    listCollections(deps.db, [orgId]),
    listMembers(deps.db, orgId),
    listOrgGrants(deps.db, orgId),
  ]);
  const full = hasFullAccess(membership);
  return collections
    .filter((collection) => full || ctx.grants.has(collection.id))
    .map((collection) => {
      const manageable = full || canManageCollection(ctx, orgId, collection.id);
      return { ...accessDetailsJson(collection, ctx, members, manageable ? grants : [], true, manageable), unmanaged: false };
    });
}

async function requireManageable(deps: Deps, caller: Caller, orgId: string, collectionIds: string[]) {
  const guarded = await requireOrg(deps.db, caller.user.id, orgId, 'manager');
  const ctx = await loadOrgContext(deps.db, caller.user.id);
  const collections: Collection[] = [];
  for (const id of collectionIds) {
    const collection = await findCollection(deps.db, orgId, id);
    if (!collection) throw notFound(COLLECTION_NOT_FOUND);
    if (!canManageCollection(ctx, orgId, id)) throw forbidden("You don't have permission to manage this collection");
    collections.push(collection);
  }
  return { ...guarded, ctx, collections };
}

export async function collectionDetails(deps: Deps, caller: Caller, orgId: string, collectionId: string) {
  const { membership, ctx, collections } = await requireManageable(deps, caller, orgId, [collectionId]);
  const [members, grants] = await Promise.all([listMembers(deps.db, orgId), listOrgGrants(deps.db, orgId)]);
  const assigned = hasFullAccess(membership) || ctx.grants.has(collectionId);
  return accessDetailsJson(collections[0]!, ctx, members, grants, assigned, false);
}

export async function collectionUsers(deps: Deps, caller: Caller, orgId: string, collectionId: string) {
  await requireManageable(deps, caller, orgId, [collectionId]);
  return (await listOrgGrants(deps.db, orgId))
    .filter((grant) => grant.collectionId === collectionId)
    .map(({ membershipId, readOnly, hidePasswords, manage }) => ({ id: membershipId, readOnly, hidePasswords, manage }));
}

// Grants to the members named; members with "access all" need none.
async function collectionGrants(db: Executor, orgId: string, collectionIds: string[], users: GrantInput[]): Promise<CollectionGrant[]> {
  if (!users.length) return [];
  const members = new Map((await listMembers(db, orgId)).map((member) => [member.id, member]));
  const granted = users.filter((user) => {
    const member = members.get(user.id);
    if (!member) throw badRequest('Invalid member');
    return !member.accessAll;
  });
  return collectionIds.flatMap((collectionId) => granted.map((user) => ({ ...user, collectionId, membershipId: user.id })));
}

export async function createCollection(deps: Deps, caller: Caller, orgId: string, input: CollectionInput) {
  const { membership } = await requireOrg(deps.db, caller.user.id, orgId, 'manager');
  if (membership.type === MemberType.Manager && !membership.accessAll) {
    throw forbidden("You don't have permission to create collections");
  }
  const date = now();
  const collection: Collection = { id: randomUUID(), orgId, name: input.name, externalId: input.externalId ?? null, createdAt: date, updatedAt: date };
  const grants = await collectionGrants(deps.db, orgId, [collection.id], input.users ?? []);
  await commit(deps, caller, date, orgChange(orgId), async (tx) => {
    await saveCollection(tx, collection);
    await replaceGrants(tx, { collectionIds: [] }, grants);
  });
  return collectionDetailsJson(collection, await loadOrgContext(deps.db, caller.user.id));
}

// Fields left out keep their values; `users`, when given, replaces the
// access list.
export async function updateCollection(deps: Deps, caller: Caller, orgId: string, collectionId: string, input: CollectionUpdate) {
  const { ctx, collections } = await requireManageable(deps, caller, orgId, [collectionId]);
  const date = now();
  const current = collections[0]!;
  const collection = {
    ...current,
    name: input.name ?? current.name,
    externalId: input.externalId === undefined ? current.externalId : input.externalId,
    updatedAt: date,
  };
  const grants = input.users && (await collectionGrants(deps.db, orgId, [collectionId], input.users));
  await commit(deps, caller, date, orgChange(orgId), async (tx) => {
    await saveCollection(tx, collection);
    if (grants) await replaceGrants(tx, { collectionIds: [collectionId] }, grants);
  });
  return collectionDetailsJson(collection, ctx);
}

// Gives several collections the same access list.
export async function setCollectionsAccess(deps: Deps, caller: Caller, orgId: string, collectionIds: string[], users: GrantInput[]) {
  await requireManageable(deps, caller, orgId, collectionIds);
  const grants = await collectionGrants(deps.db, orgId, collectionIds, users);
  await commit(deps, caller, now(), orgChange(orgId), (tx) => replaceGrants(tx, { collectionIds }, grants));
}

// The ciphers stay in the organization.
export async function deleteOrgCollections(deps: Deps, caller: Caller, orgId: string, collectionIds: string[]) {
  await requireManageable(deps, caller, orgId, collectionIds);
  await commit(deps, caller, now(), orgChange(orgId), (tx) => deleteCollections(tx, orgId, collectionIds));
}
