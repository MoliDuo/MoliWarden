import type { Executor } from '../../platform/db';
import {
  listCollections,
  listGrants,
  listUserMemberships,
  MemberStatus,
  MemberType,
  type Collection,
  type CollectionGrant,
  type Membership,
} from './repo';

// Who may see and change what in an organization (as Bitwarden does it):
// - Only confirmed members hold the organization key; invited, accepted and
//   revoked members see nothing.
// - Owners, admins and members with "access all" see every collection with
//   full rights.
// - Everyone else sees ciphers through their collection grants; the most
//   generous grant among a cipher's collections applies.

export interface OrgContext {
  userId: string;
  memberships: Membership[];
  confirmed: Map<string, Membership>;
  grants: Map<string, CollectionGrant>;
}

export interface CipherAccess {
  edit: boolean;
  viewPassword: boolean;
  manage: boolean;
  // The collections holding the cipher that the user can see.
  collectionIds: string[];
}

export const FULL_ACCESS: CipherAccess = { edit: true, viewPassword: true, manage: true, collectionIds: [] };

export const isAdminType = (type: number) => type === MemberType.Owner || type === MemberType.Admin;

export const hasFullAccess = (membership: Membership) =>
  membership.status === MemberStatus.Confirmed && (isAdminType(membership.type) || membership.accessAll);

export async function loadOrgContext(db: Executor, userId: string): Promise<OrgContext> {
  const memberships = await listUserMemberships(db, userId);
  const confirmed = new Map(memberships.filter((m) => m.status === MemberStatus.Confirmed).map((m) => [m.orgId, m]));
  const limited = [...confirmed.values()].filter((m) => !hasFullAccess(m)).map((m) => m.id);
  const grants = new Map((await listGrants(db, limited)).map((grant) => [grant.collectionId, grant]));
  return { userId, memberships, confirmed, grants };
}

export const confirmedOrgIds = (ctx: OrgContext) => [...ctx.confirmed.keys()];

export const fullAccessOrgIds = (ctx: OrgContext) =>
  [...ctx.confirmed.values()].filter(hasFullAccess).map((membership) => membership.orgId);

export const grantedCollectionIds = (ctx: OrgContext) => [...ctx.grants.keys()];

export function hasFullAccessTo(ctx: OrgContext, orgId: string): boolean {
  const membership = ctx.confirmed.get(orgId);
  return !!membership && hasFullAccess(membership);
}

// Managers manage the collections they can fully use.
function manages(membership: Membership, grant: CollectionGrant): boolean {
  return grant.manage || (membership.type === MemberType.Manager && !grant.readOnly && !grant.hidePasswords);
}

// The user's access to an organization cipher, or null when it is hidden.
export function orgCipherAccess(ctx: OrgContext, orgId: string, collectionIds: string[]): CipherAccess | null {
  const membership = ctx.confirmed.get(orgId);
  if (!membership) return null;
  if (hasFullAccess(membership)) return { ...FULL_ACCESS, collectionIds };

  const visible = collectionIds.filter((id) => ctx.grants.has(id));
  if (!visible.length) return null;
  const grants = visible.map((id) => ctx.grants.get(id)!);
  return {
    edit: grants.some((grant) => !grant.readOnly),
    viewPassword: grants.some((grant) => !grant.hidePasswords),
    manage: grants.some((grant) => manages(membership, grant)),
    collectionIds: visible,
  };
}

// Collections the user may put ciphers into or take them out of.
export function canWriteCollection(ctx: OrgContext, orgId: string, collectionId: string): boolean {
  const membership = ctx.confirmed.get(orgId);
  if (!membership) return false;
  if (hasFullAccess(membership)) return true;
  const grant = ctx.grants.get(collectionId);
  return !!grant && !grant.readOnly;
}

export function canManageCollection(ctx: OrgContext, orgId: string, collectionId: string): boolean {
  const membership = ctx.confirmed.get(orgId);
  if (!membership) return false;
  if (isAdminType(membership.type) || (membership.type === MemberType.Manager && membership.accessAll)) return true;
  const grant = ctx.grants.get(collectionId);
  return !!grant && manages(membership, grant);
}

// All collections of an organization with full access, otherwise the granted ones.
export async function visibleCollections(db: Executor, ctx: OrgContext): Promise<Collection[]> {
  const all = await listCollections(db, confirmedOrgIds(ctx));
  return all.filter((collection) => hasFullAccessTo(ctx, collection.orgId) || ctx.grants.has(collection.id));
}
