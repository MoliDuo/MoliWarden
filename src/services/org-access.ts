import type { Cipher } from '../types';
import {
  type Collection,
  type CollectionGrant,
  listCollectionsByOrgIds,
  type OrgMembership,
  listCipherCollectionIds,
  listGrantsByMemberships,
  listMembershipsByUser,
  ORG_MEMBER_STATUS,
  ORG_MEMBER_TYPE,
} from './storage-org-repo';

// Central authorization for organization data.
//
// Rules (mirroring Bitwarden / Vaultwarden):
// - Only CONFIRMED memberships grant access to org ciphers and collections.
//   Invited / accepted members do not hold the org key yet; revoked members
//   (status -1) keep their row but lose all access.
// - Owners, admins and members with access_all see every collection and
//   cipher of the org, with full edit / view-password / manage rights.
// - Everyone else sees ciphers through collection grants; the most
//   permissive grant among the cipher's collections wins.

export interface UserOrgContext {
  userId: string;
  memberships: OrgMembership[];
  confirmedByOrg: Map<string, OrgMembership>;
  grantsByCollection: Map<string, CollectionGrant>;
}

export interface CipherAccess {
  personal: boolean;
  orgId: string | null;
  edit: boolean;
  viewPassword: boolean;
  manage: boolean;
  collectionIds: string[];
}

export function isOrgAdminType(type: number): boolean {
  return type === ORG_MEMBER_TYPE.OWNER || type === ORG_MEMBER_TYPE.ADMIN;
}

export function hasFullOrgAccess(membership: OrgMembership): boolean {
  return membership.status === ORG_MEMBER_STATUS.CONFIRMED && (isOrgAdminType(membership.type) || membership.accessAll);
}

export async function loadUserOrgContext(db: D1Database, userId: string): Promise<UserOrgContext> {
  const memberships = await listMembershipsByUser(db, userId);
  const confirmedByOrg = new Map<string, OrgMembership>();
  for (const membership of memberships) {
    if (membership.status === ORG_MEMBER_STATUS.CONFIRMED) {
      confirmedByOrg.set(membership.orgId, membership);
    }
  }
  const limited = Array.from(confirmedByOrg.values()).filter((membership) => !hasFullOrgAccess(membership));
  const grants = await listGrantsByMemberships(db, limited.map((membership) => membership.id));
  const grantsByCollection = new Map<string, CollectionGrant>();
  for (const grant of grants) grantsByCollection.set(grant.collectionId, grant);
  return { userId, memberships, confirmedByOrg, grantsByCollection };
}

export function fullAccessOrgIds(ctx: UserOrgContext): string[] {
  return Array.from(ctx.confirmedByOrg.values()).filter(hasFullOrgAccess).map((membership) => membership.orgId);
}

export function grantedCollectionIds(ctx: UserOrgContext): string[] {
  return Array.from(ctx.grantsByCollection.keys());
}

// Access of the user to one cipher, or null when it must stay invisible.
export function computeCipherAccess(ctx: UserOrgContext, cipher: Cipher, cipherCollectionIds: string[]): CipherAccess | null {
  const orgId = cipher.organizationId || null;
  if (!orgId) {
    if (cipher.userId !== ctx.userId) return null;
    return { personal: true, orgId: null, edit: true, viewPassword: true, manage: true, collectionIds: [] };
  }

  const membership = ctx.confirmedByOrg.get(orgId);
  if (!membership) return null;

  if (hasFullOrgAccess(membership)) {
    return {
      personal: false,
      orgId,
      edit: true,
      viewPassword: true,
      manage: true,
      collectionIds: cipherCollectionIds,
    };
  }

  let visible = false;
  let edit = false;
  let viewPassword = false;
  let manage = false;
  const visibleCollectionIds: string[] = [];
  for (const collectionId of cipherCollectionIds) {
    const grant = ctx.grantsByCollection.get(collectionId);
    if (!grant) continue;
    visible = true;
    visibleCollectionIds.push(collectionId);
    if (!grant.readOnly) edit = true;
    if (!grant.hidePasswords) viewPassword = true;
    // Managers manage every collection they can fully edit.
    if (grant.manage || (membership.type === ORG_MEMBER_TYPE.MANAGER && !grant.readOnly && !grant.hidePasswords)) {
      manage = true;
    }
  }
  if (!visible) return null;
  return { personal: false, orgId, edit, viewPassword, manage, collectionIds: visibleCollectionIds };
}

export async function getCipherAccess(
  db: D1Database,
  ctx: UserOrgContext,
  cipher: Cipher | null
): Promise<CipherAccess | null> {
  if (!cipher) return null;
  if (!cipher.organizationId) return computeCipherAccess(ctx, cipher, []);
  const links = await listCipherCollectionIds(db, [cipher.id]);
  return computeCipherAccess(ctx, cipher, links.get(cipher.id) || []);
}

// Collections a member may assign ciphers to / edit contents of.
export function canWriteCollection(ctx: UserOrgContext, orgId: string, collectionId: string): boolean {
  const membership = ctx.confirmedByOrg.get(orgId);
  if (!membership) return false;
  if (hasFullOrgAccess(membership)) return true;
  const grant = ctx.grantsByCollection.get(collectionId);
  return !!grant && !grant.readOnly;
}

export function canManageCollection(ctx: UserOrgContext, orgId: string, collectionId: string): boolean {
  const membership = ctx.confirmedByOrg.get(orgId);
  if (!membership) return false;
  if (isOrgAdminType(membership.type)) return true;
  if (membership.type === ORG_MEMBER_TYPE.MANAGER && membership.accessAll) return true;
  const grant = ctx.grantsByCollection.get(collectionId);
  if (!grant) return false;
  return grant.manage || (membership.type === ORG_MEMBER_TYPE.MANAGER && !grant.readOnly && !grant.hidePasswords);
}

// Collections shown to a member: all of a full-access org, otherwise the
// ones the member holds a grant for (confirmed memberships only).
export async function loadVisibleCollections(db: D1Database, ctx: UserOrgContext): Promise<Collection[]> {
  const orgIds = Array.from(ctx.confirmedByOrg.keys());
  if (!orgIds.length) return [];
  const all = await listCollectionsByOrgIds(db, orgIds);
  return all.filter((collection) => {
    const membership = ctx.confirmedByOrg.get(collection.orgId);
    if (!membership) return false;
    return hasFullOrgAccess(membership) || ctx.grantsByCollection.has(collection.id);
  });
}
