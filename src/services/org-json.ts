import type { UserOrgContext } from './org-access';
import { hasFullOrgAccess } from './org-access';
import {
  type Collection,
  type CollectionGrant,
  type OrgMembership,
  type OrgMembershipWithUser,
  type Organization,
  ORG_MEMBER_STATUS,
  ORG_MEMBER_TYPE,
} from './storage-org-repo';

// Bitwarden API response shapes for organizations. Field lists follow the
// official server's response models as served by Vaultwarden.

// Bitwarden clients no longer know the legacy Manager (3) type; it is exposed
// as Custom (4) and mapped back on input.
export function outboundMemberType(type: number): number {
  return type === ORG_MEMBER_TYPE.MANAGER ? ORG_MEMBER_TYPE.CUSTOM : type;
}

export function outboundMemberStatus(status: number): number {
  return status < ORG_MEMBER_STATUS.REVOKED ? ORG_MEMBER_STATUS.REVOKED : status;
}

function customPermissions(membership: OrgMembership): Record<string, boolean> {
  const collectionAdmin = membership.type === ORG_MEMBER_TYPE.MANAGER && membership.accessAll;
  return {
    accessEventLogs: false,
    accessImportExport: false,
    accessReports: false,
    createNewCollections: collectionAdmin,
    editAnyCollection: collectionAdmin,
    deleteAnyCollection: collectionAdmin,
    manageGroups: false,
    managePolicies: false,
    manageSso: false,
    manageUsers: false,
    manageResetPassword: false,
    manageScim: false,
  };
}

const ORG_FEATURE_FLAGS = {
  use2fa: true,
  useCustomPermissions: true,
  useDirectory: false,
  useEvents: false,
  useGroups: false,
  useTotp: true,
  usePolicies: false,
  useScim: false,
  useSso: false,
  useKeyConnector: false,
  usePasswordManager: true,
  useSecretsManager: false,
  selfHost: true,
  useApi: false,
  useDisableSMAdsForUsers: true,
  useInviteLinks: false,
  useMyItems: false,
  useOrganizationDomains: false,
  usePam: false,
  usePhishingBlocker: false,
  useResetPassword: false,
  useRiskInsights: false,
  useActivateAutofillPolicy: false,
  useAdminSponsoredFamilies: false,
  usersGetPremium: true,
  maxStorageGb: 32767,
  maxCollections: null,
};

export function organizationJson(org: Organization): Record<string, unknown> {
  return {
    id: org.id,
    name: org.name,
    seats: null,
    ...ORG_FEATURE_FLAGS,
    hasPublicAndPrivateKeys: !!(org.publicKey && org.privateKey),
    allowAdminAccessToAllCollectionItems: true,
    limitCollectionCreation: true,
    limitCollectionDeletion: false,
    limitItemDeletion: false,
    businessName: org.name,
    businessAddress1: null,
    businessAddress2: null,
    businessAddress3: null,
    businessCountry: null,
    businessTaxNumber: null,
    maxAutoscaleSeats: null,
    maxAutoscaleSmSeats: null,
    maxAutoscaleSmServiceAccounts: null,
    secretsManagerPlan: null,
    smSeats: null,
    smServiceAccounts: null,
    billingEmail: org.billingEmail,
    planType: 6,
    object: 'organization',
  };
}

// Entry of profile.organizations (the member's own view of an org).
export function profileOrganizationJson(membership: OrgMembership, org: Organization): Record<string, unknown> {
  return {
    id: org.id,
    identifier: null,
    name: org.name,
    seats: 20,
    ...ORG_FEATURE_FLAGS,
    hasPublicAndPrivateKeys: !!(org.publicKey && org.privateKey),
    resetPasswordEnrolled: false,
    ssoBound: false,
    organizationUserId: membership.id,
    providerId: null,
    providerName: null,
    providerType: null,
    familySponsorshipFriendlyName: null,
    familySponsorshipAvailable: false,
    productTierType: 3,
    keyConnectorEnabled: false,
    keyConnectorUrl: null,
    familySponsorshipLastSyncDate: null,
    familySponsorshipValidUntil: null,
    familySponsorshipToDelete: null,
    accessSecretsManager: false,
    limitCollectionCreation: membership.type === ORG_MEMBER_TYPE.USER || !membership.accessAll,
    limitCollectionDeletion: false,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsManagedByOrganization: false,
    userIsClaimedByOrganization: false,
    permissions: customPermissions(membership),
    userId: membership.userId,
    key: membership.akey,
    status: outboundMemberStatus(membership.status),
    type: outboundMemberType(membership.type),
    enabled: true,
    object: 'profileOrganization',
  };
}

// profile.organizations only lists confirmed memberships (the member holds
// the org key); organizationsNew also includes accepted ones.
export function buildProfileOrganizations(
  memberships: OrgMembership[],
  orgsById: Map<string, Organization>
): { organizations: Record<string, unknown>[]; organizationsNew: Record<string, unknown>[] } {
  const organizations: Record<string, unknown>[] = [];
  const organizationsNew: Record<string, unknown>[] = [];
  for (const membership of memberships) {
    const org = orgsById.get(membership.orgId);
    if (!org) continue;
    if (membership.status === ORG_MEMBER_STATUS.CONFIRMED) {
      organizations.push(profileOrganizationJson(membership, org));
    }
    if (membership.status === ORG_MEMBER_STATUS.CONFIRMED || membership.status === ORG_MEMBER_STATUS.ACCEPTED) {
      organizationsNew.push(profileOrganizationJson(membership, org));
    }
  }
  return { organizations, organizationsNew };
}

export function collectionJson(collection: Collection): Record<string, unknown> {
  return {
    externalId: collection.externalId,
    id: collection.id,
    organizationId: collection.orgId,
    name: collection.name,
    type: 0,
    defaultUserCollectionEmail: null,
    object: 'collection',
  };
}

// Collection as seen by the member described by ctx.
export function collectionDetailsJson(collection: Collection, ctx: UserOrgContext): Record<string, unknown> {
  const membership = ctx.confirmedByOrg.get(collection.orgId);
  let readOnly = true;
  let hidePasswords = true;
  let manage = false;
  if (membership) {
    if (hasFullOrgAccess(membership)) {
      readOnly = false;
      hidePasswords = false;
      manage = membership.type !== ORG_MEMBER_TYPE.USER;
    } else {
      const grant = ctx.grantsByCollection.get(collection.id);
      if (grant) {
        readOnly = grant.readOnly;
        hidePasswords = grant.hidePasswords;
        manage = grant.manage || (membership.type === ORG_MEMBER_TYPE.MANAGER && !grant.readOnly && !grant.hidePasswords);
      } else {
        readOnly = false;
        hidePasswords = false;
      }
    }
  }
  return {
    ...collectionJson(collection),
    readOnly,
    hidePasswords,
    manage,
    object: 'collectionDetails',
  };
}

export function grantJson(grant: CollectionGrant, memberType: number, idField: 'collection' | 'member'): Record<string, unknown> {
  return {
    id: idField === 'collection' ? grant.collectionId : grant.membershipId,
    readOnly: grant.readOnly,
    hidePasswords: grant.hidePasswords,
    manage:
      memberType === ORG_MEMBER_TYPE.OWNER ||
      memberType === ORG_MEMBER_TYPE.ADMIN ||
      grant.manage ||
      (memberType === ORG_MEMBER_TYPE.MANAGER && !grant.readOnly && !grant.hidePasswords),
  };
}

// Admin view of a member (organizationUserUserDetails).
export function memberDetailsJson(
  member: OrgMembershipWithUser,
  grants: CollectionGrant[],
  includeCollections: boolean
): Record<string, unknown> {
  const unrevokedStatus = member.status === ORG_MEMBER_STATUS.REVOKED ? member.revokedStatus ?? ORG_MEMBER_STATUS.ACCEPTED : member.status;
  const outboundType = outboundMemberType(member.type);
  return {
    id: member.id,
    userId: member.userId,
    name: unrevokedStatus >= ORG_MEMBER_STATUS.ACCEPTED ? member.name : null,
    email: member.email,
    externalId: null,
    avatarColor: null,
    groups: [],
    collections: includeCollections && !member.accessAll ? grants.map((grant) => grantJson(grant, member.type, 'collection')) : [],
    status: outboundMemberStatus(member.status),
    type: outboundType,
    accessAll: member.accessAll,
    twoFactorEnabled: member.hasTwoFactor,
    resetPasswordEnrolled: false,
    hasMasterPassword: true,
    permissions: outboundType === ORG_MEMBER_TYPE.CUSTOM && member.accessAll ? customPermissions(member) : null,
    ssoBound: false,
    managedByOrganization: false,
    claimedByOrganization: false,
    usesKeyConnector: false,
    accessSecretsManager: false,
    object: 'organizationUserUserDetails',
  };
}

export function memberMiniJson(member: OrgMembershipWithUser): Record<string, unknown> {
  return {
    id: member.id,
    userId: member.userId,
    type: outboundMemberType(member.type),
    status: outboundMemberStatus(member.status),
    name: member.name,
    email: member.email,
    object: 'organizationUserUserMiniDetails',
  };
}

export function listJson(data: unknown[]): Record<string, unknown> {
  return { data, object: 'list', continuationToken: null };
}
