import { hasFullAccessTo, isAdminType, type OrgContext } from './access';
import {
  MemberStatus,
  MemberType,
  type Collection,
  type CollectionGrant,
  type Member,
  type Membership,
  type Organization,
} from './repo';

// Bitwarden's response shapes for organizations, with the features this
// server has.

// Clients no longer know the Manager type (3); it is shown as Custom (4)
// with the collection permissions a manager has.
const CUSTOM_TYPE = 4;

export const outboundType = (type: number) => (type === MemberType.Manager ? CUSTOM_TYPE : type);

// Clients know revoked members only by -1.
const outboundStatus = (status: number) => Math.max(status, MemberStatus.Revoked);

function permissionsOf(membership: Membership) {
  const collectionAdmin = membership.type === MemberType.Manager && membership.accessAll;
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

const FEATURES = {
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

export function organizationJson(org: Organization) {
  return {
    id: org.id,
    name: org.name,
    seats: null,
    ...FEATURES,
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

// The member's own view of an organization, in the profile.
function profileOrganizationJson(membership: Membership, org: Organization) {
  return {
    id: org.id,
    identifier: null,
    name: org.name,
    seats: 20,
    ...FEATURES,
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
    limitCollectionCreation: membership.type === MemberType.User || !membership.accessAll,
    limitCollectionDeletion: false,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsManagedByOrganization: false,
    userIsClaimedByOrganization: false,
    permissions: permissionsOf(membership),
    userId: membership.userId,
    key: membership.akey,
    status: outboundStatus(membership.status),
    type: outboundType(membership.type),
    enabled: true,
    object: 'profileOrganization',
  };
}

// `organizations` lists the organizations whose key the member holds;
// `organizationsNew` also those that still have to confirm them.
export function profileOrganizationsJson(memberships: Membership[], orgs: Organization[]) {
  const byId = new Map(orgs.map((org) => [org.id, org]));
  const listed = memberships.flatMap((membership) => {
    const org = byId.get(membership.orgId);
    return org ? [{ membership, json: profileOrganizationJson(membership, org) }] : [];
  });
  return {
    organizations: listed.filter(({ membership }) => membership.status === MemberStatus.Confirmed).map(({ json }) => json),
    organizationsNew: listed
      .filter(({ membership }) => membership.status === MemberStatus.Confirmed || membership.status === MemberStatus.Accepted)
      .map(({ json }) => json),
  };
}

export function collectionJson(collection: Collection) {
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

// A collection with what the member may do with it.
export function collectionDetailsJson(collection: Collection, ctx: OrgContext) {
  const membership = ctx.confirmed.get(collection.orgId);
  const grant = ctx.grants.get(collection.id);
  let rights = { readOnly: true, hidePasswords: true, manage: false };
  if (membership && hasFullAccessTo(ctx, collection.orgId)) {
    rights = { readOnly: false, hidePasswords: false, manage: membership.type !== MemberType.User };
  } else if (membership && grant) {
    rights = {
      readOnly: grant.readOnly,
      hidePasswords: grant.hidePasswords,
      manage: grant.manage || (membership.type === MemberType.Manager && !grant.readOnly && !grant.hidePasswords),
    };
  }
  return { ...collectionJson(collection), ...rights, object: 'collectionDetails' };
}

// A grant, named by the collection or by the member.
export function grantJson(grant: CollectionGrant, memberType: number, by: 'collection' | 'member') {
  return {
    id: by === 'collection' ? grant.collectionId : grant.membershipId,
    readOnly: grant.readOnly,
    hidePasswords: grant.hidePasswords,
    manage:
      isAdminType(memberType) ||
      grant.manage ||
      (memberType === MemberType.Manager && !grant.readOnly && !grant.hidePasswords),
  };
}

export function memberDetailsJson(member: Member, grants: CollectionGrant[], includeCollections: boolean) {
  const unrevokedStatus = member.status === MemberStatus.Revoked ? (member.revokedStatus ?? MemberStatus.Accepted) : member.status;
  const type = outboundType(member.type);
  return {
    id: member.id,
    userId: member.userId,
    // Invitees have not shown their name to the organization yet.
    name: unrevokedStatus >= MemberStatus.Accepted ? member.name : null,
    email: member.email,
    externalId: null,
    avatarColor: null,
    groups: [],
    collections: includeCollections && !member.accessAll ? grants.map((grant) => grantJson(grant, member.type, 'collection')) : [],
    status: outboundStatus(member.status),
    type,
    accessAll: member.accessAll,
    twoFactorEnabled: member.hasTwoFactor,
    resetPasswordEnrolled: false,
    hasMasterPassword: true,
    permissions: type === CUSTOM_TYPE && member.accessAll ? permissionsOf(member) : null,
    ssoBound: false,
    managedByOrganization: false,
    claimedByOrganization: false,
    usesKeyConnector: false,
    accessSecretsManager: false,
    object: 'organizationUserUserDetails',
  };
}

export function memberMiniJson(member: Member) {
  return {
    id: member.id,
    userId: member.userId,
    type: outboundType(member.type),
    status: outboundStatus(member.status),
    name: member.name,
    email: member.email,
    object: 'organizationUserUserMiniDetails',
  };
}
