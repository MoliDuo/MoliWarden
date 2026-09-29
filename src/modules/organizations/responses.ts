import { hasFullAccessTo, type OrgContext } from './access';
import { MemberType, type Collection } from './repo';

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
