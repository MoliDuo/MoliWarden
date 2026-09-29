import { z } from 'zod';
import { id, optionalText } from '../../http/body';
import { MemberType } from './repo';

const orgName = z.string().trim().min(1).max(200, 'Organization name is required (max 200 characters)');
const billingEmail = z.string().trim().toLowerCase().regex(/^[^\s@]+@[^\s@]+$/, 'BillingEmail is not a valid email address');
const required = (message: string) => z.string(message).trim().min(1, message);

const ids = z
  .array(id)
  .nullish()
  .transform((list) => [...new Set(list ?? [])]);

export const createOrgBody = z.object({
  name: orgName,
  billingEmail: billingEmail.nullish(),
  key: required('Organization key is required'),
  collectionName: optionalText,
  keys: z
    .object({ publicKey: optionalText, encryptedPrivateKey: optionalText })
    .nullish()
    .transform((keys) => keys ?? { publicKey: null, encryptedPrivateKey: null }),
});
export type CreateOrgInput = z.output<typeof createOrgBody>;

export const updateOrgBody = z.object({ name: orgName.optional(), billingEmail: billingEmail.optional() });

export const passwordBody = z.object({ masterPasswordHash: z.string().nullish() });

export const orgKeysBody = z.object({
  publicKey: required('publicKey and encryptedPrivateKey are required'),
  encryptedPrivateKey: required('publicKey and encryptedPrivateKey are required'),
});

// Roles by number or name. "Custom" is stored as Manager; with every
// collection permission it sees all collections.
const ROLES: Record<string, number> = {
  '0': MemberType.Owner,
  owner: MemberType.Owner,
  '1': MemberType.Admin,
  admin: MemberType.Admin,
  '2': MemberType.User,
  user: MemberType.User,
  '3': MemberType.Manager,
  manager: MemberType.Manager,
  '4': MemberType.Manager,
  custom: MemberType.Manager,
};

const role = z.union([z.number(), z.string()]).transform((value, ctx) => {
  const name = String(value).trim().toLowerCase();
  const type = ROLES[name];
  if (type === undefined) {
    ctx.addIssue({ code: 'custom', message: 'Invalid type' });
    return z.NEVER;
  }
  return { type, custom: name === '4' || name === 'custom' };
});
export type Role = z.output<typeof role>;

const permissions = z
  .object({
    createNewCollections: z.boolean().nullish(),
    editAnyCollection: z.boolean().nullish(),
    deleteAnyCollection: z.boolean().nullish(),
  })
  .nullish()
  .catch(null);

// A member's rights to one collection, named by the other side's id.
const grants = z
  .array(
    z.object({
      id,
      readOnly: z.boolean().nullish().transform(Boolean),
      hidePasswords: z.boolean().nullish().transform(Boolean),
      manage: z.boolean().nullish().transform(Boolean),
    }),
  )
  .nullish()
  .transform((list) => [...new Map((list ?? []).map((grant) => [grant.id, grant])).values()]);
export type GrantInput = z.output<typeof grants>[number];

const memberFields = { permissions, collections: grants };

export const inviteBody = z.object({
  emails: z
    .array(z.string().trim().toLowerCase())
    .transform((list) => [...new Set(list.filter(Boolean))])
    .pipe(z.array(z.string()).min(1, 'At least one email is required').max(20, 'You can invite at most 20 users at once')),
  type: role,
  ...memberFields,
});
export type InviteInput = z.output<typeof inviteBody>;

export const editMemberBody = z.object({ type: role.nullish(), ...memberFields });
export type EditMemberInput = z.output<typeof editMemberBody>;

export const confirmBody = z.object({ key: z.string().trim().nullish() });

export const bulkConfirmBody = z.object({
  keys: z
    .array(z.object({ id, key: z.string().trim().nullish() }))
    .nullish()
    .transform((list) => list ?? []),
});

export const idsBody = z.object({ ids });

export const collectionBody = z.object({
  name: required('Collection name is required'),
  externalId: optionalText,
  users: grants.optional(),
});
export type CollectionInput = z.output<typeof collectionBody>;

export const updateCollectionBody = collectionBody.partial();
export type CollectionUpdate = z.output<typeof updateCollectionBody>;

export const bulkAccessBody = z.object({ collectionIds: ids, users: grants });
