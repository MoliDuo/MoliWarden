import { z } from 'zod';
import { id } from '../../http/body';
import { cipherInput } from './model';

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);

const ids = z
  .array(id)
  .nullish()
  .transform((list) => [...new Set(list ?? [])]);

// Clients send a cipher either as it is or, with its collections, as
// { cipher, collectionIds }.
export const cipherBody = z.preprocess(
  (value) =>
    isObject(value) && isObject(value.cipher)
      ? value
      : { cipher: value, preserveRevisionDate: isObject(value) ? value.preserveRevisionDate : undefined },
  z.object({
    cipher: cipherInput,
    collectionIds: ids,
    // The web vault repairs items without making them look changed.
    preserveRevisionDate: z.boolean().nullish(),
  }),
);
export type CipherBody = z.output<typeof cipherBody>;

export const idsBody = z.object({ ids: z.array(id, 'ids array is required').transform((list) => [...new Set(list)]) });

export const moveBody = z.object({
  ids: idsBody.shape.ids,
  folderId: z.preprocess((value) => (value === '' ? null : value), id.nullish()),
});

export const partialBody = z.object({
  folderId: z.preprocess((value) => (value === '' ? null : value), id.nullish()),
  favorite: z.boolean().nullish(),
});

export const shareBody = z.object({ cipher: cipherInput, collectionIds: ids });

export const bulkShareBody = z.object({
  ciphers: z.array(cipherInput.extend({ id })).min(1, 'You must select at least one cipher.'),
  collectionIds: ids.pipe(z.array(z.string()).min(1, 'You must select at least one collection.')),
});

export const collectionsBody = z.object({ collectionIds: ids });

export const bulkCollectionsBody = z.object({
  organizationId: id,
  cipherIds: ids,
  collectionIds: ids,
  removeCollections: z.boolean().nullish(),
});

const relationships = z
  .array(z.object({ key: z.coerce.number().int().min(0), value: z.coerce.number().int().min(0) }))
  .nullish()
  .transform((list) => list ?? []);

export const IMPORT_LIMIT = 5000;

export const importBody = z
  .object({
    ciphers: z.array(cipherInput.extend({ id: z.string().trim().nullish() })).nullish().transform((list) => list ?? []),
    folders: z
      .array(z.object({ name: cipherInput.shape.name }))
      .nullish()
      .transform((list) => list ?? []),
    folderRelationships: relationships,
  })
  .refine((body) => body.ciphers.length + body.folders.length <= IMPORT_LIMIT, `Import exceeds maximum of ${IMPORT_LIMIT} items`);
export type ImportInput = z.output<typeof importBody>;

export const orgImportBody = z.object({
  ciphers: z
    .array(cipherInput)
    .max(IMPORT_LIMIT, 'Too many items in one import')
    .nullish()
    .transform((list) => list ?? []),
  // Existing collections by id; the others are created.
  collections: z
    .array(z.object({ id: id.nullish().catch(null), name: z.string().trim().nullish() }))
    .nullish()
    .transform((list) => list ?? []),
  collectionRelationships: relationships,
});
export type OrgImportInput = z.output<typeof orgImportBody>;
