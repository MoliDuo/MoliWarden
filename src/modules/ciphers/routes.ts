import { Hono, type Context } from 'hono';
import { authenticate, callerOf, type AuthedEnv } from '../../http/authenticate';
import { id, readJson } from '../../http/body';
import { listJson } from '../../http/list';
import { idParam } from '../../http/params';
import type { Deps } from '../../main/deps';
import { importCiphers } from './import';
import {
  bulkCollectionsBody,
  bulkShareBody,
  cipherBody,
  collectionsBody,
  idsBody,
  importBody,
  moveBody,
  orgImportBody,
  partialBody,
  shareBody,
} from './schemas';
import {
  archiveCipher,
  archiveCiphers,
  cipherById,
  ciphersJson,
  createCipher,
  moveCiphers,
  purgeCipher,
  purgeCiphers,
  trashCipher,
  trashCiphers,
  updateCipher,
  updateCipherState,
} from './service';
import {
  exportOrganization,
  importOrganization,
  organizationDetails,
  setBulkCollections,
  setCipherCollections,
  shareCiphers,
  type CollectionsVariant,
} from './sharing';

const ciphers = (...suffixes: string[]) => suffixes.map((suffix) => `/api/ciphers${suffix}`);

const organizationParam = (c: Context) => id.parse(c.req.query('organizationId') ?? '');

export function cipherRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);

  // Routes on the collection come before those on one cipher.
  app.get('/api/ciphers', authed, async (c) => c.json(await ciphersJson(deps, callerOf(c), c.req.query('deleted') === 'true')));
  app.on('POST', ciphers('', '/create', '/admin'), authed, async (c) =>
    c.json(await createCipher(deps, callerOf(c), await readJson(c, cipherBody))),
  );

  // Trash on PUT, permanent deletion otherwise.
  app.on('PUT', ciphers('/delete', '/delete-admin'), authed, async (c) => {
    await trashCiphers(deps, callerOf(c), (await readJson(c, idsBody)).ids, true);
    return c.body(null, 204);
  });
  app.on('POST', ciphers('/delete', '/delete-admin', '/delete-permanent'), authed, async (c) => {
    await purgeCiphers(deps, callerOf(c), (await readJson(c, idsBody)).ids);
    return c.body(null, 204);
  });
  app.on('DELETE', ciphers('', '/admin'), authed, async (c) => {
    await purgeCiphers(deps, callerOf(c), (await readJson(c, idsBody)).ids);
    return c.body(null, 204);
  });
  app.on(['PUT', 'POST'], ciphers('/restore', '/restore-admin'), authed, async (c) => {
    const restored = await trashCiphers(deps, callerOf(c), (await readJson(c, idsBody)).ids, false);
    return c.req.method === 'PUT' ? c.json(restored) : c.body(null, 204);
  });
  app.on(['PUT', 'POST'], ciphers('/archive', '/unarchive'), authed, async (c) =>
    c.json(await archiveCiphers(deps, callerOf(c), (await readJson(c, idsBody)).ids, c.req.path.endsWith('/archive'))),
  );
  app.on(['PUT', 'POST'], ciphers('/move'), authed, async (c) => {
    const { ids, folderId } = await readJson(c, moveBody);
    await moveCiphers(deps, callerOf(c), ids, folderId ?? null);
    return c.body(null, 204);
  });

  app.on(['PUT', 'POST'], ciphers('/share'), authed, async (c) => {
    const { ciphers: items, collectionIds } = await readJson(c, bulkShareBody);
    const shared = await shareCiphers(deps, callerOf(c), items.map((input) => ({ id: input.id, input })), collectionIds);
    return c.json(listJson(shared));
  });
  app.post('/api/ciphers/bulk-collections', authed, async (c) => {
    await setBulkCollections(deps, callerOf(c), await readJson(c, bulkCollectionsBody));
    return c.body(null, 200);
  });
  app.get('/api/ciphers/organization-details', authed, async (c) =>
    c.json(await organizationDetails(deps, callerOf(c), organizationParam(c))),
  );
  app.post('/api/ciphers/import-organization', authed, async (c) => {
    await importOrganization(deps, callerOf(c), organizationParam(c), await readJson(c, orgImportBody));
    return c.body(null, 200);
  });
  app.get('/api/organizations/:orgId/export', authed, async (c) =>
    c.json(await exportOrganization(deps, callerOf(c), idParam(c, 'orgId'))),
  );
  // Clients split large imports into many requests.
  app.post('/api/ciphers/import', authenticate(deps, 'bulk'), async (c) => {
    const result = await importCiphers(deps, callerOf(c), await readJson(c, importBody));
    return c.req.query('returnCipherMap') === '1' ? c.json(result) : c.body(null, 200);
  });

  app.on('GET', ciphers('/:id', '/:id/admin', '/:id/details'), authed, async (c) =>
    c.json(await cipherById(deps, callerOf(c), idParam(c))),
  );
  app.on(['PUT', 'POST'], ciphers('/:id', '/:id/admin'), authed, async (c) =>
    c.json(await updateCipher(deps, callerOf(c), idParam(c), await readJson(c, cipherBody))),
  );
  app.on('PUT', ciphers('/:id/delete', '/:id/delete-admin'), authed, async (c) =>
    c.json(await trashCipher(deps, callerOf(c), idParam(c), true)),
  );
  app.on('PUT', ciphers('/:id/restore', '/:id/restore-admin'), authed, async (c) =>
    c.json(await trashCipher(deps, callerOf(c), idParam(c), false)),
  );
  app.on(['DELETE', 'POST'], ciphers('/:id/delete', '/:id/delete-admin'), authed, async (c) => {
    await purgeCipher(deps, callerOf(c), idParam(c));
    return c.body(null, 204);
  });
  app.on('DELETE', ciphers('/:id', '/:id/admin'), authed, async (c) => {
    await purgeCipher(deps, callerOf(c), idParam(c));
    return c.body(null, 204);
  });
  app.on(['PUT', 'POST'], ciphers('/:id/partial'), authed, async (c) =>
    c.json(await updateCipherState(deps, callerOf(c), idParam(c), await readJson(c, partialBody))),
  );
  app.on(['PUT', 'POST'], ciphers('/:id/archive', '/:id/unarchive'), authed, async (c) =>
    c.json(await archiveCipher(deps, callerOf(c), idParam(c), c.req.path.endsWith('/archive'))),
  );
  app.on(['PUT', 'POST'], ciphers('/:id/share'), authed, async (c) => {
    const { cipher, collectionIds } = await readJson(c, shareBody);
    const [shared] = await shareCiphers(deps, callerOf(c), [{ id: idParam(c), input: cipher }], collectionIds);
    return c.json(shared);
  });
  const variants: Record<string, CollectionsVariant> = { collections: 'v1', collections_v2: 'v2', 'collections-admin': 'admin' };
  for (const [suffix, variant] of Object.entries(variants)) {
    app.on(['PUT', 'POST'], ciphers(`/:id/${suffix}`), authed, async (c) => {
      const { collectionIds } = await readJson(c, collectionsBody);
      const result = await setCipherCollections(deps, callerOf(c), idParam(c), collectionIds, variant);
      return result ? c.json(result) : c.body(null, 200);
    });
  }

  return app;
}
