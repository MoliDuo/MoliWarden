// The personal vault over HTTP: cipher writes, trash, import, domain rules
// and what sync returns. Organization sharing is in organizations.e2e.test.ts.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, cipherPayload, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';
import { errorText } from './e2e-support';

let server: TestServer;
let client: Client;
let alice: Session;
let bob: Session;

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  alice = await client.registerAndLogin('vault-alice@example.com');
  bob = await client.registerAndLogin('vault-bob@example.com');
});

after(async () => {
  await server?.close();
});

async function failure(session: Session, path: string, init: RequestInit & { json?: unknown }) {
  const response = await session.request(path, init);
  return { status: response.status, message: errorText(await response.json().catch(() => null)) };
}

test('only the fields of the item type are stored and returned', async () => {
  const created = await alice.json('/api/ciphers', {
    method: 'POST',
    json: cipherPayload('whitelist', {
      card: { number: fakeEncString('card-number') },
      unknownField: 'dropped',
      data: '{"legacy":true}',
    }),
  });
  assert.equal(created.object, 'cipherDetails');
  assert.equal(created.card, null);
  assert.equal(created.unknownField, undefined);
  assert.equal(created.data, undefined);
  assert.ok(created.login.username);

  const invalid = await failure(alice, '/api/ciphers', { method: 'POST', json: cipherPayload('bad', { name: 'plain text' }) });
  assert.equal(invalid.status, 400);
  assert.match(invalid.message, /name/);
});

test('a stale update is rejected, and the stored key survives an update without one', async () => {
  const created = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('stale', { key: fakeEncString('item-key') }) });
  const updated = await alice.json(`/api/ciphers/${created.id}`, {
    method: 'PUT',
    json: cipherPayload('stale-2', { lastKnownRevisionDate: created.revisionDate }),
  });
  assert.equal(updated.key, created.key);

  const stale = await failure(alice, `/api/ciphers/${created.id}`, {
    method: 'PUT',
    json: cipherPayload('stale-3', { lastKnownRevisionDate: new Date(Date.parse(created.revisionDate) - 60_000).toISOString() }),
  });
  assert.equal(stale.status, 400);
  assert.match(stale.message, /out of date/i);
});

test('other users cannot see, change or delete an item', async () => {
  const created = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('private') });
  assert.equal((await bob.request(`/api/ciphers/${created.id}`)).status, 404);
  assert.equal((await bob.request(`/api/ciphers/${created.id}`, { method: 'PUT', json: cipherPayload('x') })).status, 404);
  assert.equal((await bob.request(`/api/ciphers/${created.id}`, { method: 'DELETE' })).status, 404);
  await bob.request('/api/ciphers/delete', { method: 'POST', json: { ids: [created.id] } });
  assert.equal((await alice.request(`/api/ciphers/${created.id}`)).status, 200);

  // Ids in the path are UUIDs; anything else names nothing.
  assert.equal((await alice.request('/api/ciphers/not-an-id')).status, 404);
});

test('a folder must be the user’s own', async () => {
  const folder = await bob.json('/api/folders', { method: 'POST', json: { name: fakeEncString('bob-folder') } });
  const result = await failure(alice, '/api/ciphers', { method: 'POST', json: cipherPayload('folder', { folderId: folder.id }) });
  assert.equal(result.status, 404);
});

test('trash, restore and permanent deletion', async () => {
  const [one, two] = await Promise.all(
    ['trash-1', 'trash-2'].map((name) => alice.json('/api/ciphers', { method: 'POST', json: cipherPayload(name) })),
  );
  const trashed = await alice.json(`/api/ciphers/${one.id}/delete`, { method: 'PUT' });
  assert.ok(trashed.deletedDate);
  assert.ok(!(await alice.json('/api/ciphers')).data.some((cipher: any) => cipher.id === one.id));
  assert.ok((await alice.json('/api/ciphers?deleted=true')).data.some((cipher: any) => cipher.id === one.id));

  const restored = await alice.json('/api/ciphers/restore', { method: 'PUT', json: { ids: [one.id] } });
  assert.equal(restored.object, 'list');
  assert.equal(restored.data[0].deletedDate, null);

  assert.equal((await alice.request('/api/ciphers/delete', { method: 'POST', json: { ids: [one.id, two.id] } })).status, 204);
  assert.equal((await alice.request(`/api/ciphers/${one.id}`)).status, 404);
  assert.equal((await alice.request(`/api/ciphers/${two.id}`)).status, 404);
});

test('archive, favorite and folder are set without touching the item', async () => {
  const folder = await alice.json('/api/folders', { method: 'POST', json: { name: fakeEncString('state') } });
  const created = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('state') });
  const partial = await alice.json(`/api/ciphers/${created.id}/partial`, { method: 'PUT', json: { folderId: folder.id, favorite: true } });
  assert.equal(partial.folderId, folder.id);
  assert.equal(partial.favorite, true);
  assert.equal(partial.name, created.name);

  const archived = await alice.json(`/api/ciphers/${created.id}/archive`, { method: 'PUT' });
  assert.ok(archived.archivedDate);
  const unarchived = await alice.json('/api/ciphers/unarchive', { method: 'PUT', json: { ids: [created.id] } });
  assert.equal(unarchived.data[0].archivedDate, null);

  await alice.json(`/api/ciphers/${created.id}/delete`, { method: 'PUT' });
  const result = await failure(alice, `/api/ciphers/${created.id}/archive`, { method: 'PUT' });
  assert.equal(result.status, 400);
});

test('import creates folders and maps items into them', async () => {
  const existing = await alice.json('/api/folders', { method: 'POST', json: { name: fakeEncString('existing') } });
  const known = new Set((await alice.json('/api/folders')).data.map((folder: any) => folder.id));
  const result = await alice.json('/api/ciphers/import?returnCipherMap=1', {
    method: 'POST',
    json: {
      folders: [{ name: fakeEncString('imported') }],
      ciphers: [
        { ...cipherPayload('import-1'), id: 'source-1' },
        { ...cipherPayload('import-2'), folderId: existing.id },
        cipherPayload('import-3', { card: { number: fakeEncString('dropped') } }),
      ],
      folderRelationships: [{ key: 0, value: 0 }],
    },
  });
  assert.equal(result.object, 'import-result');
  assert.deepEqual(result.cipherMap.map((entry: any) => [entry.index, entry.sourceId]), [[0, 'source-1'], [1, null], [2, null]]);

  const sync = await alice.json('/api/sync');
  const byId = new Map(sync.ciphers.map((cipher: any) => [cipher.id, cipher]));
  const [imported, ...others] = sync.folders.filter((folder: any) => !known.has(folder.id));
  assert.ok(imported);
  assert.equal(others.length, 0);
  assert.equal((byId.get(result.cipherMap[0].id) as any).folderId, imported.id);
  assert.equal((byId.get(result.cipherMap[1].id) as any).folderId, existing.id);
  assert.equal((byId.get(result.cipherMap[2].id) as any).card, null);

  const tooMany = await failure(alice, '/api/ciphers/import', {
    method: 'POST',
    json: { ciphers: Array.from({ length: 5001 }, () => ({})), folders: [] },
  });
  assert.equal(tooMany.status, 400);
});

test('domain rules are saved, and sync leaves out excluded global groups', async () => {
  const before = await alice.json('/api/settings/domains');
  assert.equal(before.object, 'domains');
  const [firstGlobal] = before.globalEquivalentDomains;

  const saved = await alice.json('/api/settings/domains', {
    method: 'PUT',
    json: {
      customEquivalentDomains: [{ domains: ['example.com', 'example.net'] }, { domains: ['off.example', 'off.test'], excluded: true }],
      excludedGlobalEquivalentDomains: [firstGlobal.type],
    },
  });
  assert.equal(saved.customEquivalentDomains.length, 2);
  assert.ok(saved.equivalentDomains.some((group: string[]) => group.includes('example.net')));
  assert.ok(!saved.equivalentDomains.some((group: string[]) => group.includes('off.test')));
  assert.equal(saved.globalEquivalentDomains.find((entry: any) => entry.type === firstGlobal.type).excluded, true);

  // Fields left out keep their values.
  const kept = await alice.json('/settings/domains', { method: 'POST', json: {} });
  assert.equal(kept.customEquivalentDomains.length, 2);

  const sync = await alice.json('/api/sync');
  assert.ok(!sync.domains.globalEquivalentDomains.some((entry: any) => entry.type === firstGlobal.type));
  assert.equal((await alice.json('/api/sync?excludeDomains=true')).domains, null);
});

test('sync is the vault in one response', async () => {
  const sync = await bob.json('/api/sync?excludeSends=1');
  assert.equal(sync.object, 'sync');
  assert.equal(sync.profile.email, 'vault-bob@example.com');
  assert.deepEqual(sync.sends, []);
  assert.deepEqual(sync.policies, []);
  assert.equal(sync.UserDecryptionOptions.HasMasterPassword, true);
  assert.ok(sync.folders.every((folder: any) => folder.object === 'folder'));
});
