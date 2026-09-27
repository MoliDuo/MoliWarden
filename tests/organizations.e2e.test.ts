// Organizations: lifecycle, sharing and the permission boundaries around them.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, cipherPayload, fakeEncString, fakeRsaEncString, startTestServer, type Session, type TestServer } from './helpers';

let server: TestServer;
let client: Client;
let alice: Session; // owner
let bob: Session & { publicKey: string }; // member
let carol: Session; // outsider
let orgId: string;
let c1: string;
let c2: string;
let bobMemberId: string;
let sharedCipherId: string;
let hiddenCipherId: string;

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  alice = await client.registerAndLogin('alice@example.com');
  bob = await client.registerAndLogin('bob@example.com');
  carol = await client.registerAndLogin('carol@example.com');
});

after(async () => {
  await server?.close();
});

async function status(session: Session, path: string, init: RequestInit & { json?: unknown } = {}): Promise<number> {
  const response = await session.request(path, init);
  await response.arrayBuffer();
  return response.status;
}

test('owner creates an organization with a default collection', async () => {
  const org = await alice.json('/api/organizations', {
    method: 'POST',
    json: {
      name: 'Family',
      billingEmail: 'alice@example.com',
      key: fakeRsaEncString('org-key-alice'),
      collectionName: fakeEncString('Default'),
      keys: { publicKey: 'b3JnLXB1Yg==', encryptedPrivateKey: fakeEncString('org-private') },
      planType: 0,
    },
  });
  orgId = org.id;
  assert.equal(org.object, 'organization');
  assert.equal(org.hasPublicAndPrivateKeys, true);

  const sync = await alice.json('/api/sync');
  assert.equal(sync.profile.organizations.length, 1);
  const entry = sync.profile.organizations[0];
  assert.equal(entry.id, orgId);
  assert.equal(entry.type, 0);
  assert.equal(entry.status, 2);
  assert.ok(entry.key.startsWith('4.'));
  assert.equal(sync.collections.length, 1);
  c1 = sync.collections[0].id;
  assert.equal(sync.collections[0].manage, true);
});

test('invite -> accept -> confirm lifecycle', async () => {
  assert.equal(
    await status(alice, `/api/organizations/${orgId}/users/invite`, {
      method: 'POST',
      json: { emails: ['nobody@example.com'], type: 2, collections: [], groups: [] },
    }),
    400
  );
  await alice.json(`/api/organizations/${orgId}/users/invite`, {
    method: 'POST',
    json: { emails: ['bob@example.com'], type: 2, collections: [{ id: c1, readOnly: false, hidePasswords: false, manage: false }], groups: [] },
  });

  // Invited: nothing visible in sync, but the invitation is listed.
  let bobSync = await bob.json('/api/sync');
  assert.equal(bobSync.profile.organizations.length, 0);
  assert.equal(bobSync.profile.organizationsNew.length, 0);
  const invitations = await bob.json('/api/organizations/invitations');
  assert.equal(invitations.data.length, 1);
  bobMemberId = invitations.data[0].id;

  // Only the invitee can accept, and only once.
  assert.equal(await status(carol, `/api/organizations/${orgId}/users/${bobMemberId}/accept`, { method: 'POST', json: {} }), 404);
  await bob.json(`/api/organizations/${orgId}/users/${bobMemberId}/accept`, { method: 'POST', json: {} });
  bobSync = await bob.json('/api/sync');
  assert.equal(bobSync.profile.organizations.length, 0);
  assert.equal(bobSync.profile.organizationsNew.length, 1);

  // Accepted but unconfirmed members cannot read org data.
  assert.equal(await status(bob, `/api/organizations/${orgId}/collections/details`), 403);

  const keys = await alice.json(`/api/organizations/${orgId}/users/public-keys`, { method: 'POST', json: { ids: [bobMemberId] } });
  assert.equal(keys.data[0].key, bob.publicKey);
  await alice.json(`/api/organizations/${orgId}/users/${bobMemberId}/confirm`, {
    method: 'POST',
    json: { key: fakeRsaEncString('org-key-bob') },
  });
  bobSync = await bob.json('/api/sync');
  assert.equal(bobSync.profile.organizations.length, 1);
  assert.equal(bobSync.profile.organizations[0].status, 2);
  assert.deepEqual(bobSync.collections.map((c: any) => c.id), [c1]);

  const members = await alice.json(`/api/organizations/${orgId}/users?includeCollections=true`);
  const bobEntry = members.data.find((m: any) => m.id === bobMemberId);
  assert.equal(bobEntry.status, 2);
  assert.deepEqual(bobEntry.collections.map((c: any) => c.id), [c1]);
});

test('org cipher in a shared collection is visible to the member', async () => {
  const created = await alice.json('/api/ciphers/create', {
    method: 'POST',
    json: { cipher: cipherPayload('shared', { organizationId: orgId }), collectionIds: [c1] },
  });
  sharedCipherId = created.id;
  assert.equal(created.organizationId, orgId);
  assert.deepEqual(created.collectionIds, [c1]);

  const bobSync = await bob.json('/api/sync');
  const seen = bobSync.ciphers.find((c: any) => c.id === sharedCipherId);
  assert.ok(seen);
  assert.equal(seen.edit, true);
  assert.equal(seen.organizationId, orgId);
  assert.equal(await status(carol, `/api/ciphers/${sharedCipherId}`), 404);
});

test('org items require a writable collection of that org', async () => {
  // No collection, foreign collection, non-member org.
  assert.equal(
    await status(bob, '/api/ciphers/create', { method: 'POST', json: { cipher: cipherPayload('x', { organizationId: orgId }), collectionIds: [] } }),
    400
  );
  assert.equal(
    await status(carol, '/api/ciphers/create', { method: 'POST', json: { cipher: cipherPayload('x', { organizationId: orgId }), collectionIds: [c1] } }),
    400
  );
  // Plain create cannot smuggle an org id without collections either.
  assert.equal(await status(carol, '/api/ciphers', { method: 'POST', json: cipherPayload('x', { organizationId: orgId }) }), 400);
});

test('sharing a personal item into a collection the member cannot see', async () => {
  const collection = await alice.json(`/api/organizations/${orgId}/collections`, {
    method: 'POST',
    json: { name: fakeEncString('Private'), groups: [], users: [] },
  });
  c2 = collection.id;

  const personal = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('to-share') });
  // Carol cannot share Alice's item, Bob (plain user without c2 rights) cannot share into c2.
  assert.equal(
    await status(carol, `/api/ciphers/${personal.id}/share`, {
      method: 'PUT',
      json: { cipher: cipherPayload('to-share', { organizationId: orgId }), collectionIds: [c2] },
    }),
    404
  );
  const bobPersonal = await bob.json('/api/ciphers', { method: 'POST', json: cipherPayload('bob-own') });
  assert.equal(
    await status(bob, `/api/ciphers/${bobPersonal.id}/share`, {
      method: 'PUT',
      json: { cipher: cipherPayload('bob-own', { organizationId: orgId }), collectionIds: [c2] },
    }),
    403
  );

  const shared = await alice.json(`/api/ciphers/${personal.id}/share`, {
    method: 'PUT',
    json: { cipher: cipherPayload('to-share', { organizationId: orgId }), collectionIds: [c2] },
  });
  hiddenCipherId = shared.id;
  assert.equal(shared.organizationId, orgId);
  assert.deepEqual(shared.collectionIds, [c2]);

  const aliceIds = (await alice.json('/api/sync')).ciphers.map((c: any) => c.id);
  assert.ok(aliceIds.includes(hiddenCipherId));
  const bobIds = (await bob.json('/api/sync')).ciphers.map((c: any) => c.id);
  assert.ok(!bobIds.includes(hiddenCipherId));
  assert.equal(await status(bob, `/api/ciphers/${hiddenCipherId}`), 404);

  // Items cannot hop between orgs or back to personal through a plain update.
  assert.equal(
    await status(alice, `/api/ciphers/${hiddenCipherId}`, { method: 'PUT', json: cipherPayload('to-share', { organizationId: null }) }),
    400
  );
});

test('iOS request casing (organizationID) works for share, create and update', async () => {
  // The iOS app's CipherRequestModel encodes the owner as "organizationID".
  const ios = (name: string, org: string | null) => {
    const payload: Record<string, unknown> = { ...cipherPayload(name), encryptedFor: alice.userId };
    payload.organizationID = org;
    return payload;
  };
  const personal = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('ios-share') });
  const shared = await alice.json(`/api/ciphers/${personal.id}/share`, {
    method: 'PUT',
    json: { cipher: ios('ios-share', orgId), collectionIds: [c1] },
  });
  assert.equal(shared.organizationId, orgId);
  assert.deepEqual(shared.collectionIds, [c1]);
  assert.equal(shared.organizationID, undefined);

  const created = await alice.json('/api/ciphers/create', {
    method: 'POST',
    json: { cipher: ios('ios-create', orgId), collectionIds: [c1] },
  });
  assert.equal(created.organizationId, orgId, 'created in the organization, not the personal vault');

  const updated = await alice.json(`/api/ciphers/${created.id}`, { method: 'PUT', json: ios('ios-edit', orgId) });
  assert.equal(updated.organizationId, orgId);
  assert.equal(await status(alice, `/api/ciphers/${created.id}`, { method: 'PUT', json: ios('ios-edit', null) }), 400);

  // Leave the org as the following tests expect it.
  for (const id of [shared.id, created.id]) {
    assert.ok((await alice.request(`/api/ciphers/${id}`, { method: 'DELETE' })).ok);
  }
});

test('read-only access blocks writes but allows per-user folder/favorite', async () => {
  await alice.json(`/api/organizations/${orgId}/users/${bobMemberId}`, {
    method: 'PUT',
    json: { type: 2, collections: [{ id: c1, readOnly: true, hidePasswords: true, manage: false }], groups: [] },
  });
  const seen = (await bob.json('/api/sync')).ciphers.find((c: any) => c.id === sharedCipherId);
  assert.equal(seen.edit, false);
  assert.equal(seen.viewPassword, false);
  assert.deepEqual(seen.permissions, { delete: false, restore: false });

  assert.equal(await status(bob, `/api/ciphers/${sharedCipherId}`, { method: 'PUT', json: cipherPayload('hack', { organizationId: orgId }) }), 403);
  assert.equal(await status(bob, `/api/ciphers/${sharedCipherId}/delete`, { method: 'PUT' }), 403);
  assert.equal(await status(bob, `/api/ciphers/${sharedCipherId}`, { method: 'DELETE' }), 403);
  await bob.request('/api/ciphers/delete', { method: 'PUT', json: { ids: [sharedCipherId] } });
  assert.equal((await alice.json(`/api/ciphers/${sharedCipherId}`)).deletedDate, null);

  const folder = await bob.json('/api/folders', { method: 'POST', json: { name: fakeEncString('bob-folder') } });
  await bob.json(`/api/ciphers/${sharedCipherId}/partial`, { method: 'PUT', json: { folderId: folder.id, favorite: true } });
  const bobView = await bob.json(`/api/ciphers/${sharedCipherId}`);
  assert.equal(bobView.folderId, folder.id);
  assert.equal(bobView.favorite, true);
  const aliceView = await alice.json(`/api/ciphers/${sharedCipherId}`);
  assert.equal(aliceView.folderId, null);
  assert.equal(aliceView.favorite, false);
});

test('plain members cannot administer the organization', async () => {
  assert.equal(await status(bob, `/api/organizations/${orgId}/users`), 403);
  assert.equal(
    await status(bob, `/api/organizations/${orgId}/users/invite`, { method: 'POST', json: { emails: ['carol@example.com'], type: 2, groups: [] } }),
    403
  );
  assert.equal(await status(bob, `/api/organizations/${orgId}/collections`, { method: 'POST', json: { name: fakeEncString('n'), users: [], groups: [] } }), 403);
  assert.equal(await status(bob, `/api/organizations/${orgId}/export`), 404);
  assert.equal(await status(bob, `/api/ciphers/organization-details?organizationId=${orgId}`), 404);
  assert.equal(await status(carol, `/api/organizations/${orgId}/users`), 404);
  assert.equal(await status(carol, `/api/organizations/${orgId}`), 404);
  // An admin-only action on another org's member id must not leak across orgs.
  assert.equal(await status(carol, `/api/organizations/${orgId}/users/${bobMemberId}`, { method: 'DELETE' }), 404);
});

test('attachments of org items follow collection access', async () => {
  const content = Buffer.from('org-attachment');
  const meta = await alice.json(`/api/ciphers/${sharedCipherId}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('k'), fileName: fakeEncString('f'), fileSize: content.length },
  });
  const uploadUrl = new URL(meta.url);
  const upload = await client.fetch(uploadUrl.pathname + uploadUrl.search, { method: 'PUT', body: content });
  assert.equal(upload.status, 201);

  // Read-only Bob can download but not add attachments.
  const info = await bob.json(`/api/ciphers/${sharedCipherId}/attachment/${meta.attachmentId}`);
  const download = await client.fetch(new URL(info.url).pathname + new URL(info.url).search);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), content);
  assert.equal(
    await status(bob, `/api/ciphers/${sharedCipherId}/attachment/v2`, { method: 'POST', json: { key: fakeEncString('k'), fileName: fakeEncString('f'), fileSize: 1 } }),
    403
  );
  assert.equal(await status(carol, `/api/ciphers/${sharedCipherId}/attachment/${meta.attachmentId}`), 404);
});

test('revoked members lose access, restored members regain it', async () => {
  await alice.json(`/api/organizations/${orgId}/users/${bobMemberId}/revoke`, { method: 'PUT' });
  let bobSync = await bob.json('/api/sync');
  assert.equal(bobSync.profile.organizations.length, 0);
  assert.ok(!bobSync.ciphers.some((c: any) => c.organizationId));
  assert.equal(await status(bob, `/api/ciphers/${sharedCipherId}`), 404);
  assert.equal(await status(bob, `/api/organizations/${orgId}/keys`), 404);

  await alice.json(`/api/organizations/${orgId}/users/${bobMemberId}/restore`, { method: 'PUT' });
  bobSync = await bob.json('/api/sync');
  assert.ok(bobSync.ciphers.some((c: any) => c.id === sharedCipherId));
});

test('moving an item between collections changes who sees it', async () => {
  const moved = await alice.json(`/api/ciphers/${sharedCipherId}/collections_v2`, { method: 'PUT', json: { collectionIds: [c2] } });
  assert.equal(moved.object, 'optionalCipherDetails');
  assert.deepEqual(moved.cipher.collectionIds, [c2]);
  assert.ok(!(await bob.json('/api/sync')).ciphers.some((c: any) => c.id === sharedCipherId));

  await alice.json('/api/ciphers/bulk-collections', {
    method: 'POST',
    json: { organizationId: orgId, cipherIds: [sharedCipherId], collectionIds: [c1], removeCollections: false },
  });
  assert.ok((await bob.json('/api/sync')).ciphers.some((c: any) => c.id === sharedCipherId));
});

test('admin listings and export', async () => {
  const details = await alice.json(`/api/ciphers/organization-details?organizationId=${orgId}`);
  assert.equal(details.data.length, 2);
  assert.equal(details.data[0].folderId, undefined);
  const exported = await alice.json(`/api/organizations/${orgId}/export`);
  assert.equal(exported.collections.length, 2);
  assert.equal(exported.ciphers.length, 2);
  const collections = await alice.json(`/api/organizations/${orgId}/collections/details`);
  const c1Details = collections.data.find((c: any) => c.id === c1);
  assert.ok(c1Details.users.some((u: any) => u.id === bobMemberId));
});

test('client-supplied permission fields are ignored', async () => {
  const created = await carol.json('/api/ciphers', {
    method: 'POST',
    json: { ...cipherPayload('spoof'), edit: false, viewPassword: false, collectionIds: [c1], permissions: { delete: false } },
  });
  assert.equal(created.edit, true);
  assert.equal(created.organizationId, null);
  assert.deepEqual(created.collectionIds, []);
  const again = await carol.json(`/api/ciphers/${created.id}`);
  assert.deepEqual(again.collectionIds, []);
  assert.equal(again.viewPassword, true);
});

test('last owner protections and member removal', async () => {
  assert.equal(await status(alice, `/api/organizations/${orgId}/leave`, { method: 'POST' }), 400);
  const members = await alice.json(`/api/organizations/${orgId}/users`);
  const aliceMember = members.data.find((m: any) => m.email === 'alice@example.com');
  assert.equal(await status(alice, `/api/organizations/${orgId}/users/${aliceMember.id}`, { method: 'PUT', json: { type: 2, groups: [] } }), 400);

  await alice.request(`/api/organizations/${orgId}/users/${bobMemberId}`, { method: 'DELETE' });
  const bobSync = await bob.json('/api/sync');
  assert.equal(bobSync.profile.organizations.length, 0);
  assert.ok(!bobSync.ciphers.some((c: any) => c.organizationId));
});

test('org import creates items and collections', async () => {
  await alice.json(`/api/ciphers/import-organization?organizationId=${orgId}`, {
    method: 'POST',
    json: {
      ciphers: [cipherPayload('imp-1'), cipherPayload('imp-2')],
      collections: [{ name: fakeEncString('Imported') }, { id: c1, name: 'ignored' }],
      collectionRelationships: [{ key: 0, value: 0 }, { key: 1, value: 1 }],
    },
  });
  const details = await alice.json(`/api/ciphers/organization-details?organizationId=${orgId}`);
  assert.equal(details.data.length, 4);
});

test('deleting the organization requires the master password and removes its items', async () => {
  assert.equal(await status(alice, `/api/organizations/${orgId}`, { method: 'DELETE', json: { masterPasswordHash: 'wrong' } }), 400);
  const response = await alice.request(`/api/organizations/${orgId}`, {
    method: 'DELETE',
    json: { masterPasswordHash: Buffer.from('hash-alice@example.com').toString('base64') },
  });
  assert.equal(response.status, 200, await response.clone().text());
  const sync = await alice.json('/api/sync');
  assert.equal(sync.profile.organizations.length, 0);
  assert.ok(!sync.ciphers.some((c: any) => c.organizationId));
  assert.equal(sync.collections.length, 0);
});

test('instance backup round-trips organizations', async () => {
  const org = await alice.json('/api/organizations', {
    method: 'POST',
    json: { name: 'Backup Org', billingEmail: 'alice@example.com', key: fakeRsaEncString('k'), collectionName: fakeEncString('C'), planType: 0 },
  });
  const collectionId = (await alice.json(`/api/organizations/${org.id}/collections`)).data[0].id;
  const item = await alice.json('/api/ciphers/create', {
    method: 'POST',
    json: { cipher: cipherPayload('backup', { organizationId: org.id }), collectionIds: [collectionId] },
  });
  await alice.json(`/api/ciphers/${item.id}/partial`, { method: 'PUT', json: { favorite: true } });

  const password = Buffer.from('hash-alice@example.com').toString('base64');
  const exported = await alice.request('/api/admin/backup/export', { method: 'POST', json: { includeAttachments: false, masterPasswordHash: password } });
  assert.equal(exported.status, 200, await exported.clone().text());
  const form = new FormData();
  form.set('file', new Blob([new Uint8Array(await exported.arrayBuffer())], { type: 'application/zip' }), 'backup.zip');
  form.set('masterPasswordHash', password);
  form.set('replaceExisting', '1');
  const restored = await alice.request('/api/admin/backup/import', { method: 'POST', body: form });
  assert.equal(restored.status, 200, await restored.clone().text());

  const relogin = await client.login('alice@example.com');
  const sync = await relogin.json('/api/sync');
  assert.equal(sync.profile.organizations.length, 1);
  const restoredItem = sync.ciphers.find((c: any) => c.id === item.id);
  assert.ok(restoredItem);
  assert.deepEqual(restoredItem.collectionIds, [collectionId]);
  assert.equal(restoredItem.favorite, true);
});

test('security regressions: casing, cross-org links, orphaning, admin collection ids', async () => {
  const org = await alice.json('/api/organizations', {
    method: 'POST',
    json: { name: 'Sec', billingEmail: 'alice@example.com', key: fakeRsaEncString('k'), collectionName: fakeEncString('S1'), planType: 0 },
  });
  const s1 = (await alice.json(`/api/organizations/${org.id}/collections`)).data[0].id;
  const s2 = (await alice.json(`/api/organizations/${org.id}/collections`, { method: 'POST', json: { name: fakeEncString('S2'), users: [], groups: [] } })).id;
  await alice.json(`/api/organizations/${org.id}/users/invite`, {
    method: 'POST',
    json: { emails: ['bob@example.com'], type: 2, groups: [], collections: [{ id: s1, readOnly: false, hidePasswords: true, manage: false }] },
  });
  const invitation = (await bob.json('/api/organizations/invitations')).data.find((d: any) => d.organizationId === org.id);
  await bob.json(`/api/organizations/${org.id}/users/${invitation.id}/accept`, { method: 'POST', json: {} });
  await alice.json(`/api/organizations/${org.id}/users/${invitation.id}/confirm`, { method: 'POST', json: { key: fakeRsaEncString('b') } });

  const item = await alice.json('/api/ciphers/create', {
    method: 'POST',
    json: { cipher: cipherPayload('sec', { organizationId: org.id }), collectionIds: [s1, s2] },
  });
  // PascalCase copies of server-owned fields are neither stored nor echoed.
  const put = await bob.request(`/api/ciphers/${item.id}`, {
    method: 'PUT',
    json: { ...cipherPayload('sec2'), Edit: true, ViewPassword: true, Permissions: { Delete: true }, Id: 'x', DeletedDate: '2020-01-01T00:00:00Z' },
  });
  assert.equal(put.status, 200, await put.clone().text());
  const seen = (await bob.json('/api/sync')).ciphers.find((c: any) => c.id === item.id);
  for (const key of ['Edit', 'ViewPassword', 'Permissions', 'Id', 'DeletedDate']) assert.equal(key in seen, false, key);
  assert.equal(seen.viewPassword, false);

  // collections-admin does not reveal collections outside the caller's grants.
  const adminView = await bob.json(`/api/ciphers/${item.id}/collections-admin`, { method: 'PUT', json: { collectionIds: [s1] } });
  assert.deepEqual(adminView.collectionIds, [s1]);

  // A limited member cannot orphan an item through bulk removal.
  const single = await alice.json('/api/ciphers/create', {
    method: 'POST',
    json: { cipher: cipherPayload('only-s1', { organizationId: org.id }), collectionIds: [s1] },
  });
  const bulk = await bob.request('/api/ciphers/bulk-collections', {
    method: 'POST',
    json: { organizationId: org.id, cipherIds: [single.id], collectionIds: [s1], removeCollections: true },
  });
  assert.equal(bulk.status, 400);

  // Collection links never cross organizations, even when inserted directly.
  const other = await alice.json('/api/organizations', {
    method: 'POST',
    json: { name: 'Other', billingEmail: 'alice@example.com', key: fakeRsaEncString('k'), collectionName: fakeEncString('O1'), planType: 0 },
  });
  const o1 = (await alice.json(`/api/organizations/${other.id}/collections`)).data[0].id;
  const { getEnv } = await import('../src/platform/env');
  const { addCipherCollectionStatement } = await import('../src/services/storage-org-repo');
  const db = getEnv().DB;
  await addCipherCollectionStatement(db, item.id, o1).run();
  const links = await db.prepare('SELECT collection_id FROM cipher_collections WHERE cipher_id = ?').bind(item.id).all<{ collection_id: string }>();
  assert.ok(!links.results.some((row) => row.collection_id === o1));
});
