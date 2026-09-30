// The number of database queries behind a sync does not grow with the vault.
// The server runs in this process, so counting the queries its pg clients
// send is enough.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { Client, cipherPayload, fakeEncString, fakeRsaEncString, startTestServer, type Session, type TestServer } from './helpers';

let server: TestServer;
let alice: Session;
let bob: Session;

let counting = false;
let queries = 0;
const query = pg.Client.prototype.query;
pg.Client.prototype.query = function (this: pg.Client, ...args: unknown[]) {
  if (counting) queries += 1;
  return (query as (...a: unknown[]) => unknown).apply(this, args);
} as typeof query;

async function syncQueries(session: Session): Promise<number> {
  queries = 0;
  counting = true;
  try {
    await session.json('/api/sync');
  } finally {
    counting = false;
  }
  return queries;
}

const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

async function fillVault(owner: Session, orgId: string, collectionId: string, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    const folder = await owner.json('/api/folders', { method: 'POST', json: { name: fakeEncString(`folder-${i}`) } });
    await owner.json('/api/ciphers', { method: 'POST', json: cipherPayload(`personal-${i}`, { folderId: folder.id, favorite: i % 2 === 0 }) });
    const shared = await owner.json('/api/ciphers/create', {
      method: 'POST',
      json: { cipher: cipherPayload(`shared-${i}`, { organizationId: orgId }), collectionIds: [collectionId] },
    });
    await owner.json(`/api/ciphers/${shared.id}/attachment/v2`, {
      method: 'POST',
      json: { key: fakeEncString(`att-key-${i}`), fileName: fakeEncString(`file-${i}`), fileSize: 10 },
    });
    await owner.json('/api/sends', {
      method: 'POST',
      json: { type: 0, name: fakeEncString(`send-${i}`), key: fakeEncString('send-key'), text: { text: fakeEncString('t'), hidden: false }, deletionDate: inDays(7) },
    });
    await owner.json(`/api/organizations/${orgId}/collections`, { method: 'POST', json: { name: fakeEncString(`collection-${i}`), users: [], groups: [] } });
  }
}

before(async () => {
  server = await startTestServer();
  const client = new Client(server.baseUrl);
  alice = await client.registerAndLogin('alice@example.com');
  bob = await client.registerAndLogin('bob@example.com');
});

after(async () => {
  pg.Client.prototype.query = query;
  await server?.close();
});

test('a sync costs the same number of queries for a small and a large vault', async (t) => {
  const org = await alice.json('/api/organizations', {
    method: 'POST',
    json: {
      name: 'Budget',
      billingEmail: 'alice@example.com',
      key: fakeRsaEncString('org-key'),
      collectionName: fakeEncString('Default'),
      keys: { publicKey: 'b3JnLXB1Yg==', encryptedPrivateKey: fakeEncString('org-private') },
      planType: 0,
    },
  });
  const collectionId = (await alice.json('/api/sync')).collections[0].id;

  await fillVault(alice, org.id, collectionId, 1);
  await syncQueries(alice); // warms up what is set up once per process
  const small = await syncQueries(alice);

  await fillVault(alice, org.id, collectionId, 20);
  const large = await syncQueries(alice);
  const sync = await alice.json('/api/sync');
  assert.equal(sync.ciphers.length, 42);
  assert.equal(sync.collections.length, 22);

  assert.equal(large, small, `${small} queries for a small vault, ${large} for a large one`);
  t.diagnostic(`${small} queries per sync`);
  assert.ok(small > 0 && small <= 20, `${small} queries`);
  // Someone without an organization costs no more.
  assert.ok((await syncQueries(bob)) <= small);
});
