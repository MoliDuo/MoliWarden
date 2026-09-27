// The web vault's import must stay under Vercel's 4.5 MB request body limit
// by splitting large imports; drives webapp/src/lib/api/vault.ts directly.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, cipherPayload, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';

let server: TestServer;
let alice: Session;

before(async () => {
  server = await startTestServer();
  alice = await new Client(server.baseUrl).registerAndLogin('alice@example.com');
});

after(async () => {
  await server?.close();
});

async function runImport(cipherCount: number, notesSize: number) {
  const { importCiphers } = await import('../webapp/src/lib/api/vault');
  const requests: number[] = [];
  const authedFetch = async (input: string, init: RequestInit = {}) => {
    if (typeof init.body === 'string') requests.push(init.body.length);
    return alice.request(input, init);
  };
  const folders = [{ name: fakeEncString('f0') }, { name: fakeEncString('f1') }];
  const ciphers = Array.from({ length: cipherCount }, (_, i) => ({
    ...cipherPayload(`imp-${i}`),
    id: `source-${i}`,
    notes: fakeEncString('n'.repeat(notesSize)),
  }));
  const folderRelationships = ciphers.map((_, i) => ({ key: i, value: i % 2 }));
  const map = await importCiphers(authedFetch as never, { folders, ciphers, folderRelationships }, { returnCipherMap: true });
  return { map: map || [], requests };
}

test('large import is split below the platform body limit and keeps folders and order', async () => {
  const { map, requests } = await runImport(1500, 1200);
  assert.ok(requests.length > 2, `split into ${requests.length} requests`);
  for (const size of requests) assert.ok(size < 4.5 * 1024 * 1024, `request of ${size} chars`);

  const sync = await alice.json('/api/sync?excludeDomains=true');
  assert.equal(sync.folders.length, 2);
  assert.equal(sync.ciphers.length, 1500);
  assert.equal(map.length, 1500);
  const byId = new Map(sync.ciphers.map((c: any) => [c.id, c]));
  const folderIds = new Set(sync.folders.map((f: any) => f.id));
  for (const entry of map) {
    assert.equal(entry.sourceId, `source-${entry.index}`);
    const cipher: any = byId.get(entry.id);
    assert.ok(cipher && folderIds.has(cipher.folderId), `cipher ${entry.index} is in a folder`);
  }
  const folderOf = (index: number) => (byId.get(map.find((e) => e.index === index)!.id) as any).folderId;
  assert.notEqual(folderOf(0), folderOf(1));
  assert.equal(folderOf(0), folderOf(1498));
});

test('small import stays a single request', async () => {
  const { requests } = await runImport(3, 10);
  assert.equal(requests.length, 1);
});
