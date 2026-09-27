// Compatibility test against the OFFICIAL Bitwarden CLI (@bitwarden/cli).
//
// Accounts and organizations are created with real client crypto
// (tests/bw-crypto.ts); everything a user would do day to day then goes
// through the official `bw` binary against this server over HTTPS.
//
//   TEST_DATABASE_URL=postgres://... npx tsx --test tests/official-cli.e2e.test.ts
//   BW_CLI=/path/to/bw   use a specific CLI build instead of the cached install
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startTestServer, type TestServer } from './helpers';
import { BwCli, createSelfSignedCert, encodeJson, resolveBwCli, type TlsMaterial } from './bw-cli';
import {
  createAccountMaterial,
  createOrganizationMaterial,
  decryptBytes,
  decryptString,
  splitKey,
  unwrapOrgKey,
  type RealAccount,
  type SymmetricKey,
} from './bw-crypto';

let server: TestServer;
let tls: TlsMaterial;
let bin: string;
let workDir: string;
const clis: BwCli[] = [];

interface ApiUser {
  account: RealAccount;
  userId: string;
  token: string;
  api<T = any>(path: string, init?: { method?: string; json?: unknown }): Promise<T>;
}

let alice: ApiUser; // instance admin + org owner
let bob: ApiUser; // org member, can edit
let carol: ApiUser; // org member, read-only
let aliceCli: BwCli;
let bobCli: BwCli;
let carolCli: BwCli;

async function http(path: string, init: { method?: string; json?: unknown; token?: string; form?: Record<string, string> } = {}): Promise<Response> {
  const headers: Record<string, string> = { 'Bitwarden-Client-Name': 'cli', 'Bitwarden-Client-Version': '2026.9.0', Origin: server.baseUrl };
  let body: string | undefined;
  if (init.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(init.json);
  }
  if (init.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(init.form).toString();
  }
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  return fetch(`${server.baseUrl}${path}`, { method: init.method || (body ? 'POST' : 'GET'), headers, body });
}

async function registerApiUser(email: string, password: string, inviteFrom?: ApiUser): Promise<ApiUser> {
  const account = createAccountMaterial(email, password);
  let inviteCode: string | undefined;
  if (inviteFrom) {
    const invite = await inviteFrom.api('/api/admin/invites', {
      method: 'POST',
      json: { expiresInHours: 1, masterPasswordHash: inviteFrom.account.masterPasswordHash },
    });
    inviteCode = invite.code ?? invite.invite?.code;
  }
  const registered = await http('/api/accounts/register', { json: { ...account.registerBody, inviteCode } });
  assert.equal(registered.status, 200, await registered.clone().text());

  const login = await http('/identity/connect/token', {
    form: {
      grant_type: 'password',
      username: email,
      password: account.masterPasswordHash,
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceIdentifier: crypto.randomUUID(),
      deviceName: 'e2e',
    },
  });
  const tokenText = await login.text();
  assert.equal(login.status, 200, tokenText);
  const token = JSON.parse(tokenText).access_token as string;
  const userId = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).sub as string;
  return {
    account,
    userId,
    token,
    async api(path, init = {}) {
      const response = await http(path, { ...init, token });
      const text = await response.text();
      if (!response.ok) throw new Error(`${init.method || 'GET'} ${path} -> ${response.status}: ${text}`);
      return text ? JSON.parse(text) : null;
    },
  };
}

function newCli(label: string): BwCli {
  const cli = new BwCli(bin, tls.certPath, label);
  clis.push(cli);
  return cli;
}

// `bw status --response` wraps the status in a template envelope.
async function cliStatus(cli: BwCli): Promise<any> {
  return (await cli.data(['status'])).template;
}

async function loginCli(cli: BwCli, user: ApiUser): Promise<void> {
  await cli.ok(['config', 'server', server.httpsUrl!]);
  const session = (await cli.ok(['login', user.account.email, user.account.password, '--raw'])).trim();
  assert.match(session, /^[A-Za-z0-9+/=]{20,}$/, 'login --raw prints the session key');
  cli.session = session;
}

// RFC 6238 with the CLI's defaults (SHA-1, 6 digits, 30 s).
function totpCodes(base32Secret: string): string[] {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32Secret.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const now = Math.floor(Date.now() / 1000 / 30);
  return [now - 1, now, now + 1].map((counter) => {
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const hmac = createHmac('sha1', key).update(message).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
  });
}

// Decrypts a cipher's name as stored on the server, honouring per-item keys.
function serverSideName(cipher: any, key: SymmetricKey): string {
  const itemKey = cipher.key ? splitKey(decryptBytes(cipher.key, key)) : key;
  return decryptString(cipher.name, itemKey);
}

before(async () => {
  bin = resolveBwCli();
  tls = createSelfSignedCert();
  workDir = mkdtempSync(join(tmpdir(), 'mw-bw-files-'));
  server = await startTestServer({ tls: { key: tls.key, cert: tls.cert } });
  alice = await registerApiUser('alice@example.com', 'alice master password');
  bob = await registerApiUser('bob@example.com', 'bob master password', alice);
  carol = await registerApiUser('carol@example.com', 'carol master password', alice);
});

after(async () => {
  for (const cli of clis) cli.dispose();
  if (workDir) rmSync(workDir, { recursive: true, force: true });
  if (tls) rmSync(tls.dir, { recursive: true, force: true });
  await server?.close();
});

// ---------------------------------------------------------------------------
// Personal vault
// ---------------------------------------------------------------------------

let folderId: string;
let loginItemId: string;
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

test('config server, login, status and sync', async () => {
  aliceCli = newCli('alice');
  await loginCli(aliceCli, alice);
  const status = await cliStatus(aliceCli);
  assert.equal(status.status, 'unlocked');
  assert.equal(status.userEmail, 'alice@example.com');
  assert.equal(status.userId, alice.userId);
  assert.equal(status.serverUrl, server.httpsUrl);
  await aliceCli.ok(['sync']);
  const after = await cliStatus(aliceCli);
  assert.ok(after.lastSync, 'sync records lastSync');

  // The CLI reported its user key id once (key id backfill); sync echoes it.
  const sync = await alice.api('/api/sync');
  assert.match(sync.userDecryption.userKeyId ?? '', /^[A-Za-z0-9+/=_-]+$/);
  assert.equal(sync.UserDecryption.UserKeyId, sync.userDecryption.userKeyId);
});

test('folders and login items: create, list, get, edit', async () => {
  const folder = await aliceCli.data(['create', 'folder', encodeJson({ name: 'Work' })]);
  folderId = folder.id;
  assert.equal(folder.name, 'Work');
  const folders = await aliceCli.data(['list', 'folders']);
  assert.ok(folders.data.some((f: any) => f.id === folderId && f.name === 'Work'));

  const item = await aliceCli.data([
    'create',
    'item',
    encodeJson({
      type: 1,
      name: 'Example login',
      notes: 'some notes',
      favorite: true,
      folderId,
      reprompt: 0,
      fields: [{ name: 'custom', value: 'field value', type: 0 }],
      login: {
        username: 'alice-user',
        password: 'Secr3t! pässword',
        totp: TOTP_SECRET,
        uris: [{ uri: 'https://example.com/login', match: null }],
      },
    }),
  ]);
  loginItemId = item.id;
  assert.equal(item.name, 'Example login');
  assert.equal(item.folderId, folderId);

  // What the server stores must be decryptable with the real user key.
  const stored = await alice.api(`/api/ciphers/${loginItemId}`);
  assert.equal(serverSideName(stored, alice.account.userKey), 'Example login');

  const items = await aliceCli.data(['list', 'items', '--search', 'Example']);
  assert.deepEqual(items.data.map((i: any) => i.id), [loginItemId]);
  const inFolder = await aliceCli.data(['list', 'items', '--folderid', folderId]);
  assert.equal(inFolder.data.length, 1);

  const got = await aliceCli.data(['get', 'item', loginItemId]);
  assert.equal(got.login.username, 'alice-user');
  assert.equal(got.login.uris[0].uri, 'https://example.com/login');
  assert.equal(got.fields[0].value, 'field value');
  assert.equal(got.notes, 'some notes');
  assert.equal(got.favorite, true);

  assert.equal((await aliceCli.ok(['get', 'password', loginItemId, '--raw'])).trim(), 'Secr3t! pässword');
  assert.equal((await aliceCli.ok(['get', 'username', 'Example login', '--raw'])).trim(), 'alice-user');
  const code = (await aliceCli.ok(['get', 'totp', loginItemId, '--raw'])).trim();
  assert.ok(totpCodes(TOTP_SECRET).includes(code), `totp ${code}`);

  got.name = 'Example login (edited)';
  got.login.password = 'n3w-password';
  const edited = await aliceCli.data(['edit', 'item', loginItemId, encodeJson(got)]);
  assert.equal(edited.name, 'Example login (edited)');
  await aliceCli.ok(['sync']);
  assert.equal((await aliceCli.ok(['get', 'password', loginItemId, '--raw'])).trim(), 'n3w-password');
  const history = (await aliceCli.data(['get', 'item', loginItemId])).passwordHistory;
  assert.ok(history?.some((h: any) => h.password === 'Secr3t! pässword'), 'password history kept');

  const renamed = await aliceCli.data(['edit', 'folder', folderId, encodeJson({ name: 'Work stuff' })]);
  assert.equal(renamed.name, 'Work stuff');
});

test('secure note, card and identity items', async () => {
  const note = await aliceCli.data(['create', 'item', encodeJson({ type: 2, name: 'A note', notes: 'secret note body', secureNote: { type: 0 } })]);
  const card = await aliceCli.data([
    'create',
    'item',
    encodeJson({ type: 3, name: 'Visa', card: { cardholderName: 'Alice', brand: 'Visa', number: '4111111111111111', expMonth: '1', expYear: '2030', code: '123' } }),
  ]);
  const identity = await aliceCli.data([
    'create',
    'item',
    encodeJson({ type: 4, name: 'Me', identity: { firstName: 'Alice', lastName: 'Liddell', email: 'alice@example.com' } }),
  ]);
  await aliceCli.ok(['sync']);
  assert.equal((await aliceCli.data(['get', 'notes', note.id])).data, 'secret note body');
  assert.equal((await aliceCli.data(['get', 'item', card.id])).card.number, '4111111111111111');
  assert.equal((await aliceCli.data(['get', 'item', identity.id])).identity.lastName, 'Liddell');
  // Clean up with a permanent delete (bypasses the trash).
  await aliceCli.ok(['delete', 'item', note.id, '--permanent']);
  await aliceCli.ok(['sync']);
  assert.notEqual((await aliceCli.run(['get', 'item', note.id])).code, 0);
});

test('delete to trash and restore', async () => {
  await aliceCli.ok(['delete', 'item', loginItemId]);
  const trash = await aliceCli.data(['list', 'items', '--trash']);
  assert.ok(trash.data.some((i: any) => i.id === loginItemId));
  assert.ok((await alice.api(`/api/ciphers/${loginItemId}`)).deletedDate);

  await aliceCli.ok(['restore', 'item', loginItemId]);
  const items = await aliceCli.data(['list', 'items']);
  assert.ok(items.data.some((i: any) => i.id === loginItemId && !i.deletedDate));
  assert.equal((await alice.api(`/api/ciphers/${loginItemId}`)).deletedDate, null);
});

test('attachments: upload and download round-trip', async () => {
  const content = Buffer.concat([Buffer.from('attachment payload é\n'), Buffer.alloc(70_000, 7)]);
  const filePath = join(workDir, 'report.bin');
  writeFileSync(filePath, content);
  const updated = await aliceCli.data(['create', 'attachment', '--file', filePath, '--itemid', loginItemId]);
  const attachment = updated.attachments.find((a: any) => a.fileName === 'report.bin');
  assert.ok(attachment, 'attachment listed on the item');

  const outPath = join(workDir, 'downloaded.bin');
  await aliceCli.ok(['get', 'attachment', attachment.id, '--itemid', loginItemId, '--output', outPath]);
  assert.deepEqual(readFileSync(outPath), content);

  // The stored blob is encrypted, not the plaintext.
  const meta = await alice.api(`/api/ciphers/${loginItemId}/attachment/${attachment.id}`);
  const blob = Buffer.from(await (await fetch(meta.url.replace(server.httpsUrl!, server.baseUrl))).arrayBuffer());
  assert.notDeepEqual(blob, content);

  await aliceCli.ok(['delete', 'attachment', attachment.id, '--itemid', loginItemId]);
  await aliceCli.ok(['sync']);
  assert.equal((await aliceCli.data(['get', 'item', loginItemId])).attachments?.length ?? 0, 0);
});

test('sends: text and file, received through the access URL', async () => {
  const textSend = await aliceCli.data(['send', '-n', 'text send', '--fullObject', 'hello from a send']);
  assert.ok(textSend.accessUrl.startsWith(server.httpsUrl!), textSend.accessUrl);
  const received = await aliceCli.ok(['send', 'receive', textSend.accessUrl, '--raw']);
  assert.equal(received.trim(), 'hello from a send');

  const sendList = await aliceCli.data(['send', 'list']);
  assert.ok(sendList.data.some((s: any) => s.id === textSend.id && s.name === 'text send'));

  const fileContent = Buffer.from('file send content\n'.repeat(100));
  const filePath = join(workDir, 'shared.txt');
  writeFileSync(filePath, fileContent);
  const fileSend = await aliceCli.data(['send', '-f', filePath, '--fullObject']);
  assert.equal(fileSend.type, 1);
  const outPath = join(workDir, 'received.txt');
  await aliceCli.ok(['send', 'receive', fileSend.accessUrl, '--output', outPath]);
  assert.deepEqual(readFileSync(outPath), fileContent);

  // Password-protected send.
  const protectedSend = await aliceCli.data(['send', '-n', 'pw send', '--password', 'letmein', '--fullObject', 'guarded']);
  assert.notEqual((await aliceCli.run(['send', 'receive', protectedSend.accessUrl])).code, 0);
  assert.equal((await aliceCli.ok(['send', 'receive', protectedSend.accessUrl, '--password', 'letmein', '--raw'])).trim(), 'guarded');

  await aliceCli.ok(['send', 'delete', textSend.id]);
  const remaining = await aliceCli.data(['send', 'list']);
  assert.ok(!remaining.data.some((s: any) => s.id === textSend.id));
});

test('export json contains decrypted vault data', async () => {
  const outPath = join(workDir, 'export.json');
  await aliceCli.ok(['export', '--format', 'json', '--output', outPath]);
  const exported = JSON.parse(readFileSync(outPath, 'utf8'));
  assert.equal(exported.encrypted, false);
  const item = exported.items.find((i: any) => i.id === loginItemId);
  assert.equal(item.login.password, 'n3w-password');
  assert.ok(exported.folders.some((f: any) => f.name === 'Work stuff'));
});

test('lock, unlock, logout and log in again', async () => {
  await aliceCli.ok(['lock']);
  assert.equal((await cliStatus(aliceCli)).status, 'locked');
  assert.notEqual((await aliceCli.run(['list', 'items'])).code, 0, 'locked vault refuses to list');
  assert.notEqual((await aliceCli.run(['unlock', 'wrong password', '--raw'])).code, 0);
  aliceCli.session = (await aliceCli.ok(['unlock', alice.account.password, '--raw'])).trim();
  assert.equal((await cliStatus(aliceCli)).status, 'unlocked');
  assert.equal((await aliceCli.ok(['get', 'password', loginItemId, '--raw'])).trim(), 'n3w-password');

  await aliceCli.ok(['logout']);
  aliceCli.session = null;
  assert.equal((await cliStatus(aliceCli)).status, 'unauthenticated');
  assert.notEqual((await aliceCli.run(['login', alice.account.email, 'not the password', '--raw'])).code, 0);
  const session = (await aliceCli.ok(['login', alice.account.email, alice.account.password, '--raw'])).trim();
  aliceCli.session = session;
  assert.equal((await aliceCli.ok(['get', 'password', loginItemId, '--raw'])).trim(), 'n3w-password');
});

test('login with a personal API key (client_credentials)', async () => {
  const apiKey = await alice.api('/api/accounts/api-key', { method: 'POST', json: { masterPasswordHash: alice.account.masterPasswordHash } });
  const cli = newCli('alice-apikey');
  await cli.ok(['config', 'server', server.httpsUrl!]);
  await cli.ok(['login', '--apikey'], { BW_CLIENTID: `user.${alice.userId}`, BW_CLIENTSECRET: apiKey.apiKey });
  assert.equal((await cliStatus(cli)).status, 'locked');
  cli.session = (await cli.ok(['unlock', alice.account.password, '--raw'])).trim();
  assert.equal((await cli.ok(['get', 'password', loginItemId, '--raw'])).trim(), 'n3w-password');

  const wrong = newCli('alice-apikey-wrong');
  await wrong.ok(['config', 'server', server.httpsUrl!]);
  assert.notEqual((await wrong.run(['login', '--apikey'], { BW_CLIENTID: `user.${alice.userId}`, BW_CLIENTSECRET: 'wrong-secret' })).code, 0);
  await cli.ok(['logout']);
});

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

let orgId: string;
let orgKey: SymmetricKey;
let defaultCollectionId: string;
let secondCollectionId: string;
let orgItemId: string;
const memberIds: Record<string, string> = {};

test('organization created with real keys is usable by the owner CLI', async () => {
  const org = createOrganizationMaterial('Family Vault', alice.account.email, alice.account, 'Shared logins');
  orgKey = org.orgKey;
  const created = await alice.api('/api/organizations', { method: 'POST', json: org.createBody });
  orgId = created.id;

  await aliceCli.ok(['sync']);
  const orgs = await aliceCli.data(['list', 'organizations']);
  const listed = orgs.data.find((o: any) => o.id === orgId);
  assert.ok(listed, 'organization listed');
  assert.equal(listed.name, 'Family Vault');
  assert.equal(listed.status, 2);
  assert.equal(listed.type, 0);

  const collections = await aliceCli.data(['list', 'org-collections', '--organizationid', orgId]);
  assert.equal(collections.data.length, 1);
  assert.equal(collections.data[0].name, 'Shared logins');
  defaultCollectionId = collections.data[0].id;
  const mine = await aliceCli.data(['list', 'collections']);
  assert.ok(mine.data.some((c: any) => c.id === defaultCollectionId && c.name === 'Shared logins'));

  const second = await aliceCli.data([
    'create',
    'org-collection',
    encodeJson({ organizationId: orgId, name: 'Second collection', externalId: null, groups: [], users: [] }),
    '--organizationid',
    orgId,
  ]);
  secondCollectionId = second.id;
  assert.equal(second.name, 'Second collection');
  const details = await alice.api(`/api/organizations/${orgId}/collections/${secondCollectionId}/details`);
  assert.equal(decryptString(details.name, orgKey), 'Second collection');
});

test('invited members accept, owner confirms them with the CLI', async () => {
  await alice.api(`/api/organizations/${orgId}/users/invite`, {
    method: 'POST',
    json: { emails: [bob.account.email], type: 2, collections: [{ id: defaultCollectionId, readOnly: false, hidePasswords: false, manage: false }], groups: [] },
  });
  await alice.api(`/api/organizations/${orgId}/users/invite`, {
    method: 'POST',
    json: { emails: [carol.account.email], type: 2, collections: [{ id: defaultCollectionId, readOnly: true, hidePasswords: false, manage: false }], groups: [] },
  });
  for (const user of [bob, carol]) {
    const invitations = await user.api('/api/organizations/invitations');
    const invitation = invitations.data.find((i: any) => i.organizationId === orgId) ?? invitations.data[0];
    await user.api(`/api/organizations/${orgId}/users/${invitation.id}/accept`, { method: 'POST', json: {} });
  }

  const members = await aliceCli.data(['list', 'org-members', '--organizationid', orgId]);
  for (const user of [bob, carol]) {
    const member = members.data.find((m: any) => m.email === user.account.email);
    assert.ok(member, `${user.account.email} listed`);
    assert.equal(member.status, 1, 'accepted, awaiting confirmation');
    memberIds[user.account.email] = member.id;
    await aliceCli.ok(['confirm', 'org-member', member.id, '--organizationid', orgId]);
  }
  const confirmed = await aliceCli.data(['list', 'org-members', '--organizationid', orgId]);
  for (const user of [bob, carol]) {
    assert.equal(confirmed.data.find((m: any) => m.email === user.account.email).status, 2);
  }

  // The CLI wrapped the org key with each member's RSA key: they can unwrap it.
  for (const user of [bob, carol]) {
    const sync = await user.api('/api/sync');
    const membership = sync.profile.organizations.find((o: any) => o.id === orgId);
    assert.equal(membership.status, 2);
    const key = unwrapOrgKey(membership.key, user.account);
    assert.deepEqual(key.enc, orgKey.enc);
    assert.deepEqual(key.mac, orgKey.mac);
  }
});

test('owner shares a personal item and creates org items via the CLI', async () => {
  const moved = await aliceCli.data(['move', loginItemId, orgId, encodeJson([defaultCollectionId])]);
  assert.equal(moved.organizationId, orgId);
  assert.deepEqual(moved.collectionIds, [defaultCollectionId]);
  const stored = await alice.api(`/api/ciphers/${loginItemId}`);
  assert.equal(stored.organizationId, orgId);
  assert.equal(serverSideName(stored, orgKey), 'Example login (edited)');

  const created = await aliceCli.data([
    'create',
    'item',
    encodeJson({
      type: 1,
      name: 'Org router',
      organizationId: orgId,
      collectionIds: [defaultCollectionId],
      notes: null,
      login: { username: 'admin', password: 'router-pass', uris: [{ uri: 'http://192.168.1.1', match: null }], totp: null },
    }),
  ]);
  orgItemId = created.id;
  assert.equal(created.organizationId, orgId);
  assert.deepEqual(created.collectionIds, [defaultCollectionId]);
  assert.equal(serverSideName(await alice.api(`/api/ciphers/${orgItemId}`), orgKey), 'Org router');

  const orgItems = await aliceCli.data(['list', 'items', '--organizationid', orgId]);
  assert.deepEqual(orgItems.data.map((i: any) => i.id).sort(), [loginItemId, orgItemId].sort());
  const inCollection = await aliceCli.data(['list', 'items', '--collectionid', defaultCollectionId]);
  assert.equal(inCollection.data.length, 2);
});

test('members decrypt shared items with their own CLI', async () => {
  bobCli = newCli('bob');
  await loginCli(bobCli, bob);
  await bobCli.ok(['sync']);
  const orgs = await bobCli.data(['list', 'organizations']);
  assert.deepEqual(orgs.data.map((o: any) => o.id), [orgId]);
  const collections = await bobCli.data(['list', 'collections']);
  assert.deepEqual(collections.data.map((c: any) => c.name), ['Shared logins']);

  const shared = await bobCli.data(['get', 'item', loginItemId]);
  assert.equal(shared.name, 'Example login (edited)');
  assert.equal(shared.login.username, 'alice-user');
  assert.equal((await bobCli.ok(['get', 'password', loginItemId, '--raw'])).trim(), 'n3w-password');
  const router = await bobCli.data(['get', 'item', orgItemId]);
  assert.equal(router.name, 'Org router');
  assert.equal(router.login.password, 'router-pass');
  const orgItems = await bobCli.data(['list', 'items', '--organizationid', orgId]);
  assert.equal(orgItems.data.length, 2);

  // A member with edit rights can change the shared item; the owner sees it.
  router.login.password = 'router-pass-2';
  await bobCli.data(['edit', 'item', orgItemId, encodeJson(router)]);
  await aliceCli.ok(['sync']);
  assert.equal((await aliceCli.ok(['get', 'password', orgItemId, '--raw'])).trim(), 'router-pass-2');
});

test('attachments on shared items are readable by members', async () => {
  const content = Buffer.from('shared attachment \u2713 '.repeat(500));
  const filePath = join(workDir, 'org-file.txt');
  writeFileSync(filePath, content);
  const updated = await aliceCli.data(['create', 'attachment', '--file', filePath, '--itemid', orgItemId]);
  const attachment = updated.attachments.find((a: any) => a.fileName === 'org-file.txt');
  assert.ok(attachment);

  await bobCli.ok(['sync']);
  const outPath = join(workDir, 'org-file-bob.txt');
  await bobCli.ok(['get', 'attachment', 'org-file.txt', '--itemid', orgItemId, '--output', outPath]);
  assert.deepEqual(readFileSync(outPath), content);
  await aliceCli.ok(['delete', 'attachment', attachment.id, '--itemid', orgItemId]);
});

test('members with edit rights can trash and restore shared items', async () => {
  await bobCli.ok(['delete', 'item', loginItemId]);
  assert.ok((await alice.api(`/api/ciphers/${loginItemId}`)).deletedDate);
  await bobCli.ok(['restore', 'item', loginItemId]);
  assert.equal((await alice.api(`/api/ciphers/${loginItemId}`)).deletedDate, null);
});

test('collection assignment is edited with item-collections', async () => {
  const updated = await aliceCli.data([
    'edit',
    'item-collections',
    orgItemId,
    encodeJson([defaultCollectionId, secondCollectionId]),
    '--organizationid',
    orgId,
  ]);
  assert.deepEqual([...updated.collectionIds].sort(), [defaultCollectionId, secondCollectionId].sort());
  const stored = await alice.api(`/api/ciphers/${orgItemId}`);
  assert.deepEqual([...stored.collectionIds].sort(), [defaultCollectionId, secondCollectionId].sort());

  // Moved out of the only collection Bob can see: it disappears for him.
  await aliceCli.data(['edit', 'item-collections', orgItemId, encodeJson([secondCollectionId]), '--organizationid', orgId]);
  await bobCli.ok(['sync']);
  assert.notEqual((await bobCli.run(['get', 'item', orgItemId])).code, 0);
  await aliceCli.data(['edit', 'item-collections', orgItemId, encodeJson([defaultCollectionId]), '--organizationid', orgId]);
});

test('read-only members can read but not change shared items', async () => {
  carolCli = newCli('carol');
  await loginCli(carolCli, carol);
  await carolCli.ok(['sync']);
  const item = await carolCli.data(['get', 'item', orgItemId]);
  assert.equal(item.login.password, 'router-pass-2');

  item.name = 'hijacked';
  const edit = await carolCli.run(['edit', 'item', orgItemId, encodeJson(item)]);
  assert.notEqual(edit.code, 0, 'read-only edit must fail');
  const del = await carolCli.run(['delete', 'item', orgItemId]);
  assert.notEqual(del.code, 0, 'read-only delete must fail');

  const stored = await alice.api(`/api/ciphers/${orgItemId}`);
  assert.equal(serverSideName(stored, orgKey), 'Org router');
  assert.equal(stored.deletedDate, null);
  // Nor can a plain member create items in the org.
  const create = await carolCli.run([
    'create',
    'item',
    encodeJson({ type: 2, name: 'x', organizationId: orgId, collectionIds: [defaultCollectionId], secureNote: { type: 0 } }),
  ]);
  assert.notEqual(create.code, 0);
});

test('org collections are renamed and deleted with the CLI', async () => {
  const extra = await aliceCli.data([
    'create',
    'org-collection',
    encodeJson({ organizationId: orgId, name: 'Temporary', externalId: null, groups: [], users: [] }),
    '--organizationid',
    orgId,
  ]);
  const fetched = await aliceCli.data(['get', 'org-collection', extra.id, '--organizationid', orgId]);
  assert.equal(fetched.name, 'Temporary');
  const renamed = await aliceCli.data([
    'edit',
    'org-collection',
    extra.id,
    encodeJson({ ...fetched, name: 'Renamed' }),
    '--organizationid',
    orgId,
  ]);
  assert.equal(renamed.name, 'Renamed');
  await aliceCli.ok(['delete', 'org-collection', extra.id, '--organizationid', orgId]);
  const remaining = await aliceCli.data(['list', 'org-collections', '--organizationid', orgId]);
  assert.deepEqual(remaining.data.map((c: any) => c.name).sort(), ['Second collection', 'Shared logins']);
});

test('org export by the owner includes shared items', async () => {
  const outPath = join(workDir, 'org-export.json');
  await aliceCli.ok(['export', '--organizationid', orgId, '--format', 'json', '--output', outPath]);
  const exported = JSON.parse(readFileSync(outPath, 'utf8'));
  const names = exported.items.map((i: any) => i.name).sort();
  assert.deepEqual(names, ['Example login (edited)', 'Org router']);
  assert.deepEqual(exported.collections.map((c: any) => c.name).sort(), ['Second collection', 'Shared logins']);
});
