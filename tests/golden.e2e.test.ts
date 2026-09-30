// Golden snapshots of what official clients parse: token responses, sync,
// every cipher type, errors and headers. Ids, dates and secrets are masked;
// everything else must match tests/golden/*.json exactly.
//
// A deliberate change to a response is recorded with
//   UPDATE_GOLDEN=1 npx tsx --test tests/golden.e2e.test.ts
// and the diff of tests/golden/ is reviewed like code.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client, startTestServer, type TestServer } from './helpers';
import { TotpCodes } from './totp';

const GOLDEN_DIR = fileURLToPath(new URL('./golden/', import.meta.url));
const UPDATE = process.env.UPDATE_GOLDEN === '1';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/;
const JWT = /^eyJ[\w-]*\.[\w-]+\.[\w-]+$/;
// Values that are random per run whatever their shape.
const VOLATILE_KEYS = new Set(['refresh_token', 'securitystamp', 'sstamp', 'dstamp', 'accessid', 'key_id', 'usertoken', 'userverificationtoken']);
const VOLATILE_HEADERS = new Set(['date', 'content-length', 'connection', 'keep-alive', 'transfer-encoding', 'etag']);

// Ids and per-run secrets are named after what the test created, so a
// snapshot reads "<cipher:card>" rather than a UUID.

function name<T extends { id: string }>(entity: T, label: string): T {
  names.set(entity.id, label);
  return entity;
}

function mask(value: unknown, key = ''): unknown {
  if (typeof value === 'string') {
    if (VOLATILE_KEYS.has(key.toLowerCase())) return '<volatile>';
    if (names.has(value)) return `<${names.get(value)}>`;
    if (UUID.test(value)) return `<${names.get(value.toLowerCase()) ?? 'uuid'}>`;
    if (ISO_DATE.test(value)) return '<date>';
    if (JWT.test(value)) return '<jwt>';
    // The test server listens on a random port.
    return server ? value.replaceAll(server.baseUrl, '<origin>') : value;
  }
  if (typeof value === 'number' && value > 1_500_000_000_000 && value < 5_000_000_000_000) return '<epoch-ms>';
  if (Array.isArray(value)) {
    const items = value.map((item) => mask(item));
    // Order of listed entities is not part of the contract.
    if (items.every((item) => item && typeof item === 'object' && 'id' in item)) {
      items.sort((a: any, b: any) => String(a.id).localeCompare(String(b.id)));
    }
    return items;
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, mask(v, k)]));
  }
  return value;
}

function golden(file: string, value: unknown): void {
  const path = `${GOLDEN_DIR}${file}.json`;
  const actual = mask(value);
  if (UPDATE) {
    mkdirSync(GOLDEN_DIR, { recursive: true });
    writeFileSync(path, `${JSON.stringify(actual, null, 2)}\n`);
    return;
  }
  assert.ok(existsSync(path), `missing snapshot ${file}.json; record it with UPDATE_GOLDEN=1`);
  assert.deepStrictEqual(actual, JSON.parse(readFileSync(path, 'utf8')), `snapshot ${file}.json`);
}

async function response(res: Response): Promise<{ status: number; headers: Record<string, string>; body: unknown }> {
  const headers = Object.fromEntries(
    [...res.headers.entries()].filter(([header]) => !VOLATILE_HEADERS.has(header)).sort(([a], [b]) => a.localeCompare(b)),
  );
  const text = await res.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON; keep the text.
  }
  return { status: res.status, headers, body };
}

// Deterministic EncStrings keep the snapshots free of masks for ciphertext.
function enc(label: string): string {
  const b64 = (text: string) => Buffer.from(text).toString('base64');
  return `2.${b64(`iv-${label}`)}|${b64(`ct-${label}`)}|${b64(`mac-${label}`)}`;
}

const names = new Map<string, string>();

const EMAIL = 'golden@example.com';
const PASSWORD_HASH = Buffer.from('hash-golden').toString('base64');
const DEVICE = '0f4b2c1e-5d6a-4b7c-8e9f-a0b1c2d3e4f5';
const SECOND_DEVICE = '1a2b3c4d-0000-4000-8000-000000000001';
names.set(DEVICE, 'device');
names.set(SECOND_DEVICE, 'second-device');

let server: TestServer;
let client: Client;
let accessToken = '';
let refreshToken = '';

function form(fields: Record<string, string>): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  };
}

function passwordGrant(extra: Record<string, string> = {}): RequestInit {
  return form({
    grant_type: 'password',
    username: EMAIL,
    password: PASSWORD_HASH,
    scope: 'api offline_access',
    client_id: 'cli',
    deviceType: '8',
    deviceIdentifier: DEVICE,
    deviceName: 'golden',
    ...extra,
  });
}

async function api(path: string, init: RequestInit & { json?: unknown } = {}): Promise<Response> {
  return client.fetch(path, { ...init, token: accessToken });
}

async function apiJson(path: string, init: RequestInit & { json?: unknown } = {}): Promise<any> {
  const res = await api(path, init);
  const text = await res.text();
  assert.ok(res.ok, `${init.method ?? 'GET'} ${path} -> ${res.status} ${text}`);
  return JSON.parse(text);
}

const CIPHERS: Array<[string, Record<string, unknown>]> = [
  ['login', {
    type: 1,
    login: {
      username: enc('username'),
      password: enc('password'),
      totp: enc('totp'),
      uris: [{ uri: enc('uri'), match: 0 }],
      passwordRevisionDate: '2025-01-02T03:04:05.000Z',
    },
    fields: [{ name: enc('field-name'), value: enc('field-value'), type: 0, linkedId: null }],
    passwordHistory: [{ password: enc('old-password'), lastUsedDate: '2025-01-01T00:00:00.000Z' }],
  }],
  ['note', { type: 2, secureNote: { type: 0 } }],
  ['card', {
    type: 3,
    card: { cardholderName: enc('holder'), brand: enc('brand'), number: enc('number'), expMonth: enc('month'), expYear: enc('year'), code: enc('code') },
  }],
  ['identity', {
    type: 4,
    identity: { title: enc('title'), firstName: enc('first'), lastName: enc('last'), email: enc('email'), phone: enc('phone'), address1: enc('address') },
  }],
  ['ssh-key', { type: 5, sshKey: { privateKey: enc('private'), publicKey: enc('public'), keyFingerprint: enc('fingerprint') } }],
  ['bank-account', { type: 6, bankAccount: { bankName: enc('bank'), accountNumber: enc('account'), iban: enc('iban') } }],
  ['drivers-license', { type: 7, driversLicense: { firstName: enc('first'), licenseNumber: enc('license') } }],
  ['passport', { type: 8, passport: { surname: enc('surname'), passportNumber: enc('passport') } }],
];

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
});

after(async () => {
  await server?.close();
});

test('registration and prelogin', async () => {
  const unknown = await client.fetch('/identity/accounts/prelogin', { method: 'POST', json: { email: 'nobody@example.com' } });
  golden('prelogin-unknown', await response(unknown));

  const registered = await client.fetch('/api/accounts/register', {
    method: 'POST',
    headers: { Origin: server.baseUrl },
    json: {
      email: EMAIL,
      name: 'Golden',
      masterPasswordHash: PASSWORD_HASH,
      key: enc('user-key'),
      keys: { publicKey: Buffer.from('golden-public-key').toString('base64'), encryptedPrivateKey: enc('private-key') },
      kdf: 0,
      kdfIterations: 600000,
    },
  });
  golden('register', await response(registered));

  const known = await client.fetch('/identity/accounts/prelogin', { method: 'POST', json: { email: EMAIL } });
  golden('prelogin', await response(known));
});

test('token responses', async () => {
  const login = await client.fetch('/identity/connect/token', passwordGrant());
  const token = await response(login);
  golden('token-password', token);
  const body = token.body as any;
  const claims = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64url').toString());
  names.set(claims.sub, 'user');
  golden('access-token-claims', { header: JSON.parse(Buffer.from(body.access_token.split('.')[0], 'base64url').toString()), claims: { ...claims, iat: '<iat>', exp: claims.exp - claims.iat } });

  accessToken = body.access_token;
  refreshToken = body.refresh_token;

  const refreshed = await client.fetch('/identity/connect/token', form({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: refreshToken }));
  golden('token-refresh', await response(refreshed));

  const wrong = await client.fetch('/identity/connect/token', passwordGrant({ password: Buffer.from('wrong').toString('base64') }));
  golden('error-invalid-grant', await response(wrong));
});

test('profile, devices and web bootstrap', async () => {
  golden('profile', await response(await api('/api/accounts/profile')));
  golden('devices', await response(await api('/api/devices')));
  golden('web-bootstrap', await response(await client.fetch('/api/web-bootstrap')));
  golden('config', await response(await client.fetch('/api/config')));
});

test('folders and every cipher type', async () => {
  const folder = name(await apiJson('/api/folders', { method: 'POST', json: { name: enc('folder') } }), 'folder');
  golden('folder', folder);

  for (const [label, payload] of CIPHERS) {
    const res = await api('/api/ciphers', {
      method: 'POST',
      json: {
        name: enc(`name-${label}`),
        notes: enc(`notes-${label}`),
        favorite: label === 'login',
        folderId: label === 'login' ? folder.id : null,
        reprompt: 0,
        ...payload,
      },
    });
    const snapshot = await response(res);
    name(snapshot.body as { id: string }, `cipher:${label}`);
    golden(`cipher-${label}`, snapshot);
  }
});

test('organization cipher', async () => {
  const org = name(await apiJson('/api/organizations', {
    method: 'POST',
    json: {
      name: 'Golden Org',
      billingEmail: EMAIL,
      key: `4.${Buffer.from('org-key').toString('base64')}`,
      collectionName: enc('collection'),
      keys: { publicKey: Buffer.from('org-public').toString('base64'), encryptedPrivateKey: enc('org-private') },
      planType: 0,
    },
  }), 'org');
  golden('organization', org);
  const collections = await apiJson(`/api/organizations/${org.id}/collections`);
  name(collections.data[0], 'collection');
  golden('collections', collections);

  const created = await api('/api/ciphers/create', {
    method: 'POST',
    json: {
      cipher: { type: 1, name: enc('org-item'), organizationId: org.id, login: { username: enc('org-user'), password: enc('org-pass') }, reprompt: 0 },
      collectionIds: [collections.data[0].id],
    },
  });
  const snapshot = await response(created);
  name(snapshot.body as { id: string }, 'cipher:org');
  golden('cipher-org', snapshot);
});

test('send', async () => {
  const created = await api('/api/sends', {
    method: 'POST',
    json: {
      type: 0,
      name: enc('send'),
      notes: enc('send-notes'),
      key: enc('send-key'),
      text: { text: enc('send-text'), hidden: false },
      deletionDate: new Date(Date.now() + 86400000).toISOString(),
      expirationDate: null,
      maxAccessCount: 5,
      disabled: false,
      hideEmail: false,
    },
  });
  const snapshot = await response(created);
  const send = name(snapshot.body as { id: string; accessId: string }, 'send');
  golden('send', snapshot);

  const accessed = await client.fetch(`/api/sends/access/${send.accessId}`, { method: 'POST', json: {} });
  golden('send-access', await response(accessed));
});

test('sync', async () => {
  golden('sync', await response(await api('/api/sync')));
});

test('error bodies', async () => {
  golden('error-unauthorized', await response(await client.fetch('/api/sync')));
  golden('error-route-not-found', await response(await api('/api/no-such-route')));
  golden('error-cipher-not-found', await response(await api('/api/ciphers/00000000-0000-4000-8000-000000000000')));
  golden('error-validation', await response(await api('/api/ciphers', { method: 'POST', json: { type: 1, name: 'plaintext', login: {} } })));
});

test('CORS and security headers', async () => {
  const preflight = await client.fetch('/api/ciphers', {
    method: 'OPTIONS',
    headers: { Origin: server.baseUrl, 'Access-Control-Request-Method': 'PUT', 'Access-Control-Request-Headers': 'authorization,content-type' },
  });
  golden('cors-preflight', await response(preflight));
  const foreign = await client.fetch('/api/ciphers', {
    method: 'OPTIONS',
    headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'PUT' },
  });
  golden('cors-preflight-foreign', await response(foreign));
  const extension = await client.fetch('/api/sync', { token: accessToken, headers: { Origin: 'chrome-extension://abcdefghijklmnop' } });
  golden('headers-api-extension-origin', (await response(extension)).headers);
});

test('two-factor challenge', async () => {
  const setup = await apiJson('/api/two-factor/get-authenticator', { method: 'POST', json: { masterPasswordHash: PASSWORD_HASH } });
  const key = setup.key ?? setup.Key;
  names.set(key, 'totp-secret');
  const { code } = await new TotpCodes().next(key);
  golden('two-factor-enabled', await response(await api('/api/two-factor/authenticator', {
    method: 'PUT',
    json: { key, token: code, userVerificationToken: setup.userVerificationToken ?? setup.UserVerificationToken, masterPasswordHash: PASSWORD_HASH },
  })));

  const challenge = await client.fetch('/identity/connect/token', passwordGrant({ deviceIdentifier: SECOND_DEVICE }));
  golden('two-factor-challenge', await response(challenge));
});
