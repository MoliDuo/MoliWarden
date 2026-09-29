// Every route in tests/routes.ts is answered by a handler (never "route not
// found" or 405), and every non-public route rejects a request without a
// bearer token. Handlers may still refuse the empty sample requests (400, 403,
// 404 for an unknown id, ...); only routing is under test here.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, startTestServer, type Session, type TestServer } from './helpers';
import { ROUTES, type Route } from './routes';

let server: TestServer;
let client: Client;
const sessions: Session[] = [];
let requestCount = 0;

const SAMPLE_UUID = '6f7c1f4e-0b8e-4c55-9d3a-2f1b9e0c7a11';

function samplePath(path: string): string {
  const samples: Record<string, string> = { host: 'example.com', form: 'login', code: 'no-such-invite', token: 'invalid-token' };
  return path.replace(/(?<=[/=]):([a-zA-Z]+)/g, (_, name: string) => samples[name] ?? SAMPLE_UUID);
}

// Spread requests over client addresses and users so rate limits never answer
// in place of the route.
function nextAddress(): string {
  requestCount++;
  return `10.77.${Math.floor(requestCount / 250) % 250}.${requestCount % 250}`;
}

async function call([method, path]: Route, token?: string): Promise<Response> {
  const headers: Record<string, string> = { 'X-Forwarded-For': nextAddress(), Origin: server.baseUrl };
  let body: string | undefined;
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    body = '{}';
  }
  if (path === '/api/internal/cron') headers.Authorization = 'Bearer test-cron-secret';
  return client.fetch(samplePath(path), { method, headers, body, token });
}

async function isRouteMiss(response: Response): Promise<boolean> {
  if (response.status !== 404) return false;
  const text = await response.clone().text();
  return /route not found/i.test(text);
}

async function liveSession(index: number): Promise<Session> {
  const session = sessions[index];
  const probe = await client.fetch('/api/accounts/revision-date', {
    token: session.accessToken,
    headers: { 'X-Forwarded-For': nextAddress() },
  });
  if (probe.status === 200) return session;
  // A route under test ended the session (for example by rotating the
  // security stamp); log in again.
  sessions[index] = await client.login(session.email);
  return sessions[index];
}

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  sessions.push(await client.registerAndLogin('admin@example.com'));
  for (let i = 1; i < 4; i++) sessions.push(await client.registerAndLogin(`user${i}@example.com`));
});

after(async () => {
  await server?.close();
});

test('the inventory has no duplicate entries', () => {
  const keys = ROUTES.map(([method, path]) => `${method} ${path}`);
  assert.deepEqual(keys.filter((key, index) => keys.indexOf(key) !== index), []);
});

test('non-public routes require a bearer token', async () => {
  const problems: string[] = [];
  for (const route of ROUTES) {
    if (route[2] === 'public') continue;
    const response = await call(route);
    if (response.status !== 401) problems.push(`${route[0]} ${route[1]} -> ${response.status}`);
  }
  assert.deepEqual(problems, []);
});

test('public routes are answered without a token', async () => {
  const problems: string[] = [];
  for (const route of ROUTES) {
    if (route[2] !== 'public') continue;
    const response = await call(route);
    if (response.status === 405 || (await isRouteMiss(response))) problems.push(`${route[0]} ${route[1]} -> ${response.status}`);
  }
  assert.deepEqual(problems, []);
});

test('every route is answered with a token', async () => {
  const problems: string[] = [];
  let turn = 0;
  for (const route of ROUTES) {
    // Admin routes run as the instance admin; everything else rotates over
    // the plain users so no single account hits its request budget.
    const index = route[2] === 'admin' ? 0 : 1 + (turn++ % (sessions.length - 1));
    const session = await liveSession(index);
    const response = await call(route, session.accessToken);
    if (response.status === 405 || (await isRouteMiss(response))) {
      problems.push(`${route[0]} ${route[1]} -> ${response.status} ${await response.text()}`);
    }
  }
  assert.deepEqual(problems, []);
});

test('unknown paths are not routed', async () => {
  const response = await call(['GET', '/api/no-such-route', 'user'], sessions[0].accessToken);
  assert.ok(await isRouteMiss(response), `status ${response.status}`);
});
