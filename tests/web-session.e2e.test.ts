// Web vault session: with `X-MoliWarden-Web-Session: 1` the refresh token
// never appears in JSON; it lives in an HttpOnly, SameSite=Strict cookie
// scoped to /identity/connect, and refresh / revocation read it from there.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpsRequest } from 'node:https';
import { rmSync } from 'node:fs';
import { Client, startTestServer, type TestServer } from './helpers';
import { createSelfSignedCert, type TlsMaterial } from './bw-cli';
import { masterPasswordHash } from './e2e-support';

const COOKIE = 'moliwarden_web_refresh';
const WEB = { 'X-MoliWarden-Web-Session': '1' };

let server: TestServer;
let client: Client;
let tls: TlsMaterial;

before(async () => {
  tls = createSelfSignedCert();
  server = await startTestServer({ tls: { key: tls.key, cert: tls.cert } });
  client = new Client(server.baseUrl);
  await client.registerAndLogin('alice@example.com');
  await client.register('bob@example.com');
  await client.register('carol@example.com');
  await client.register('dave@example.com');
});

after(async () => {
  await server?.close();
  if (tls) rmSync(tls.dir, { recursive: true, force: true });
});

interface TokenResult {
  status: number;
  body: any;
  setCookies: string[];
  headers: Headers;
}

function passwordForm(email: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    grant_type: 'password',
    username: email,
    password: masterPasswordHash(email),
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceIdentifier: crypto.randomUUID(),
    deviceName: 'chrome',
    ...extra,
  };
}

async function identityPost(path: string, form: Record<string, string>, headers: Record<string, string> = {}): Promise<TokenResult> {
  const response = await client.fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(form).toString(),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
    setCookies: response.headers.getSetCookie(),
    headers: response.headers,
  };
}

function token(form: Record<string, string>, headers: Record<string, string> = {}) {
  return identityPost('/identity/connect/token', form, headers);
}

function refreshCookie(setCookies: string[]): string | null {
  const cookie = setCookies.find((c) => c.startsWith(`${COOKIE}=`));
  if (!cookie) return null;
  return cookie.split(';')[0].slice(COOKIE.length + 1);
}

function cookieAttributes(setCookie: string): Map<string, string> {
  const attributes = new Map<string, string>();
  for (const part of setCookie.split(';').slice(1)) {
    const [key, ...rest] = part.trim().split('=');
    attributes.set(key.toLowerCase(), rest.join('='));
  }
  return attributes;
}

async function webLogin(email: string) {
  const result = await token(passwordForm(email), WEB);
  assert.equal(result.status, 200, JSON.stringify(result.body));
  const cookie = refreshCookie(result.setCookies);
  assert.ok(cookie, 'refresh cookie set');
  return { ...result, cookie };
}

async function profileStatus(accessToken: string): Promise<number> {
  return (await client.fetch('/api/accounts/profile', { token: accessToken })).status;
}

test('web-session login keeps the refresh token out of JSON and in an HttpOnly cookie', async () => {
  const login = await webLogin('alice@example.com');
  assert.equal(login.body.web_session, true);
  assert.equal(login.body.refresh_token, undefined);
  assert.ok(!Object.keys(login.body).some((k) => k.toLowerCase().includes('refresh')), 'no refresh token field of any casing');
  assert.ok(login.body.access_token);
  assert.equal(login.body.token_type, 'Bearer');
  assert.ok(login.body.Key);
  assert.match(login.headers.get('Cache-Control') ?? '', /no-store/);
  assert.ok(!JSON.stringify(login.body).includes(login.cookie), 'cookie value not echoed in the body');

  const cookies = login.setCookies.filter((c) => c.startsWith(`${COOKIE}=`));
  assert.equal(cookies.length, 1);
  const attributes = cookieAttributes(cookies[0]);
  assert.ok(attributes.has('httponly'));
  assert.equal(attributes.get('samesite')?.toLowerCase(), 'strict');
  assert.equal(attributes.get('path'), '/identity/connect');
  assert.ok(Number(attributes.get('max-age')) > 0);
  assert.ok(!attributes.has('secure'), 'plain http: no Secure flag');
  assert.ok(!attributes.has('domain'), 'host-only cookie');

  assert.equal(await profileStatus(login.body.access_token), 200);
});

test('refresh with the web-session header reads the cookie and re-sets it', async () => {
  const login = await webLogin('bob@example.com');
  const refreshed = await token(
    { grant_type: 'refresh_token', client_id: 'web' },
    { ...WEB, Cookie: `other=1; ${COOKIE}=${login.cookie}` },
  );
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
  assert.ok(refreshed.body.access_token);
  assert.equal(refreshed.body.web_session, true);
  assert.equal(refreshed.body.refresh_token, undefined);
  assert.equal(await profileStatus(refreshed.body.access_token), 200);

  const renewed = refreshed.setCookies.find((c) => c.startsWith(`${COOKIE}=`));
  assert.ok(renewed, 'cookie re-set on refresh');
  const attributes = cookieAttributes(renewed);
  assert.ok(attributes.has('httponly'));
  assert.equal(attributes.get('samesite')?.toLowerCase(), 'strict');
  assert.equal(attributes.get('path'), '/identity/connect');
  assert.ok(Number(attributes.get('max-age')) > 0);
  const nextCookie = refreshCookie(refreshed.setCookies)!;
  assert.ok(nextCookie);

  // The (possibly rotated) cookie keeps working.
  const again = await token({ grant_type: 'refresh_token', client_id: 'web' }, { ...WEB, Cookie: `${COOKIE}=${nextCookie}` });
  assert.equal(again.status, 200, JSON.stringify(again.body));
});

test('refresh without a usable cookie fails', async () => {
  const login = await webLogin('carol@example.com');

  const noCookie = await token({ grant_type: 'refresh_token', client_id: 'web' }, WEB);
  assert.equal(noCookie.status, 400);
  assert.ok(['invalid_request', 'invalid_grant'].includes(noCookie.body.error), noCookie.body.error);
  assert.ok(!noCookie.body.access_token);

  const bogus = await token({ grant_type: 'refresh_token', client_id: 'web' }, { ...WEB, Cookie: `${COOKIE}=bogus-token` });
  assert.equal(bogus.status, 400);
  assert.equal(bogus.body.error, 'invalid_grant');
  const cleared = bogus.setCookies.find((c) => c.startsWith(`${COOKIE}=`));
  assert.ok(cleared, 'an invalid session cookie is cleared');
  assert.equal(cookieAttributes(cleared).get('max-age'), '0');

  // The cookie is only honoured together with the web-session header.
  const headerless = await token({ grant_type: 'refresh_token', client_id: 'web' }, { Cookie: `${COOKIE}=${login.cookie}` });
  assert.equal(headerless.status, 400);
  assert.ok(!headerless.body.access_token);

  // The real session still works afterwards.
  const ok = await token({ grant_type: 'refresh_token', client_id: 'web' }, { ...WEB, Cookie: `${COOKIE}=${login.cookie}` });
  assert.equal(ok.status, 200);
});

test('revocation with the web-session header clears the cookie and kills the session', async () => {
  const login = await webLogin('dave@example.com');
  // Exactly what the web vault sends on logout: an empty form body, header + cookie.
  const revoked = await identityPost(
    '/identity/connect/revocation',
    {},
    { ...WEB, Cookie: `${COOKIE}=${login.cookie}`, Authorization: `Bearer ${login.body.access_token}` },
  );
  assert.equal(revoked.status, 200);
  const cleared = revoked.setCookies.find((c) => c.startsWith(`${COOKIE}=`));
  assert.ok(cleared, 'Set-Cookie clears the refresh cookie');
  assert.equal(refreshCookie(revoked.setCookies), '');
  const attributes = cookieAttributes(cleared);
  assert.equal(attributes.get('max-age'), '0');
  assert.equal(attributes.get('path'), '/identity/connect');

  const refresh = await token({ grant_type: 'refresh_token', client_id: 'web' }, { ...WEB, Cookie: `${COOKIE}=${login.cookie}` });
  assert.equal(refresh.status, 400);
  assert.equal(refresh.body.error, 'invalid_grant');
});

test('a non-web login returns refresh_token in JSON and sets no cookie; revocation by body token works', async () => {
  const login = await token(passwordForm('alice@example.com', { client_id: 'cli', deviceType: '25' }));
  assert.equal(login.status, 200, JSON.stringify(login.body));
  assert.ok(login.body.refresh_token);
  assert.equal(login.body.web_session, undefined);
  assert.equal(login.setCookies.length, 0);

  const refreshed = await token({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: login.body.refresh_token });
  assert.equal(refreshed.status, 200);
  assert.ok(refreshed.body.refresh_token);
  assert.equal(refreshed.setCookies.length, 0);

  const revoked = await identityPost('/identity/connect/revocation', { token: refreshed.body.refresh_token, token_type_hint: 'refresh_token' });
  assert.equal(revoked.status, 200);
  assert.equal(revoked.setCookies.length, 0);
  const dead = await token({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: refreshed.body.refresh_token });
  assert.equal(dead.status, 400);
  assert.equal(dead.body.error, 'invalid_grant');
});

test('over HTTPS the refresh cookie is Secure', async () => {
  const url = new URL('/identity/connect/token', server.httpsUrl!);
  const body = new URLSearchParams(passwordForm('alice@example.com')).toString();
  const { status, setCookies, json } = await new Promise<{ status: number; setCookies: string[]; json: any }>((resolve, reject) => {
    const req = httpsRequest(
      url,
      {
        method: 'POST',
        ca: tls.cert,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
          'Bitwarden-Client-Name': 'web',
          'Bitwarden-Client-Version': '2026.1.0',
          ...WEB,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = res.headers['set-cookie'];
          resolve({
            status: res.statusCode ?? 0,
            setCookies: Array.isArray(raw) ? raw : raw ? [raw] : [],
            json: JSON.parse(Buffer.concat(chunks).toString() || 'null'),
          });
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });
  assert.equal(status, 200, JSON.stringify(json));
  assert.equal(json.web_session, true);
  assert.equal(json.refresh_token, undefined);
  const cookie = setCookies.find((c) => c.startsWith(`${COOKIE}=`));
  assert.ok(cookie);
  const attributes = cookieAttributes(cookie);
  assert.ok(attributes.has('secure'));
  assert.ok(attributes.has('httponly'));
  assert.equal(attributes.get('samesite')?.toLowerCase(), 'strict');
  assert.equal(attributes.get('path'), '/identity/connect');
});
