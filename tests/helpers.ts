// Shared end-to-end test harness.
//
// Requires a disposable PostgreSQL database and S3 bucket:
//   TEST_DATABASE_URL=postgres://mw:mw@localhost:55432/mw
//   TEST_S3_ENDPOINT=http://localhost:58333 TEST_S3_ACCESS_KEY_ID=... TEST_S3_SECRET_ACCESS_KEY=...
// Every test file resets the `public` schema before starting the server.
import { createServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import pg from 'pg';
import { AwsClient } from 'aws4fetch';

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgres://mw:mw@localhost:55432/mw';
const S3_ENDPOINT = process.env.TEST_S3_ENDPOINT || 'http://localhost:58333';
const S3_ACCESS_KEY_ID = process.env.TEST_S3_ACCESS_KEY_ID || 'mwaccess';
const S3_SECRET_ACCESS_KEY = process.env.TEST_S3_SECRET_ACCESS_KEY || 'mwsecret123';

export interface TestServer {
  baseUrl: string;
  // Set when started with `tls`: the same app behind HTTPS (official clients
  // refuse plain-HTTP servers).
  httpsUrl?: string;
  close(): Promise<void>;
}

export async function resetDatabase(connectionString = TEST_DATABASE_URL): Promise<void> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    await client.query('DROP SCHEMA IF EXISTS public CASCADE');
    await client.query('CREATE SCHEMA public');
  } finally {
    await client.end();
  }
}

export async function ensureBucket(bucket: string): Promise<void> {
  const aws = new AwsClient({ accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY, region: 'us-east-1', service: 's3' });
  const response = await aws.fetch(`${S3_ENDPOINT}/${bucket}`, { method: 'PUT' });
  if (!response.ok && response.status !== 409) {
    throw new Error(`Could not create test bucket: ${response.status} ${await response.text()}`);
  }
}

// Environment for a server under test, as it would be set on Vercel.
export function testServerEnv(bucket: string): Record<string, string> {
  return {
    DATABASE_URL: TEST_DATABASE_URL,
    JWT_SECRET: 'test-secret-test-secret-test-secret-0123456789',
    S3_ENDPOINT,
    S3_BUCKET: bucket,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_REGION: 'us-east-1',
    CRON_SECRET: 'test-cron-secret',
    PUSH_RELAY_DISABLED: '1',
  };
}

export async function startTestServer(options: { tls?: { key: string | Buffer; cert: string | Buffer } } = {}): Promise<TestServer> {
  const bucket = `mw-test-${process.pid}`;
  await resetDatabase();
  await ensureBucket(bucket);

  Object.assign(process.env, testServerEnv(bucket));

  const { handleNodeRequest } = await import('../src/platform/node-http');
  const server: Server = createServer((req, res) => {
    void handleNodeRequest(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const servers: Server[] = [server];
  let httpsUrl: string | undefined;
  if (options.tls) {
    // TLS terminates here like at Vercel's edge, which forwards the scheme.
    const secure = createHttpsServer(options.tls, (req, res) => {
      req.headers['x-forwarded-proto'] = 'https';
      void handleNodeRequest(req, res);
    });
    await new Promise<void>((resolve) => secure.listen(0, '127.0.0.1', resolve));
    servers.push(secure);
    httpsUrl = `https://127.0.0.1:${(secure.address() as AddressInfo).port}`;
  }
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    httpsUrl,
    async close() {
      for (const s of servers) {
        s.closeAllConnections?.();
        await new Promise<void>((resolve) => s.close(() => resolve()));
      }
      const { getEnv } = await import('../src/platform/env');
      const db = getEnv().DB as unknown as { pool: pg.Pool };
      await db.pool.end();
    },
  };
}

// Opaque but well-formed Bitwarden EncString (type 2: AES-CBC + HMAC).
export function fakeEncString(label = 'x'): string {
  const b64 = (value: string) => Buffer.from(value).toString('base64');
  return `2.${b64(`iv-${label}-${crypto.randomUUID()}`)}|${b64(`ct-${label}`)}|${b64(`mac-${label}`)}`;
}

export function fakeRsaEncString(label = 'x'): string {
  return `4.${Buffer.from(`rsa-${label}-${crypto.randomUUID()}`).toString('base64')}`;
}

export interface Session {
  email: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  deviceIdentifier: string;
  request(path: string, init?: RequestInit & { json?: unknown }): Promise<Response>;
  json<T = any>(path: string, init?: RequestInit & { json?: unknown }): Promise<T>;
}

export class Client {
  // First registered user becomes the instance admin; it mints invite codes
  // for everyone registered after it.
  private admin: { session: Session; password: string } | null = null;

  // `origin` is what browsers would send; it differs from baseUrl behind a
  // TLS-terminating proxy such as Vercel's.
  constructor(readonly baseUrl: string, readonly origin = baseUrl) {}

  private async inviteCode(): Promise<string | undefined> {
    if (!this.admin) return undefined;
    const invite = await this.admin.session.json('/api/admin/invites', {
      method: 'POST',
      json: { expiresInHours: 1, masterPasswordHash: Buffer.from(this.admin.password).toString('base64') },
    });
    return invite.code ?? invite.invite?.code;
  }

  async fetch(path: string, init: RequestInit & { json?: unknown; token?: string } = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    let body = init.body;
    if (init.json !== undefined) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(init.json);
    }
    if (init.token) headers.set('Authorization', `Bearer ${init.token}`);
    if (!headers.has('Bitwarden-Client-Name')) headers.set('Bitwarden-Client-Name', 'cli');
    if (!headers.has('Bitwarden-Client-Version')) headers.set('Bitwarden-Client-Version', '2026.1.0');
    return fetch(`${this.baseUrl}${path}`, { ...init, headers, body, redirect: 'manual' });
  }

  async register(email: string, password = 'hash-' + email): Promise<{ publicKey: string }> {
    const inviteCode = await this.inviteCode();
    const publicKey = Buffer.from(`public-key-${email}`).toString('base64');
    const response = await this.fetch('/api/accounts/register', {
      method: 'POST',
      headers: { Origin: this.origin },
      json: {
        email,
        name: email.split('@')[0],
        masterPasswordHash: Buffer.from(password).toString('base64'),
        key: fakeEncString('user-key'),
        keys: { publicKey, encryptedPrivateKey: fakeEncString('private-key') },
        kdf: 0,
        kdfIterations: 600000,
        inviteCode,
      },
    });
    if (!response.ok) throw new Error(`register ${email} failed: ${response.status} ${await response.text()}`);
    return { publicKey };
  }

  async login(email: string, password = 'hash-' + email): Promise<Session> {
    const deviceIdentifier = crypto.randomUUID();
    const form = new URLSearchParams({
      grant_type: 'password',
      username: email,
      password: Buffer.from(password).toString('base64'),
      scope: 'api offline_access',
      client_id: 'cli',
      deviceType: '8',
      deviceIdentifier,
      deviceName: 'e2e',
    });
    const response = await this.fetch('/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`login ${email} failed: ${response.status} ${text}`);
    const token = JSON.parse(text);
    const payload = JSON.parse(Buffer.from(token.access_token.split('.')[1], 'base64url').toString());
    const client = this;
    const session: Session = {
      email,
      userId: payload.sub,
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      deviceIdentifier,
      request(path, init = {}) {
        return client.fetch(path, { ...init, token: session.accessToken });
      },
      async json(path, init = {}) {
        const res = await session.request(path, init);
        const body = await res.text();
        if (!res.ok) throw new Error(`${init.method || 'GET'} ${path} -> ${res.status}: ${body}`);
        return body ? JSON.parse(body) : null;
      },
    };
    return session;
  }

  async registerAndLogin(email: string): Promise<Session & { publicKey: string }> {
    const { publicKey } = await this.register(email);
    const session = await this.login(email);
    if (!this.admin) this.admin = { session, password: 'hash-' + email };
    return Object.assign(session, { publicKey });
  }
}

export function cipherPayload(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 1,
    name: fakeEncString(`name-${name}`),
    notes: null,
    favorite: false,
    login: {
      username: fakeEncString(`user-${name}`),
      password: fakeEncString(`pass-${name}`),
      uris: [{ uri: fakeEncString(`uri-${name}`), match: null }],
      totp: null,
    },
    reprompt: 0,
    ...extra,
  };
}
