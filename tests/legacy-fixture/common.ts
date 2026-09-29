// Shared pieces of the legacy (v1) fixture generator and its verifier.
//
// Everything here is black-box plumbing: Postgres admin helpers, the S3
// bucket the fixture lives in, a Yubico validation mock with a FIXED API
// secret (so a restored database keeps validating OTPs), deterministic
// EncStrings and a few HTTP helpers for the identity endpoint.
import { createHmac, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, renameSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';
import { AwsClient } from 'aws4fetch';

export const FIXTURE_DIR = fileURLToPath(new URL('./', import.meta.url));

// The server code the fixture is generated with / verified against.
// v1 is the last backend before the rewrite; by default it is exported from
// git into a temporary directory (node_modules is symlinked from this checkout).
//   FIXTURE_SERVER_REF=<commit>   use another commit
//   FIXTURE_SERVER_REF=worktree   use this checkout as it is
//   FIXTURE_SERVER_ROOT=<dir>     use an existing export
export const V1_COMMIT = '88604b648f17a5fda1c9c9713654c0a9822dec5f';
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const SERVER_REF = process.env.FIXTURE_SERVER_ROOT ? null : process.env.FIXTURE_SERVER_REF || V1_COMMIT;
export const SERVER_ROOT = process.env.FIXTURE_SERVER_ROOT
  ? resolve(process.env.FIXTURE_SERVER_ROOT)
  : SERVER_REF === 'worktree'
    ? REPO_ROOT
    : join(tmpdir(), `moliwarden-fixture-src-${SERVER_REF}`);

export function serverCommit(): string {
  if (SERVER_REF === 'worktree') return `worktree at ${git(['rev-parse', 'HEAD'])} (plus uncommitted changes, if any)`;
  if (SERVER_REF) return git(['rev-parse', `${SERVER_REF}^{commit}`]);
  return process.env.FIXTURE_SERVER_COMMIT || `unknown (FIXTURE_SERVER_ROOT=${SERVER_ROOT})`;
}

function git(args: string[]): string {
  return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
}

// Exports SERVER_REF into SERVER_ROOT once (no-op for worktree/FIXTURE_SERVER_ROOT).
export function prepareServerRoot(): void {
  if (!SERVER_REF || SERVER_REF === 'worktree') return;
  if (!existsSync(join(SERVER_ROOT, 'src'))) {
    const commit = serverCommit();
    const staging = `${SERVER_ROOT}.tmp-${process.pid}`;
    rmSync(staging, { recursive: true, force: true });
    mkdirSync(staging, { recursive: true });
    const archive = execFileSync('git', ['archive', '--format=tar', commit, 'src', 'shared', 'tests', 'package.json', 'tsconfig.json'], { cwd: REPO_ROOT, maxBuffer: 256 * 1024 * 1024 });
    execFileSync('tar', ['-x', '-C', staging], { input: archive });
    rmSync(SERVER_ROOT, { recursive: true, force: true });
    renameSync(staging, SERVER_ROOT);
  }
  if (!existsSync(join(SERVER_ROOT, 'node_modules'))) symlinkSync(join(REPO_ROOT, 'node_modules'), join(SERVER_ROOT, 'node_modules'), 'dir');
}

export async function importServerModule<T>(relativePath: string): Promise<T> {
  return (await import(pathToFileURL(join(SERVER_ROOT, relativePath)).href)) as T;
}

export const FIXTURE_DATABASE_URL = process.env.FIXTURE_DATABASE_URL || 'postgres://mw:mw@localhost:55432/mw_fixture';
export const VERIFY_DATABASE_URL = process.env.FIXTURE_VERIFY_DATABASE_URL || withDatabase(FIXTURE_DATABASE_URL, 'mw_fixture_verify');
export const FIXTURE_BUCKET = process.env.FIXTURE_S3_BUCKET || 'mw-legacy-fixture';
export const VERIFY_BUCKET = process.env.FIXTURE_VERIFY_S3_BUCKET || 'mw-legacy-fixture-verify';
export const PG_CONTAINER = process.env.FIXTURE_PG_CONTAINER || 'mw-pg';

export const S3_ENDPOINT = process.env.TEST_S3_ENDPOINT || 'http://localhost:58333';
export const S3_ACCESS_KEY_ID = process.env.TEST_S3_ACCESS_KEY_ID || 'mwaccess';
export const S3_SECRET_ACCESS_KEY = process.env.TEST_S3_SECRET_ACCESS_KEY || 'mwsecret123';

// Must match tests/helpers.ts testServerEnv(): the backup-settings runtime
// envelope and every JWT are keyed on it.
export const FIXTURE_JWT_SECRET = 'test-secret-test-secret-test-secret-0123456789';
export const WEBAUTHN_RP_NAME = 'MoliWarden Legacy Fixture';
// Passkeys are bound to this RP id (the request host); reach the server at 127.0.0.1.
export const WEBAUTHN_RP_ID = '127.0.0.1';

export const YUBICO_CLIENT_ID = '424242';
export const YUBICO_SECRET_KEY = Buffer.from('legacy-fixture-yubico').subarray(0, 20).toString('base64');

// ---------------------------------------------------------------------------
// Deterministic data

// Deterministic Bitwarden EncString (type 2), same shape as tests/golden.
export function enc(label: string): string {
  const b64 = (text: string) => Buffer.from(text).toString('base64');
  return `2.${b64(`iv-${label}`)}|${b64(`ct-${label}`)}|${b64(`mac-${label}`)}`;
}

// Deterministic RSA-wrapped EncString (type 4).
export function rsaEnc(label: string): string {
  return `4.${Buffer.from(`rsa-${label}`).toString('base64')}`;
}

// What the harness sends as the master password hash: base64 of a string.
export function passwordString(email: string): string {
  return `hash-${email}`;
}

export function masterPasswordHash(email: string): string {
  return Buffer.from(passwordString(email)).toString('base64');
}

// ---------------------------------------------------------------------------
// Postgres

export function withDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

export function databaseName(url: string): string {
  return decodeURIComponent(new URL(url).pathname.replace(/^\//, ''));
}

// Connects to the maintenance database `mw` on the same server.
async function withAdmin<T>(url: string, fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: withDatabase(url, process.env.FIXTURE_ADMIN_DATABASE || 'mw') });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

export async function ensureDatabase(url: string): Promise<void> {
  const name = databaseName(url);
  await withAdmin(url, async (client) => {
    const found = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (!found.rowCount) await client.query(`CREATE DATABASE ${quoteIdent(name)}`);
  });
}

export async function recreateDatabase(url: string): Promise<void> {
  const name = databaseName(url);
  await withAdmin(url, async (client) => {
    await client.query(`DROP DATABASE IF EXISTS ${quoteIdent(name)} WITH (FORCE)`);
    await client.query(`CREATE DATABASE ${quoteIdent(name)}`);
  });
}

export async function withDb<T>(url: string, fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------------------
// S3

function aws(): AwsClient {
  return new AwsClient({ accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY, region: 'us-east-1', service: 's3' });
}

function objectUrl(bucket: string, key: string): string {
  return `${S3_ENDPOINT}/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
}

export async function ensureBucketExists(bucket: string): Promise<void> {
  const response = await aws().fetch(`${S3_ENDPOINT}/${bucket}`, { method: 'PUT' });
  if (!response.ok && response.status !== 409) {
    throw new Error(`Could not create bucket ${bucket}: ${response.status} ${await response.text()}`);
  }
}

function xmlDecode(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

export async function listObjectKeys(bucket: string): Promise<string[]> {
  const keys: string[] = [];
  let token: string | null = null;
  do {
    const url = new URL(`${S3_ENDPOINT}/${bucket}`);
    url.searchParams.set('list-type', '2');
    if (token) url.searchParams.set('continuation-token', token);
    const response = await aws().fetch(url.toString());
    const text = await response.text();
    if (!response.ok) throw new Error(`ListObjectsV2 ${bucket}: ${response.status} ${text}`);
    for (const match of text.matchAll(/<Key>([\s\S]*?)<\/Key>/g)) keys.push(xmlDecode(match[1]));
    const truncated = /<IsTruncated>true<\/IsTruncated>/.test(text);
    const next = text.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/);
    token = truncated && next ? xmlDecode(next[1]) : null;
  } while (token);
  return keys.sort();
}

export async function getObject(bucket: string, key: string): Promise<Buffer> {
  const response = await aws().fetch(objectUrl(bucket, key));
  if (!response.ok) throw new Error(`GET ${bucket}/${key}: ${response.status} ${await response.text()}`);
  return Buffer.from(await response.arrayBuffer());
}

export async function putObject(bucket: string, key: string, body: Buffer): Promise<void> {
  const response = await aws().fetch(objectUrl(bucket, key), { method: 'PUT', body: new Uint8Array(body) });
  if (!response.ok) throw new Error(`PUT ${bucket}/${key}: ${response.status} ${await response.text()}`);
}

export async function emptyBucket(bucket: string): Promise<void> {
  for (const key of await listObjectKeys(bucket)) {
    const response = await aws().fetch(objectUrl(bucket, key), { method: 'DELETE' });
    if (!response.ok && response.status !== 404) throw new Error(`DELETE ${bucket}/${key}: ${response.status}`);
  }
}

// ---------------------------------------------------------------------------
// Yubico validation mock with a fixed API secret (wsapi 2.0 verify).
// Same protocol as tests/yubico-mock.ts, which draws a random secret per run.

const MODHEX = 'cbdefghijklnrtuv';

export function yubiKeyOtp(publicId: string): string {
  const bytes = randomBytes(32);
  let out = publicId;
  for (let i = 0; i < 32; i++) out += MODHEX[bytes[i] & 0x0f];
  return out;
}

function yubicoSign(fields: Record<string, string>, secret = YUBICO_SECRET_KEY): string {
  const canonical = Object.keys(fields)
    .filter((key) => key !== 'h')
    .sort()
    .map((key) => `${key}=${fields[key]}`)
    .join('&');
  return createHmac('sha1', Buffer.from(secret, 'base64')).update(canonical).digest('base64');
}

export interface FixedYubicoMock {
  url: string;
  requests: number;
  close(): Promise<void>;
}

export async function startFixedYubicoMock(): Promise<FixedYubicoMock> {
  const seen = new Set<string>();
  const state = { requests: 0 };
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method !== 'GET' || url.pathname !== '/wsapi/2.0/verify') {
      res.statusCode = 404;
      res.end();
      return;
    }
    state.requests += 1;
    const params: Record<string, string> = Object.fromEntries(url.searchParams);
    const otp = params.otp ?? '';
    let status = 'OK';
    if (params.id !== YUBICO_CLIENT_ID) status = 'NO_SUCH_CLIENT';
    else if (!params.h || yubicoSign(params) !== params.h) status = 'BAD_SIGNATURE';
    else if (seen.has(otp)) status = 'REPLAYED_OTP';
    if (status === 'OK') seen.add(otp);
    const fields: Record<string, string> = {
      t: new Date().toISOString().replace(/\.\d+Z$/, 'Z0000'),
      otp,
      nonce: params.nonce ?? '',
      sl: '100',
      status,
    };
    const body = [`h=${yubicoSign(fields)}`, ...Object.entries(fields).map(([k, v]) => `${k}=${v}`)].join('\r\n') + '\r\n';
    res.setHeader('Content-Type', 'text/plain');
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/wsapi/2.0/verify`,
    get requests() {
      return state.requests;
    },
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP

export interface HttpResult {
  status: number;
  body: any;
  headers: Headers;
}

export class Http {
  constructor(readonly baseUrl: string) {}

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

  async call(path: string, init: RequestInit & { json?: unknown; token?: string } = {}): Promise<HttpResult> {
    const response = await this.fetch(path, init);
    const text = await response.text();
    let body: any = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      // keep text
    }
    return { status: response.status, body, headers: response.headers };
  }

  // Like call(), but throws unless 2xx.
  async ok(path: string, init: RequestInit & { json?: unknown; token?: string } = {}): Promise<any> {
    const result = await this.call(path, init);
    if (result.status < 200 || result.status > 299) {
      throw new Error(`${init.method ?? 'GET'} ${path} -> ${result.status}: ${typeof result.body === 'string' ? result.body : JSON.stringify(result.body)}`);
    }
    return result.body;
  }

  async token(fields: Record<string, string>, headers: Record<string, string> = {}): Promise<HttpResult> {
    return this.call('/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(fields).toString(),
    });
  }
}

export interface PasswordGrantOptions {
  masterPasswordHash: string;
  deviceIdentifier: string;
  clientId?: string;
  deviceType?: number;
  deviceName?: string;
  extra?: Record<string, string>;
  headers?: Record<string, string>;
}

export function passwordGrantFields(email: string, options: PasswordGrantOptions): Record<string, string> {
  return {
    grant_type: 'password',
    username: email,
    password: options.masterPasswordHash,
    scope: 'api offline_access',
    client_id: options.clientId ?? 'cli',
    deviceType: String(options.deviceType ?? 25),
    deviceIdentifier: options.deviceIdentifier,
    deviceName: options.deviceName ?? 'legacy-fixture',
    ...options.extra,
  };
}

export function jwtClaims(accessToken: string): any {
  return JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString());
}

// .NET Guid.ToByteArray() layout of a UUID, used for WebAuthn user handles.
export function dotNetGuidBytes(uuid: string): Buffer {
  const hex = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  return Buffer.from([hex[3], hex[2], hex[1], hex[0], hex[5], hex[4], hex[7], hex[6], ...hex.subarray(8)]);
}

export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
