import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';

// Login with a device: a new device asks, a signed-in device approves and
// hands over the vault key, and the new device then signs in once with the
// request's access code.

export const AUTH_REQUEST_TTL_MS = 15 * 60 * 1000;

export const AuthRequestType = { LoginAndUnlock: 0, Unlock: 1, AdminApproval: 2 } as const;
export type AuthRequestType = (typeof AuthRequestType)[keyof typeof AuthRequestType];
// The kinds the user answers from a signed-in device.
const ANSWERED_BY_USER = [AuthRequestType.LoginAndUnlock, AuthRequestType.Unlock];

export interface AuthRequest {
  id: string;
  userId: string;
  type: AuthRequestType;
  requestDeviceIdentifier: string;
  requestDeviceType: number;
  requestIpAddress: string | null;
  requestCountryName: string | null;
  responseDeviceIdentifier: string | null;
  accessCode: string;
  publicKey: string;
  key: string | null;
  approved: boolean | null;
  creationDate: string;
  responseDate: string | null;
  authenticationDate: string | null;
}

function toAuthRequest(row: Row<'auth_requests'>): AuthRequest {
  return {
    id: row.id,
    userId: row.user_id,
    type: row.type as AuthRequestType,
    requestDeviceIdentifier: row.request_device_identifier,
    requestDeviceType: row.request_device_type,
    requestIpAddress: row.request_ip_address,
    requestCountryName: row.request_country_name,
    responseDeviceIdentifier: row.response_device_identifier,
    accessCode: row.access_code,
    publicKey: row.public_key,
    key: row.key,
    approved: row.approved,
    creationDate: row.created_at,
    responseDate: row.responded_at,
    authenticationDate: row.authenticated_at,
  };
}

const cutoff = (now: number) => new Date(now - AUTH_REQUEST_TTL_MS).toISOString();

export async function insertAuthRequest(db: Executor, request: AuthRequest): Promise<void> {
  await db
    .insertInto('auth_requests')
    .values({
      id: request.id,
      user_id: request.userId,
      type: request.type,
      request_device_identifier: request.requestDeviceIdentifier,
      request_device_type: request.requestDeviceType,
      request_ip_address: request.requestIpAddress,
      request_country_name: request.requestCountryName,
      response_device_identifier: null,
      access_code: request.accessCode,
      public_key: request.publicKey,
      key: null,
      approved: null,
      created_at: request.creationDate,
      responded_at: null,
      authenticated_at: null,
    })
    .execute();
}

// Unexpired requests only. Without a user, any user's.
export async function findAuthRequest(db: Executor, id: string, userId: string | null, now = Date.now()): Promise<AuthRequest | null> {
  let query = db.selectFrom('auth_requests').selectAll().where('id', '=', id).where('created_at', '>', cutoff(now));
  if (userId) query = query.where('user_id', '=', userId);
  const row = await query.executeTakeFirst();
  return row ? toAuthRequest(row) : null;
}

export async function listAuthRequests(db: Executor, userId: string): Promise<AuthRequest[]> {
  const rows = await db
    .selectFrom('auth_requests')
    .selectAll()
    .where('user_id', '=', userId)
    .orderBy('created_at', 'desc')
    .execute();
  return rows.map(toAuthRequest);
}

// Only the latest request from a device counts; an earlier one it replaced
// can no longer be answered.
async function latestPerDevice(db: Executor, userId: string, now: number, deviceIdentifier?: string): Promise<AuthRequest[]> {
  let query = db
    .selectFrom('auth_requests')
    .selectAll()
    .distinctOn('request_device_identifier')
    .where('user_id', '=', userId)
    .where('type', 'in', ANSWERED_BY_USER)
    .where('created_at', '>', cutoff(now));
  if (deviceIdentifier !== undefined) query = query.where('request_device_identifier', '=', deviceIdentifier);
  const rows = await query.orderBy('request_device_identifier').orderBy('created_at', 'desc').execute();
  return rows.map(toAuthRequest);
}

const isOpen = (request: AuthRequest) => request.approved === null && !request.responseDate && !request.authenticationDate;

// The requests waiting for the user's answer, newest first.
export async function listPendingAuthRequests(db: Executor, userId: string, now = Date.now()): Promise<AuthRequest[]> {
  const latest = await latestPerDevice(db, userId, now);
  return latest.filter(isOpen).sort((a, b) => b.creationDate.localeCompare(a.creationDate));
}

export async function isLatestFromDevice(db: Executor, request: AuthRequest, now = Date.now()): Promise<boolean> {
  const [latest] = await latestPerDevice(db, request.userId, now, request.requestDeviceIdentifier);
  return latest?.id === request.id;
}

// Records the user's answer. Null when the request was answered already.
export async function answerAuthRequest(
  db: Executor,
  request: AuthRequest,
  answer: { approved: boolean; key: string | null; deviceIdentifier: string },
): Promise<AuthRequest | null> {
  const row = await db
    .updateTable('auth_requests')
    .set({
      approved: answer.approved,
      key: answer.approved ? answer.key : null,
      response_device_identifier: answer.deviceIdentifier,
      responded_at: new Date().toISOString(),
    })
    .where('id', '=', request.id)
    .where('user_id', '=', request.userId)
    .where('approved', 'is', null)
    .where('responded_at', 'is', null)
    .where('authenticated_at', 'is', null)
    .returningAll()
    .executeTakeFirst();
  return row ? toAuthRequest(row) : null;
}

export interface ApprovedLoginRequest {
  id: string;
  accessCode: string;
  key: string;
}

// An approved request of the user's that has not been used to sign in yet.
export async function findApprovedLoginRequest(
  db: Executor,
  id: string,
  userId: string,
  now = Date.now(),
): Promise<ApprovedLoginRequest | null> {
  const row = await db
    .selectFrom('auth_requests')
    .select(['id', 'access_code', 'key'])
    .where('id', '=', id)
    .where('user_id', '=', userId)
    .where('type', '=', AuthRequestType.LoginAndUnlock)
    .where('approved', '=', true)
    .where('responded_at', 'is not', null)
    .where('authenticated_at', 'is', null)
    .where('created_at', '>', cutoff(now))
    .executeTakeFirst();
  return row?.key ? { id: row.id, accessCode: row.access_code, key: row.key } : null;
}

// Uses the request up. False when a concurrent login used it first.
export async function markAuthRequestUsed(db: Executor, id: string): Promise<boolean> {
  const result = await db
    .updateTable('auth_requests')
    .set({ authenticated_at: new Date().toISOString() })
    .where('id', '=', id)
    .where('authenticated_at', 'is', null)
    .executeTakeFirst();
  return result.numUpdatedRows > 0n;
}

// For the scheduled cleanup.
export async function deleteExpiredAuthRequests(db: Executor, now = Date.now()): Promise<number> {
  const result = await db.deleteFrom('auth_requests').where('created_at', '<=', cutoff(now)).executeTakeFirst();
  return Number(result.numDeletedRows);
}
