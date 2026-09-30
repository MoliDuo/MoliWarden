import { randomUUID } from 'node:crypto';
import { withPascalCase } from '../../http/casing';
import { clientCountry, clientIp } from '../../http/client';
import { badRequest, conflict, notFound } from '../../http/errors';
import { consume, requireClientAddress } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { constantTimeEqual } from '../../platform/crypto';
import { isEncString } from '../../platform/enc-string';
import type { Device, User } from '../../types';
import { findUserByEmail } from '../accounts/repo';
import { PushType } from '../push/service';
import {
  answerAuthRequest,
  AuthRequestType,
  findAuthRequest,
  insertAuthRequest,
  isLatestFromDevice,
  listAuthRequests,
  listPendingAuthRequests,
  type AuthRequest,
} from './repo';
import type { AnswerInput, CreateInput } from './schemas';

// Login with a device. The new device sends a public key and keeps an
// access code; a signed-in device of the user approves by sending the user
// key encrypted to that public key. The new device polls with the access
// code, decrypts the key and signs in with the code as its password.
//
// The server only relays: it never sees the user key in the clear.

export interface RequestingDevice {
  identifier: string;
  type: number;
}

const DEVICE_TYPE_NAMES: Record<number, string> = {
  0: 'Android',
  1: 'iOS',
  2: 'Chrome Extension',
  3: 'Firefox Extension',
  4: 'Opera Extension',
  5: 'Edge Extension',
  6: 'Windows Desktop',
  7: 'macOS Desktop',
  8: 'Linux Desktop',
  9: 'Chrome',
  10: 'Firefox',
  11: 'Opera',
  12: 'Edge',
  13: 'Internet Explorer',
  14: 'Unknown Browser',
  15: 'Android',
  16: 'Windows UWP',
  17: 'Safari',
  18: 'Vivaldi',
  19: 'Vivaldi Extension',
  20: 'Safari Extension',
  21: 'SDK',
  22: 'Server',
  23: 'Windows CLI',
  24: 'macOS CLI',
  25: 'Linux CLI',
  26: 'DuckDuckGo',
};

// The access code is a secret shared with the new device, and never shown.
function authRequestJson(request: AuthRequest, origin: string, requestDeviceId: string | null = null) {
  const typeName = DEVICE_TYPE_NAMES[request.requestDeviceType] ?? `Device ${request.requestDeviceType}`;
  return withPascalCase({
    id: request.id,
    publicKey: request.publicKey,
    requestDeviceIdentifier: request.requestDeviceIdentifier,
    requestDeviceTypeValue: request.requestDeviceType,
    requestDeviceType: typeName,
    requestIpAddress: request.requestIpAddress,
    requestCountryName: request.requestCountryName,
    key: request.key,
    masterPasswordHash: null,
    creationDate: request.creationDate,
    responseDate: request.responseDate,
    requestApproved: request.approved ?? false,
    requestDeviceId,
    origin,
    object: 'auth-request',
  });
}

const listJson = <T>(data: T[]) => withPascalCase({ data, object: 'list', continuationToken: null });

// A client could otherwise flood a user with approval prompts.
async function limitRequests(deps: Deps, request: Request, email: string, device: string): Promise<void> {
  await consume(deps.limiter, 'auth-request', `ip:${requireClientAddress(request)}`);
  await consume(deps.limiter, 'auth-request', `email:${email}`);
  await consume(deps.limiter, 'auth-request', `device:${device}`);
}

async function create(deps: Deps, request: Request, user: User, type: AuthRequestType, input: CreateInput, device: RequestingDevice) {
  const created: AuthRequest = {
    id: randomUUID(),
    userId: user.id,
    type,
    requestDeviceIdentifier: device.identifier,
    requestDeviceType: device.type,
    requestIpAddress: clientIp(request),
    requestCountryName: clientCountry(request),
    responseDeviceIdentifier: null,
    accessCode: input.accessCode,
    publicKey: input.publicKey,
    key: null,
    approved: null,
    creationDate: new Date().toISOString(),
    responseDate: null,
    authenticationDate: null,
  };
  await insertAuthRequest(deps.db, created);
  deps.push.notify({ type: PushType.AuthRequest, userId: user.id, deviceIdentifier: device.identifier, item: { id: created.id } });
  return authRequestJson(created, new URL(request.url).host);
}

// From a device that is not signed in.
export async function requestLogin(deps: Deps, request: Request, input: CreateInput, device: RequestingDevice | null) {
  if (!input.email || !device) throw badRequest('Email, public key, device identifier, and access code are required.');
  if (input.type !== AuthRequestType.LoginAndUnlock && input.type !== AuthRequestType.Unlock) {
    throw badRequest('Invalid auth request type.');
  }
  // Counted before the lookup, so that probing for accounts costs the same.
  await limitRequests(deps, request, input.email, device.identifier);
  const user = await findUserByEmail(deps.db, input.email);
  if (user?.status !== 'active') throw badRequest('User or known device not found.');
  return create(deps, request, user, input.type, input, device);
}

// A signed-in device asking an organization admin for the user key. It is
// recorded, but no admin can answer it on this server.
export async function requestAdminApproval(
  deps: Deps,
  request: Request,
  user: User,
  input: CreateInput,
  device: RequestingDevice | null,
) {
  if (input.type !== AuthRequestType.AdminApproval) throw badRequest('Invalid AuthRequestType. Expected AdminApproval.');
  const email = input.email || user.email;
  if (email !== user.email.toLowerCase()) throw badRequest('Email does not match authenticated user.');
  if (!device) throw badRequest('Public key, device identifier, and access code are required.');
  await limitRequests(deps, request, email, device.identifier);
  return create(deps, request, user, AuthRequestType.AdminApproval, input, device);
}

// The new device polls here until the request is answered.
export async function loginResponse(deps: Deps, origin: string, id: string, accessCode: string) {
  const found = await findAuthRequest(deps.db, id, null);
  if (!found || !accessCode || !constantTimeEqual(accessCode, found.accessCode)) throw notFound();
  return authRequestJson(found, origin);
}

export async function authRequestById(deps: Deps, origin: string, user: User, id: string) {
  const found = await findAuthRequest(deps.db, id, user.id);
  if (!found) throw notFound();
  return authRequestJson(found, origin);
}

export async function authRequestsJson(deps: Deps, origin: string, user: User) {
  return listJson((await listAuthRequests(deps.db, user.id)).map((request) => authRequestJson(request, origin)));
}

export async function pendingAuthRequests(deps: Deps, origin: string, user: User) {
  const pending = await listPendingAuthRequests(deps.db, user.id);
  return listJson(pending.map((request) => authRequestJson(request, origin, request.requestDeviceIdentifier)));
}

// Approving hands over the user key, encrypted to the requesting device;
// denying is final too.
export async function answer(deps: Deps, origin: string, user: User, current: Device | null, id: string, input: AnswerInput) {
  const found = await findAuthRequest(deps.db, id, user.id);
  if (!found) throw notFound();
  if (found.approved !== null || found.responseDate || found.authenticationDate) {
    throw conflict('Auth request has already been answered.');
  }
  if (!(await isLatestFromDevice(deps.db, found))) {
    throw badRequest('This request is no longer valid. Make sure to approve the most recent request.');
  }
  if (input.requestApproved && !input.key) throw badRequest('Encrypted key is required to approve the request.');
  if (input.requestApproved && !isEncString(input.key!)) throw badRequest('Encrypted key is not a valid encrypted string.');

  const answered = await answerAuthRequest(deps.db, found, {
    approved: input.requestApproved,
    key: input.key,
    deviceIdentifier: input.deviceIdentifier || current?.deviceIdentifier || 'web',
  });
  if (!answered) throw conflict('Auth request has already been answered.');
  return authRequestJson(answered, origin);
}
