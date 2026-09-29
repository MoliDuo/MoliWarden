import { randomUUID } from 'node:crypto';
import { HttpError, IdentityError, notFound, unauthorized } from '../../http/errors';
import { FILE_TOKEN_TTL_SECONDS, fileDownload } from '../../http/files';
import type { Deps } from '../../main/deps';
import { sendFileKey } from '../../platform/blob';
import { findUserById } from '../accounts/repo';
import { clearFailures, lockedFor, lockoutKey, minutes, recordFailure } from '../auth/lockout';
import { useTokenOnce } from '../auth/repo';
import { PushType } from '../push/service';
import { commit } from '../sync/changes';
import { checkSendPassword, isAvailable, sendIdOf, SendType, type Send } from './model';
import { countAccess, findSend } from './repo';
import { sendAccessJson } from './responses';

// What recipients of a Send do, without an account. Clients open a Send
// in one of two ways:
//   v1: POST /api/sends/access/:accessId with the password in the body;
//   v2: a send_access grant at the token endpoint, which checks the
//       password once, then requests with the token it returns.
// Each opening of a text, and each download of a file, counts as one access.

export const SEND_ACCESS_TOKEN_TTL_SECONDS = 300;
const INACCESSIBLE = 'Send does not exist or is no longer available';

type SendAccessClaims = { sub: string };
type SendDownloadClaims = { sendId: string; fileId: string; jti: string };

const isId = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

// Links carry the access id; some clients use the Send id itself.
async function availableSend(deps: Deps, idOrAccessId: string): Promise<Send | null> {
  const id = isId(idOrAccessId) ? idOrAccessId.toLowerCase() : sendIdOf(idOrAccessId);
  const send = id ? await findSend(deps.db, id) : null;
  return send && isAvailable(send) ? send : null;
}

async function requireAvailable(deps: Deps, idOrAccessId: string): Promise<Send> {
  const send = await availableSend(deps, idOrAccessId);
  if (!send) throw notFound(INACCESSIBLE);
  return send;
}

type PasswordCheck = 'ok' | 'missing' | 'wrong' | { lockedFor: number };

// Guessing is limited per client address and Send. Asking without a
// password is how clients learn that one is needed, so it is no failure.
async function checkPassword(deps: Deps, address: string, send: Send, password: string | null): Promise<PasswordCheck> {
  if (!send.password) return 'ok';
  if (!password) return 'missing';
  const key = lockoutKey(address, 'send', send.id);
  const locked = await lockedFor(deps.limiter, key);
  if (locked) return { lockedFor: locked };
  if (await checkSendPassword(send.password, password)) {
    await clearFailures(deps.limiter, key);
    return 'ok';
  }
  const started = await recordFailure(deps.limiter, key);
  return started ? { lockedFor: started } : 'wrong';
}

const lockedMessage = (seconds: number) => `Too many failed send password attempts. Try again in ${minutes(seconds)} minutes.`;

async function requirePassword(deps: Deps, address: string, send: Send, password: string | null): Promise<void> {
  const check = await checkPassword(deps, address, send, password);
  if (check === 'missing') throw unauthorized('Password not provided');
  if (check === 'wrong') throw new HttpError(400, 'Invalid password');
  if (check !== 'ok') throw new HttpError(429, lockedMessage(check.lockedFor));
}

// Counts the access; the Send may have run out meanwhile. Its owner's
// clients learn the new count.
async function useSend(deps: Deps, send: Send): Promise<Send> {
  const now = new Date().toISOString();
  const owner = { user: { id: send.userId }, device: null };
  const change = { push: { type: PushType.SyncSendUpdate, item: { id: send.id, revisionDate: now } } };
  const used = await commit(deps, owner, now, change, (tx) => countAccess(tx, send.id, now));
  if (!used) throw notFound(INACCESSIBLE);
  return used;
}

async function accessJson(deps: Deps, send: Send) {
  // Opening a file Send shows what it is; downloading the file counts.
  const opened = send.type === SendType.Text ? await useSend(deps, send) : send;
  const owner = opened.hideEmail ? null : await findUserById(deps.db, opened.userId);
  return sendAccessJson(opened, owner?.email ?? null);
}

// A download URL for the file, good for one download.
async function fileAccessJson(deps: Deps, origin: string, send: Send, fileId: string) {
  if (send.file?.id !== fileId) throw notFound(INACCESSIBLE);
  await useSend(deps, send);
  const token = deps.tokens.sign<SendDownloadClaims>(
    'send-download',
    { sendId: send.id, fileId, jti: randomUUID() },
    FILE_TOKEN_TTL_SECONDS,
  );
  return { object: 'send-fileDownload', id: fileId, url: `${origin}/api/sends/${send.id}/${fileId}?t=${token}` };
}

export async function accessSend(deps: Deps, address: string, accessId: string, password: string | null) {
  const send = await requireAvailable(deps, accessId);
  await requirePassword(deps, address, send, password);
  return accessJson(deps, send);
}

export async function accessSendFile(deps: Deps, address: string, origin: string, idOrAccessId: string, fileId: string, password: string | null) {
  const send = await requireAvailable(deps, idOrAccessId);
  await requirePassword(deps, address, send, password);
  return fileAccessJson(deps, origin, send, fileId);
}

async function sendOfToken(deps: Deps, token: string | null): Promise<Send> {
  const claims = deps.tokens.verify<SendAccessClaims>('send-access', token);
  if (!claims) throw unauthorized();
  return requireAvailable(deps, claims.sub);
}

export async function accessSendWithToken(deps: Deps, token: string | null) {
  return accessJson(deps, await sendOfToken(deps, token));
}

export async function accessSendFileWithToken(deps: Deps, origin: string, token: string | null, fileId: string) {
  return fileAccessJson(deps, origin, await sendOfToken(deps, token), fileId);
}

export async function downloadSendFile(deps: Deps, sendId: string, fileId: string, token: string | null): Promise<Response> {
  if (!token) throw unauthorized('Token required');
  const claims = deps.tokens.verify<SendDownloadClaims>('send-download', token);
  if (!claims) throw unauthorized('Invalid or expired token');
  if (claims.sendId !== sendId || claims.fileId !== fileId) throw unauthorized('Token mismatch');
  // The download was counted when the URL was handed out.
  const send = await findSend(deps.db, sendId);
  if (!send || send.file?.id !== fileId) throw notFound(INACCESSIBLE);
  if (!(await useTokenOnce(deps.db, claims.jti, claims.exp))) throw unauthorized('Invalid or expired token');
  return fileDownload(deps.blobs, sendFileKey(sendId, fileId), send.file.fileName || 'send-file', 'Send file not found');
}

// The send_access grant of the token endpoint (v2).
export async function issueSendAccessToken(deps: Deps, address: string, idOrAccessId: string, password: string | null) {
  const send = await availableSend(deps, idOrAccessId);
  if (!send) throw new IdentityError('invalid_grant', INACCESSIBLE, 400, { send_access_error_type: 'send_id_invalid' });
  const check = await checkPassword(deps, address, send, password);
  if (check === 'missing') {
    throw new IdentityError('invalid_request', 'Password is required.', 400, { send_access_error_type: 'password_hash_b64_required' });
  }
  if (check === 'wrong') {
    throw new IdentityError('invalid_grant', 'Invalid password.', 400, { send_access_error_type: 'password_hash_b64_invalid' });
  }
  if (check !== 'ok') {
    throw new IdentityError('invalid_grant', lockedMessage(check.lockedFor), 429, {
      send_access_error_type: 'too_many_password_attempts',
    });
  }
  return deps.tokens.sign<SendAccessClaims>('send-access', { sub: send.id }, SEND_ACCESS_TOKEN_TTL_SECONDS);
}
