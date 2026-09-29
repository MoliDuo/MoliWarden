import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, conflict, forbidden, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { isEncString } from '../../platform/enc-string';
import { touchRevisionDate } from '../accounts/repo';
import { findFolder } from '../folders/repo';
import { canWriteCollection, type OrgContext } from '../organizations/access';
import { listCollections, touchMemberRevisions } from '../organizations/repo';
import type { PushEvent, PushType } from '../push/service';
import { TYPE_PARTS, type Cipher, type CipherData, type CipherInput } from './model';
import { saveCiphers, saveUserStates } from './repo';

// How changes to ciphers are made: from what a client sent to what is
// stored, then who is told.

// Clocks and rounding differ by up to this much between server and clients.
const REVISION_TOLERANCE_MS = 1000;

const EMPTY_DATA: CipherData = {
  login: null,
  secureNote: null,
  card: null,
  identity: null,
  sshKey: null,
  bankAccount: null,
  driversLicense: null,
  passport: null,
  fields: null,
  passwordHistory: null,
  keyAddedFromRevision: null,
};

// Only the part of the cipher's type is kept.
function dataOf(input: CipherInput, fallback: CipherData | null, keyAddedFromRevision: string | null = null): CipherData {
  const part = TYPE_PARTS[input.type];
  return {
    ...EMPTY_DATA,
    [part]: input[part] !== undefined ? input[part] : (fallback?.[part] ?? null),
    fields: input.fields,
    passwordHistory: input.passwordHistory !== undefined ? input.passwordHistory : (fallback?.passwordHistory ?? null),
    keyAddedFromRevision,
  } as CipherData;
}

export function newCipher(
  input: CipherInput,
  owner: { userId: string; organizationId: string | null },
  now: string,
  folderId: string | null = input.folderId ?? null,
): Cipher {
  return {
    id: randomUUID(),
    userId: owner.organizationId ? null : owner.userId,
    organizationId: owner.organizationId,
    type: input.type,
    name: input.name,
    notes: input.notes,
    key: input.key ?? null,
    reprompt: input.reprompt ?? 0,
    data: dataOf(input, null),
    folderId,
    favorite: input.favorite ?? false,
    archivedAt: input.archivedDate ?? null,
    createdAt: now,
    updatedAt: now,
    deletedAt: null,
  };
}

// An update is refused when the client edited an older copy than the one
// stored. One exception: the iOS app adds a cipher key with one update and
// builds its next request (such as moving the item to an organization) from
// its copy from before that update. That request carries a key (maybe
// re-wrapped for the organization) and the revision the key was added to;
// the key-adding update changed nothing else, so nothing is lost.
function isStale(existing: Cipher, input: CipherInput): boolean {
  const known = input.lastKnownRevisionDate;
  if (!known || Date.parse(existing.updatedAt) - Date.parse(known) <= REVISION_TOLERANCE_MS) return false;
  const keyAddedFrom = existing.data.keyAddedFromRevision;
  const followsKeyAddition =
    !!keyAddedFrom && !!input.key && Math.abs(Date.parse(keyAddedFrom) - Date.parse(known)) <= REVISION_TOLERANCE_MS;
  return !followsKeyAddition;
}

const hasAttachmentChanges = (input: CipherInput) =>
  Object.keys(input.attachments ?? {}).length > 0 || Object.keys(input.attachments2 ?? {}).length > 0;

// A cipher after a client's full update. What the input leaves out is kept
// as described in model.ts; the caller checks the folder.
export function applyUpdate(
  existing: Cipher,
  input: CipherInput,
  options: { now: string; preserveRevisionDate?: boolean; organizationId?: string },
): Cipher {
  // Clients re-encrypting attachment names send their current copy.
  if (!hasAttachmentChanges(input) && isStale(existing, input)) {
    throw badRequest('The client copy of this cipher is out of date. Resync the client and try again.');
  }
  const key = input.key ?? existing.key;
  // Remembered only by the update that adds the first key; any later update
  // ends the exception above.
  const keyAddedFromRevision = !existing.key && key ? existing.updatedAt : null;
  const organizationId = options.organizationId ?? existing.organizationId;
  return {
    ...existing,
    userId: organizationId ? null : existing.userId,
    organizationId,
    type: input.type,
    name: input.name,
    notes: input.notes,
    key,
    reprompt: input.reprompt ?? existing.reprompt,
    data: dataOf(input, existing.data, keyAddedFromRevision),
    folderId: input.folderId !== undefined ? (input.folderId ?? null) : existing.folderId,
    favorite: input.favorite ?? existing.favorite,
    archivedAt: input.archivedDate !== undefined ? (input.archivedDate ?? null) : existing.archivedAt,
    updatedAt: options.preserveRevisionDate ? existing.updatedAt : options.now,
  };
}

// Re-encrypted attachment names and keys a cipher update carries.
export function attachmentChanges(input: CipherInput): Array<{ id: string; fileName?: string; key?: string | null }> {
  const changes = new Map<string, { id: string; fileName?: string; key?: string | null }>();
  for (const [id, fileName] of Object.entries(input.attachments ?? {})) {
    if (fileName && isEncString(fileName)) changes.set(id, { id, fileName });
  }
  for (const [id, item] of Object.entries(input.attachments2 ?? {})) {
    const change = changes.get(id) ?? { id };
    if (item.fileName) change.fileName = item.fileName;
    if (item.key !== undefined) change.key = item.key;
    changes.set(id, change);
  }
  return [...changes.values()];
}

// Official clients state whom they encrypted a cipher for; one encrypted
// for another account would be unreadable.
export function checkEncryptedFor(input: CipherInput, userId: string): void {
  if (input.encryptedFor && input.encryptedFor !== userId) {
    throw badRequest('Cipher was not encrypted for the current user. Please try again.');
  }
}

export async function checkFolder(db: Executor, userId: string, folderId: string | null | undefined): Promise<void> {
  if (folderId && !(await findFolder(db, userId, folderId))) throw notFound('Folder not found');
}

// Organization ciphers go into at least one collection of their
// organization the user may put items into.
export async function checkWritableCollections(db: Executor, ctx: OrgContext, orgId: string, collectionIds: string[]): Promise<void> {
  if (!collectionIds.length) throw badRequest('Organization items must be assigned to at least one collection');
  if (!ctx.confirmed.has(orgId)) throw badRequest("You don't have permission to add items to this organization");
  const existing = new Set((await listCollections(db, [orgId])).map((collection) => collection.id));
  for (const collectionId of collectionIds) {
    if (!existing.has(collectionId)) throw badRequest('Invalid collection ID provided');
    if (!canWriteCollection(ctx, orgId, collectionId)) throw forbidden('No rights to add items to the collection');
  }
}

// Writes a cipher with the user's own state of it.
export async function saveView(tx: Executor, userId: string, cipher: Cipher, movedFrom?: string): Promise<void> {
  const written = await saveCiphers(tx, [cipher], { movedFrom });
  if (!written.has(cipher.id)) throw conflict('The item was moved at the same time. Resync the client and try again.');
  if (cipher.organizationId) await saveUserStates(tx, userId, [stateOf(cipher)]);
}

// Writes only the user's folder, favorite and archive state: on the row of
// a personal cipher, per user for an organization cipher.
export async function saveStates(tx: Executor, userId: string, ciphers: Cipher[]): Promise<void> {
  await saveCiphers(
    tx,
    ciphers.filter((cipher) => !cipher.organizationId),
  );
  await saveUserStates(
    tx,
    userId,
    ciphers.filter((cipher) => cipher.organizationId).map(stateOf),
  );
}

const stateOf = (cipher: Cipher) => ({
  cipherId: cipher.id,
  folderId: cipher.folderId,
  favorite: cipher.favorite,
  archivedAt: cipher.archivedAt,
});

export const pushItem = (cipher: Cipher, collectionIds: string[] | null = null): PushEvent['item'] => ({
  id: cipher.id,
  organizationId: cipher.organizationId,
  collectionIds,
  revisionDate: cipher.updatedAt,
});

export interface Change {
  // Organizations whose members see the change; the caller always does.
  orgIds: Array<string | null>;
  push: { type: PushType; item?: PushEvent['item'] };
}

// Runs `write` in one transaction that also moves the revision date of
// everyone who sees the change, so their clients sync; then tells their
// apps.
export async function commit<T>(deps: Deps, caller: Caller, now: string, change: Change, write: (tx: Executor) => Promise<T>): Promise<T> {
  const notified = new Set([caller.user.id]);
  const result = await deps.db.transaction().execute(async (tx) => {
    const value = await write(tx);
    await touchRevisionDate(tx, caller.user.id, now);
    for (const orgId of new Set(change.orgIds)) {
      if (!orgId) continue;
      for (const userId of await touchMemberRevisions(tx, orgId, now)) notified.add(userId);
    }
    return value;
  });
  for (const userId of notified) deps.push.notify({ ...change.push, userId, deviceIdentifier: caller.device });
  return result;
}
