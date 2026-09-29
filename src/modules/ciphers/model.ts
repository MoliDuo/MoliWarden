import { z } from 'zod';
import { integer, isoDate } from '../../http/body';
import { normalizeKeys } from '../../platform/camel-case';
import { isEncString } from '../../platform/enc-string';

// A cipher is a vault item. Everything a client encrypts is kept as it was
// sent, but only the fields Bitwarden defines are kept at all: the same
// schema validates what clients send and reads back what is stored.
//
// Stored data is read leniently: a field that does not fit (from before
// the server validated everything) reads as null, and a list entry that
// does not fit is left out, so one broken field cannot hide an item.

export const CipherType = {
  Login: 1,
  SecureNote: 2,
  Card: 3,
  Identity: 4,
  SshKey: 5,
  BankAccount: 6,
  DriversLicense: 7,
  Passport: 8,
} as const;
export type CipherType = (typeof CipherType)[keyof typeof CipherType];

type Mode = 'input' | 'stored';

const encString = (max?: number) => {
  const text = z.string().trim();
  return (max ? text.max(max, `Must be at most ${max} characters.`) : text).refine(isEncString, 'Must be an encrypted string.');
};

function schemas(mode: Mode) {
  const lenient = <T extends z.ZodType>(schema: T) => (mode === 'input' ? schema : schema.catch(null as z.output<T>));
  // Missing and null both read as null.
  const optional = <T extends z.ZodType>(schema: T) => lenient(schema.nullish().transform((value) => value ?? null));
  const enc = (max?: number) => optional(encString(max));
  const list = <T extends z.ZodType>(item: T) =>
    mode === 'input'
      ? z
          .array(item)
          .nullish()
          .transform((items) => (items?.length ? items : null))
      : z
          .array(z.unknown())
          .nullish()
          .catch(null)
          .transform((entries) => {
            const items = (entries ?? []).flatMap((entry) => {
              const parsed = item.safeParse(entry);
              return parsed.success ? [parsed.data as z.output<T>] : [];
            });
            return items.length ? items : null;
          });
  const part = <T extends z.ZodRawShape>(shape: T) => optional(z.object(shape));
  const encFields = <K extends string>(keys: readonly K[], max: number) =>
    Object.fromEntries(keys.map((key) => [key, enc(max)])) as Record<K, ReturnType<typeof enc>>;

  const fido2Credential = z.object({
    credentialId: encString(),
    keyType: encString(),
    keyAlgorithm: encString(),
    keyCurve: encString(),
    keyValue: encString(),
    rpId: encString(),
    counter: encString(),
    discoverable: encString(),
    userHandle: enc(),
    userName: enc(),
    rpName: enc(),
    userDisplayName: enc(),
    creationDate: optional(isoDate),
  });

  const login = part({
    uri: enc(10000),
    uris: list(z.object({ uri: enc(10000), uriChecksum: enc(10000), match: optional(integer) })),
    username: enc(1000),
    password: enc(5000),
    passwordRevisionDate: optional(isoDate),
    totp: enc(1000),
    autofillOnPageLoad: optional(z.boolean()),
    fido2Credentials: list(fido2Credential),
  });

  const sshKey = optional(
    z.preprocess(
      // Older web vault payloads call the fingerprint `fingerprint`.
      (value) => (value && typeof value === 'object' && !('keyFingerprint' in value) ? { ...value, keyFingerprint: (value as { fingerprint?: unknown }).fingerprint } : value),
      z.object({ privateKey: encString(), publicKey: encString(), keyFingerprint: encString() }),
    ),
  );

  return {
    login,
    secureNote: part({ type: integer.nullish().transform((type) => type ?? 0) }),
    card: part(encFields(['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'], 1000)),
    identity: part(
      encFields(
        [
          'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3', 'city', 'state',
          'postalCode', 'country', 'company', 'email', 'phone', 'ssn', 'username', 'passportNumber', 'licenseNumber',
        ],
        10000,
      ),
    ),
    sshKey,
    bankAccount: part(
      encFields(
        ['bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber', 'pin', 'swiftCode', 'iban', 'bankContactPhone'],
        10000,
      ),
    ),
    driversLicense: part(
      encFields(
        ['firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry', 'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass'],
        10000,
      ),
    ),
    passport: part(
      encFields(
        ['surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry', 'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority', 'issueDate', 'expirationDate'],
        10000,
      ),
    ),
    fields: list(z.object({ name: enc(), value: enc(), type: integer.nullish().transform((type) => type ?? 0), linkedId: optional(integer) })),
    passwordHistory: list(
      z.object({ password: encString(), lastUsedDate: isoDate.nullish().transform((date) => date ?? new Date().toISOString()) }),
    ),
  };
}

const input = schemas('input');
const stored = schemas('stored');

// The part of a cipher that depends on its type; a cipher has only its own.
export const TYPE_PARTS = {
  [CipherType.Login]: 'login',
  [CipherType.SecureNote]: 'secureNote',
  [CipherType.Card]: 'card',
  [CipherType.Identity]: 'identity',
  [CipherType.SshKey]: 'sshKey',
  [CipherType.BankAccount]: 'bankAccount',
  [CipherType.DriversLicense]: 'driversLicense',
  [CipherType.Passport]: 'passport',
} as const;
export type TypePart = (typeof TYPE_PARTS)[CipherType];

// What is stored in `ciphers.data`.
export const cipherData = z.object({
  login: stored.login,
  secureNote: stored.secureNote,
  card: stored.card,
  identity: stored.identity,
  sshKey: stored.sshKey,
  bankAccount: stored.bankAccount,
  driversLicense: stored.driversLicense,
  passport: stored.passport,
  fields: stored.fields,
  passwordHistory: stored.passwordHistory,
  // The revision right before a client first gave the cipher a key (see
  // service.ts); never shown to clients.
  keyAddedFromRevision: z.string().nullish().catch(null).transform((value) => value ?? null),
});
export type CipherData = z.output<typeof cipherData>;

export function readCipherData(json: string): CipherData {
  let parsed: unknown = {};
  try {
    parsed = JSON.parse(json);
  } catch {
    // Unreadable data reads as empty.
  }
  return cipherData.parse(normalizeKeys(parsed && typeof parsed === 'object' ? parsed : {}));
}

// Only what is set, so the column stays small.
export function writeCipherData(data: CipherData): string {
  return JSON.stringify(Object.fromEntries(Object.entries(data).filter(([, value]) => value !== null)));
}

export interface Cipher {
  id: string;
  // Exactly one of the two owns the cipher.
  userId: string | null;
  organizationId: string | null;
  type: CipherType;
  name: string;
  notes: string | null;
  key: string | null;
  reprompt: number;
  data: CipherData;
  // Where the viewing user keeps it; for an organization cipher these are
  // per user.
  folderId: string | null;
  favorite: boolean;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

// Fields a client sets on a cipher. A missing type part, password history
// or key keeps what is stored; missing notes and fields clear them, as some
// clients leave out what the user emptied.
export const cipherInput = z.object({
  type: integer.pipe(z.number().min(1, 'Unknown cipher type.').max(8, 'Unknown cipher type.')).transform((type) => type as CipherType),
  organizationId: z.preprocess((value) => (value === '' ? null : value), z.string().trim().toLowerCase().nullish()),
  folderId: z.preprocess((value) => (value === '' ? null : value), z.string().trim().toLowerCase().nullish()),
  name: encString(1000),
  notes: encString(10000).nullish().transform((value) => value ?? null),
  key: encString().nullish(),
  favorite: z.boolean().nullish(),
  reprompt: integer.pipe(z.number().min(0).max(1)).nullish(),
  login: input.login.optional(),
  secureNote: input.secureNote.optional(),
  card: input.card.optional(),
  identity: input.identity.optional(),
  sshKey: input.sshKey.optional(),
  bankAccount: input.bankAccount.optional(),
  driversLicense: input.driversLicense.optional(),
  passport: input.passport.optional(),
  fields: input.fields,
  passwordHistory: input.passwordHistory.optional(),
  archivedDate: isoDate.nullish(),
  // The user the client encrypted the cipher for.
  encryptedFor: z.string().trim().toLowerCase().nullish(),
  lastKnownRevisionDate: isoDate.nullish().catch(null),
  // Attachment names and keys, re-encrypted when the cipher gets a key or
  // moves to an organization. `attachments` is the old form, id -> name.
  attachments: z.record(z.string(), z.string().nullable()).nullish().catch(null),
  attachments2: z
    .record(z.string(), z.object({ fileName: encString().nullish(), key: encString().nullish() }))
    .nullish(),
});
export type CipherInput = z.output<typeof cipherInput>;
