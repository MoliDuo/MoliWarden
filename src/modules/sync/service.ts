import type { Caller } from '../../http/authenticate';
import type { Deps } from '../../main/deps';
import { isEncString } from '../../platform/enc-string';
import { sendToResponse } from '../../handlers/sends-shared';
import { buildUserDecryptionCompat, buildUserDecryptionOptions } from '../accounts/decryption';
import { profile } from '../accounts/service';
import { viewsJson, listViews } from '../ciphers/views';
import { domainsJson } from '../domains/service';
import { foldersJson } from '../folders/service';
import { loadOrgContext, visibleCollections } from '../organizations/access';
import { collectionDetailsJson } from '../organizations/responses';
import { listPasskeys } from '../passkeys/repo';
import { prfDecryptionOption } from '../passkeys/webauthn';
import { listSends } from '../sends/repo';

export interface SyncOptions {
  excludeDomains: boolean;
  excludeSends: boolean;
}

// Everything a client keeps of the account, in one response. The number of
// queries does not grow with the size of the vault.
export async function sync(deps: Deps, caller: Caller, options: SyncOptions) {
  const { user } = caller;
  const ctx = await loadOrgContext(deps.db, user.id);
  const [account, folders, collections, views, domains, sends, passkeys] = await Promise.all([
    profile(deps, user),
    foldersJson(deps, user),
    visibleCollections(deps.db, ctx),
    listViews(deps.db, ctx),
    options.excludeDomains ? null : domainsJson(deps.db, user.id, { omitExcludedGlobals: true }),
    options.excludeSends ? [] : listSends(deps.db, user.id),
    listPasskeys(deps.db, user.id, 'login'),
  ]);
  const prfOptions = passkeys.map(prfDecryptionOption).filter((option) => !!option);
  const decryptionOptions = buildUserDecryptionOptions(user, prfOptions[0] ?? null);

  return {
    profile: account,
    folders: folders.data,
    collections: collections.map((collection) => collectionDetailsJson(collection, ctx)),
    // An item the clients cannot decrypt would make them drop the whole sync.
    ciphers: (await viewsJson(deps.db, views)).filter((cipher) => isEncString(cipher.name)),
    domains,
    policies: [],
    policiesNew: [],
    sends: sends.map(sendToResponse),
    UserDecryption: {
      MasterPasswordUnlock: decryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      WebAuthnPrfOption: prfOptions[0] ?? null,
      WebAuthnPrfOptions: prfOptions,
      V2UpgradeToken: null,
      UserKeyId: user.keyId ?? null,
      Object: 'userDecryption',
    },
    UserDecryptionOptions: decryptionOptions,
    userDecryption: buildUserDecryptionCompat(user),
    object: 'sync',
  };
}
