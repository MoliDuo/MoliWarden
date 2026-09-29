# Legacy (v1) fixture

A database written by the v1 backend (commit `88604b6`, the last one before the
backend rewrite). It is the input for the migration script and its tests. Almost
all data went in through the HTTP API. Direct SQL was used in two cases only:

- to write a handful of old stored formats that v1 still reads but can no
  longer write (`manifest.legacyVariants`);
- to push expiry timestamps far into the future (`manifest.clockAdjustments`).

| File | Contents |
| --- | --- |
| `v1.sql` | `pg_dump --no-owner --no-privileges` of the fixture DB (pg17). Version comments and `\restrict` lines are stripped. The rate-limit tables are emptied first. |
| `blobs.json` | Every S3 object, as `{ "<key>": "<base64>" }`. Attachments are keyed `<cipherId>/<attachmentId>`, send files `sends/<sendId>/<fileId>`. |
| `v1-backup.zip` | Admin backup export with attachments, assembled the same way the web vault does it (server zip plus blobs from `/api/admin/backup/blob`). It has no sends, devices, tokens, invites or audit logs, because backups never include those. |
| `manifest.json` | Accounts and credentials, feature ids, expected sync counts and cipher ids per account, row counts per table, and the legacy variants and clock adjustments. |
| `generate.ts` / `verify.ts` / `common.ts` | The generator, the restore-and-check script, and the helpers they share. |

## Regenerate / verify

You need Postgres at `localhost:55432` (`mw`/`mw`, container `mw-pg`) and
SeaweedFS S3 at `localhost:58333` (`mwaccess`/`mwsecret123`).

```sh
npx tsx tests/legacy-fixture/generate.ts   # rebuilds DB mw_fixture + bucket mw-legacy-fixture, rewrites the outputs
npx tsx tests/legacy-fixture/verify.ts     # restores into mw_fixture_verify + bucket mw-legacy-fixture-verify, runs the checks
```

The server code comes from `git archive 88604b6` into `$TMPDIR/moliwarden-fixture-src-<commit>`,
with `node_modules` symlinked from this checkout. You can change the source with these variables:

- `FIXTURE_SERVER_REF=<commit>` uses a different commit.
- `FIXTURE_SERVER_REF=worktree` uses the checkout as it is.
- `FIXTURE_SERVER_ROOT=<dir>` uses an export you already made.

You can also override the database and bucket names:
`FIXTURE_DATABASE_URL`, `FIXTURE_VERIFY_DATABASE_URL`, `FIXTURE_S3_BUCKET`, `FIXTURE_VERIFY_S3_BUCKET`.

To serve the fixture, use:

- `JWT_SECRET` from the manifest. It also keys the backup-settings runtime envelope.
- The URL `http://127.0.0.1:<port>`. The passkeys are bound to RP id `127.0.0.1`.
- A Yubico mock that uses the fixed API secret. `startFixedYubicoMock()` in `common.ts` is one.

Server-side ids are random, so every regeneration produces a large diff.

## Accounts

Every password is the harness convention: `masterPasswordHash = base64("hash-<email>")`.
The manifest lists each account's secrets: the TOTP secret, recovery codes, the
YubiKey public id, remember tokens, refresh tokens, API keys and passkey private keys
(PKCS8 and JWK, plus the counter and PRF seed).

| Account | Covers |
| --- | --- |
| `admin@` | First user and instance admin, with a real RSA key so the backup settings carry a portable wrap. Configures the Yubico API, sets log retention to 365 days, and creates invites (used, unused, expired, deleted). Has backup settings with one S3 destination (scheduled) and one WebDAV destination, both with credentials. Owns "Fixture Org" (3 collections, 6 org ciphers, one moved from a personal item, one soft-deleted, one with an attachment). Bans `banned@`. |
| `vault@` | PBKDF2 350k with a password hint. Folders; cipher types 1–8 (login with URIs/FIDO2/TOTP/fields/password history). Favorite, archived, trashed, reprompt, a cipher key, and the key-added marker. 3 attachments. 7 sends: text, hash password, server-salted password, hidden/hideEmail/expiring, disabled, max-access reached, and file. Custom and excluded global equivalent domains. A rotated API key. Android (push token), web (cookie session), extension, desktop (device keys and note), cli and sdk devices. Auth requests: pending, approved, denied, redeemed. Org user with manage on one collection. |
| `argon@` | Argon2id (3 iterations / 64 MiB / 4 lanes). Org admin. Owns "Argon Org", which has no org key pair. |
| `totp@` | TOTP with a fixed secret, a recovery code and a remember token. Org user with readOnly and hidePasswords, plus per-user folder and favorite on an org item. |
| `yubikey@` | YubiKey OTP with NFC. Org invite still pending (status 0). |
| `webauthn2fa@` | WebAuthn security key as 2FA, with a remember token. Org status accepted (1). |
| `passkey@` | Three login passkeys: PRF with a key set, PRF without a key set, and no PRF. Org member confirmed, then revoked. |
| `manager@` / `custom@` | Org Manager (type 3) / Custom (stored as type 3 with access_all). |
| `banned@` | Banned; login must fail. |
| `legacy-rawhash@` | `master_password_hash` holds the raw client hash, with no `$s$` prefix. |
| `legacy-apikey@` | `api_key` stored as `sha256:<hex>`. Viewing it returns 409; client_credentials still works. |
| `legacy-domains@` | Only `equivalent_domains` is set; `custom_equivalent_domains` is `[]`. |
| `legacy-totp@` | TOTP secret stored lower-case with spaces, dashes and padding; recovery code stored ungrouped and lower-case. |
| `legacy-yubikey@` | YubiKey public id stored upper-case and space-padded. |
| `legacy-kdf@` | PBKDF2 with 5000 iterations, below today's minimum. |
| `legacy-status@` | `status='disabled'`, `role='member'`; the server reads these as active and user. |
| `legacy-session@` | A refresh token row with NULL stamps, client type and absolute expiry. The token is in the manifest. |
| `legacy-cipher@` | Three cipher rows: scalar values kept only in `data`; PascalCase server keys (`Id`, `Edit`, …) in `data`; an SSH key with only `fingerprint`. |
