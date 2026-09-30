# MoliWarden

A Bitwarden-compatible server for **Vercel**, with its own web vault.

[中文说明](./README_ZH.md)

- Storage: **PostgreSQL** (Neon via the Vercel Marketplace works out of the box)
- Attachments and Send files: **any S3-compatible bucket**
- **Organizations** — members, collections and per-collection permissions, usable from the official clients and the bundled web vault

> Not affiliated with Bitwarden. For learning purposes; back up your vault regularly.

## Features

| Feature | Status | Notes |
|---|---|---|
| Vault, TOTP, passkey login, 2FA, devices, login requests | ✅ | |
| Attachments / Send | ✅ | uploads through official clients are capped at ~4.4 MB per file (Vercel request body limit) |
| Instance backups (local / WebDAV / S3) | ✅ | include organization data |
| **Organizations / collections / roles** | ✅ | owner, admin, manager, user; view / view without passwords / edit / manage |
| Realtime push (WebSocket) | ⚠️ | not possible on Vercel; desktop and extension clients rely on periodic sync, mobile push relay still works |
| Email, groups, policies, SSO, emergency access | ❌ | invitations are accepted from the web vault's Organizations page |

## Deploy to Vercel

1. Add **Neon** (or set `DATABASE_URL` to any Postgres) and create a private S3 bucket.
2. Import the repository into Vercel. `vercel.json` sets the build command (`npm run build:vercel`), which emits a Build Output API bundle.
3. Set the environment variables:

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | ✅ | also accepts `POSTGRES_URL` |
| `JWT_SECRET` | ✅ | 32+ random characters; signs login tokens, changing it signs everyone out |
| `ENCRYPTION_KEY` | ✅ | 32+ random characters, different from `JWT_SECRET`; encrypts the 2FA seeds, recovery codes, API keys and backup credentials the server keeps. Keep it: a changed key makes them unreadable |
| `SHOW_PASSWORD_HINT` | | `1` to let the login page show password hints (off: a hint tells anyone who knows the email something about the password) |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | ✅ | |
| `S3_REGION` | | default `auto` |
| `S3_FORCE_PATH_STYLE` | | `0` for virtual-hosted-style URLs |
| `CRON_SECRET` | recommended | authenticates Vercel Cron calls to `/api/internal/cron`, which runs scheduled backups and removes expired sessions, tokens, Sends and abandoned uploads. Without it the job does not run |
| `MOLIWARDEN_CRON_SCHEDULE` | | build-time cron expression, daily by default (Hobby plans only allow daily jobs) |
| `BACKUP_ALLOW_PRIVATE_HOSTS` | | `1` to let backup destinations use private or loopback addresses (self-hosted NAS, tests) |
| `PUSH_RELAY_DISABLED` | | `1` to skip registering with the Bitwarden push relay |
| `HIDE_WEB_VAULT` | | `1` at build time to publish only the client API |
| `ICON_SOURCE` | | where website icons come from: `favicon` (default; favicon.im, then Bitwarden's service), `bitwarden`, or `off` |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_NAME` | | passkey relying party; default the site's host name and `MoliWarden` |
| `WEBAUTHN_ALLOWED_ORIGINS` | | comma-separated extra origins allowed to use passkeys; the official extensions and desktop app are always allowed |
| `MAX_UPLOAD_BYTES` | | largest attachment or Send file, default 4400000 (Vercel Functions accept bodies up to 4.5 MB) |
| `DATABASE_POOL_MAX` | | connections per function instance, default 5 |
| `YUBICO_VALIDATION_URLS` | | comma-separated YubiKey OTP validation servers, default Yubico's |

4. Open the site and register. The first account becomes the instance admin; later sign-ups need an invite code from the admin panel. Tables are created on the first request.

Downloads above 4 MB redirect to presigned S3 URLs; to download those from the web vault or browser extension, allow `GET` from your site origin (and `chrome-extension://*`) in the bucket's CORS rules.

## Upgrading from an earlier version

Releases before the storage rewrite kept their data in other tables. The new version does not convert them on its own: until you run the migration it answers every request with `503` and a pointer to this section. The earlier version must not keep writing during the upgrade, and deploying the new one stops it.

1. **Back up.** In the old web vault, export an instance backup with attachments (Admin → Backups), and take a snapshot of the database: a Neon branch, or `pg_dump`.
2. **Deploy.** Keep `JWT_SECRET` as it is, add `ENCRYPTION_KEY`, and deploy the new version.
3. **Migrate.** From a checkout of this repository, against the production database. Use a direct connection, not a pooled one; the script prefers `DATABASE_URL_UNPOOLED` (set by the Neon integration) over `DATABASE_URL`. `JWT_SECRET` must be the one the earlier version ran with, since it opens the stored backup settings:

   ```bash
   DATABASE_URL='<direct url>' JWT_SECRET='<current>' ENCRYPTION_KEY='<new>' npm run db:migrate-legacy -- --dry-run
   ```

   The dry run converts and checks everything, then undoes it. It prints the rows read and written, the rows it had to leave out and why, and what users need to do. When the output looks right, run the same command without `--dry-run`. The whole migration is a single transaction.
4. **Check.** Reload the site and sign in. The web vault asks everyone to sign in once, because its browser storage was renamed. The official apps, the browser extension and `bw` stay signed in, and TOTP, security keys, passkeys, remembered devices and API keys keep working. The exception is an API key the earlier version stored only as a hash: it has to be issued again, and the report names these users. Sync, open an attachment, and run a backup.
5. **Backup destinations (optional).** A destination keeps an index of the attachment files it already holds, and that index was renamed. Copy it so the first backup does not upload every attachment again:

   ```bash
   DATABASE_URL='<direct url>' ENCRYPTION_KEY='<new>' npm run db:migrate-legacy -- --migrate-remote-index
   ```

   Archives the earlier version wrote keep their old names. Retention does not prune them; delete them by hand when you no longer need them.

**Rolling back.** As long as nothing has been written since the migration, `npm run db:migrate-legacy -- --rollback` moves the earlier tables back. Then redeploy the earlier version (Vercel → Deployments → Instant Rollback). Once there are new writes it refuses, because they would be lost; restore the snapshot from step 1 instead.

**Cleaning up.** The migration keeps the earlier tables in a schema named `legacy`. When you are sure you will not roll back, drop it: `DROP SCHEMA legacy CASCADE;`.

**Old backup archives.** The new version does not restore archives of the earlier version directly. Convert one first:

```bash
npm run backup:convert-v1 -- old-backup.zip
```

This writes a `moliwarden_backup_*.zip` next to the input, which you import as usual (Admin → Backups). For files above the 4.4 MB upload limit, put the converted archive into a backup destination and restore it from there. Exports of the web vault's own JSON format from the earlier version import without their attachments; export again after upgrading.

## Development and tests

```bash
npm install
```

```bash
npm run test:services
```

Run the server locally with `npm run build && npm run dev:server` (reads the variables above from the environment).

`npm run test:services` starts Postgres, an S3 server (SeaweedFS) and a transaction-mode PgBouncer (like Neon's pooled URL) with the defaults in `tests/helpers.ts`.

```bash
npm test
```

runs type checks, i18n validation, unit tests, the API end-to-end suites (`npm run test:e2e`) and `npm run test:smoke`, which builds `.vercel/output`, copies it outside the repository and serves it with `tests/vercel-emulator.ts` (Vercel routing, 4.5 MB body limit, `waitUntil`, cron calls). `scripts/vercel-build-local.sh` runs the official `vercel build` without an account. CI runs all of it on every push.

`tests/official-cli.test.ts` drives the official Bitwarden CLI (`bw`) over HTTPS against accounts and organizations created with real client crypto: login (password and API key), lock/unlock, items, folders, attachments, Sends, export, confirming members, sharing and collections. The CLI is not a dependency; it is installed on first run into `~/.cache/moliwarden-bw-cli` (override with `BW_CLI=/path/to/bw` or `BW_CLI_VERSION`). Run it with `npm run test:official-cli` (about 5 minutes; part of `npm test` and CI).

`npm run test:ui` clicks through the web vault in Chromium (Playwright, in the official Docker image by default): items, folders, trash, attachments, Sends, import/export, settings, admin, the full organization flow, a Chinese-language pass and a 375px phone pass. Any page error, console error, error toast or 5xx fails it; see `tests/ui/README.md`.

Limits worth knowing: web vault imports are split into several requests automatically, but `bw import` sends one request and fails above ~4.5 MB; backup files uploaded from the browser are capped at 4.4 MB (restore larger ones from WebDAV/S3); sync responses are streamed and not limited. Put the Neon database in the same region as the Vercel functions (`iad1` by default).

## License

LGPL-3.0, see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
