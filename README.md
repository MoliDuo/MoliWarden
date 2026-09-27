# MoliWarden

A Bitwarden-compatible server for **Vercel**, based on [NodeWarden](https://github.com/shuaiplus/NodeWarden) 1.8.0.

[中文说明](./README_ZH.md)

- Storage: Cloudflare D1 → **PostgreSQL** (Neon via the Vercel Marketplace works out of the box)
- Attachments and Send files: R2 / KV → **any S3-compatible bucket**
- New: **Organizations** — members, collections and per-collection permissions, usable from the official clients and the bundled web vault

> Not affiliated with Bitwarden. For learning purposes; back up your vault regularly.

## Differences from NodeWarden

| Feature | Status | Notes |
|---|---|---|
| Vault, TOTP, passkey login, 2FA, devices, login requests | ✅ | unchanged |
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
| `JWT_SECRET` | ✅ | 32+ random characters |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | ✅ | |
| `S3_REGION` | | default `auto` |
| `S3_FORCE_PATH_STYLE` | | `0` for virtual-hosted-style URLs |
| `CRON_SECRET` | recommended | authenticates Vercel Cron calls to `/api/internal/cron` (scheduled backups) |
| `MOLIWARDEN_CRON_SCHEDULE` | | build-time cron expression, daily by default (Hobby plans only allow daily jobs) |
| `PUSH_RELAY_DISABLED` | | `1` to skip registering with the Bitwarden push relay |
| `HIDE_WEB_VAULT` | | `1` at build time to publish only the client API |

4. Open the site and register. The first account becomes the instance admin; later sign-ups need an invite code from the admin panel. Tables are created on the first request.

Downloads above 4 MB redirect to presigned S3 URLs; to download those from the web vault or browser extension, allow `GET` from your site origin (and `chrome-extension://*`) in the bucket's CORS rules.

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

runs type checks, i18n validation, unit tests, `check:sql` (every SQL statement is `PREPARE`d on Postgres), the API end-to-end suites (`npm run test:e2e`) and `npm run test:smoke`, which builds `.vercel/output`, copies it outside the repository and serves it with `tests/vercel-emulator.ts` (Vercel routing, 4.5 MB body limit, `waitUntil`, cron calls). `scripts/vercel-build-local.sh` runs the official `vercel build` without an account. CI runs all of it on every push.

`tests/official-cli.test.ts` drives the official Bitwarden CLI (`bw`) over HTTPS against accounts and organizations created with real client crypto: login (password and API key), lock/unlock, items, folders, attachments, Sends, export, confirming members, sharing and collections. The CLI is not a dependency; it is installed on first run into `~/.cache/moliwarden-bw-cli` (override with `BW_CLI=/path/to/bw` or `BW_CLI_VERSION`). Run it with `npm run test:official-cli` (about 5 minutes; part of `npm test` and CI).

`npm run test:ui` clicks through the web vault in Chromium (Playwright, in the official Docker image by default): items, folders, trash, attachments, Sends, import/export, settings, admin, the full organization flow, a Chinese-language pass and a 375px phone pass. Any page error, console error, error toast or 5xx fails it; see `tests/ui/README.md`.

Limits worth knowing: web vault imports are split into several requests automatically, but `bw import` sends one request and fails above ~4.5 MB; backup files uploaded from the browser are capped at 4.4 MB (restore larger ones from WebDAV/S3); sync responses are streamed and not limited. Put the Neon database in the same region as the Vercel functions (`iad1` by default).

## License

LGPL-3.0, as NodeWarden. Thanks to [NodeWarden](https://github.com/shuaiplus/NodeWarden), [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and [Bitwarden](https://bitwarden.com/).
