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

## Development

```bash
npm install
```

```bash
npm run build && npm run dev:server
```

`npm run dev:server` reads the variables above from the environment. Tests need a disposable Postgres database and S3 bucket (see `tests/helpers.ts`); each test file resets the `public` schema.

```bash
npm run test:e2e
```

```bash
npm run check:sql
```

## License

LGPL-3.0, as NodeWarden. Thanks to [NodeWarden](https://github.com/shuaiplus/NodeWarden), [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and [Bitwarden](https://bitwarden.com/).
