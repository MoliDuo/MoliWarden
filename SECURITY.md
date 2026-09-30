# Security Policy

## How MoliWarden Protects Your Data

- **The vault is encrypted on your devices.** The server stores ciphertext and
  never sees the master password, only a hash of it, which it hashes again
  (PBKDF2) before storing.
- **Tokens are typed and short-lived.** Every token the server signs (access,
  file upload and download, Send access, user verification, passkey
  challenges) carries its type and an expiry and is signed with a key of its
  own derived from `JWT_SECRET`, so it is refused anywhere else. Access tokens
  last two hours.
- **Sessions rotate.** Every refresh hands out a new refresh token. Presenting a
  replaced one again after a minute's grace ends the whole session, so a stolen
  token stops working once either copy is used. Changing the password, logging
  a device out or banning a user ends sessions on every instance immediately;
  nothing is cached.
- **Server-side secrets are sealed.** 2FA seeds, recovery codes, API keys and
  backup destination credentials are encrypted with `ENCRYPTION_KEY`
  (AES-256-GCM); refresh tokens are stored only as hashes.
- **Guessing is throttled.** Wrong passwords lock the address out after 10 tries,
  and the account (for devices it has not signed in from) after 30 tries from any
  number of addresses. 2FA codes, API keys and Send passwords are throttled the
  same way, and every route has a request budget.
- **Password hints are off** unless `SHOW_PASSWORD_HINT=1`, since a hint is shown
  to anyone who knows the email address.
- **Expired data is removed** by the cron job (`CRON_SECRET`): sessions,
  challenges, used tokens, expired Sends and unfinished uploads.

## Reporting a Vulnerability

Thank you for helping keep MoliWarden safe.

Please **do not report security vulnerabilities through public GitHub issues, discussions, pull requests, or chat groups**.

Use GitHub Private Vulnerability Reporting instead:

1. Open the [MoliWarden repository](https://github.com/MoliDuo/MoliWarden) on GitHub.
2. Go to **Security and quality**.
3. Click **Report a vulnerability**.
4. Submit the report privately.

MoliWarden is independent from Bitwarden. Please do not report MoliWarden-specific issues to the Bitwarden team.

## What to Include

Please include as much detail as possible:

* A clear description of the vulnerability.
* Steps to reproduce.
* Affected version, commit, or deployment method.
* Affected area, such as login, sync, vault data, organizations and sharing, attachments, Send, import/export, backup/restore, Passkey, WebAuthn, or API routes.
* Expected behavior and actual behavior.
* Security impact, such as authentication bypass, authorization bypass, replay, cross-user access, token misuse, data leakage, or secret exposure.
* Proof of concept, logs, screenshots, or request examples, if safe to share privately.

Please redact real passwords, tokens, private keys, recovery keys, vault data, and other secrets before submitting.

## Scope

Security reports are welcome for issues affecting MoliWarden itself, including:

* Authentication and session handling.
* User authorization and cross-user access.
* Organizations: membership, roles, collection permissions and key exchange.
* Vault data, cipher sync, attachments, and Send.
* Import, export, backup, and restore.
* Passkey, WebAuthn, and two-factor authentication.
* Secret handling and provider credentials.
* Vercel, PostgreSQL, S3 or WebDAV behavior caused by MoliWarden code, build output or documentation.

## Out of Scope

The following are usually out of scope:

* Issues only affecting third-party services or user infrastructure.
* Misconfigured personal deployments not caused by MoliWarden defaults.
* Social engineering or phishing.
* Denial-of-service testing.
* Scanner-only reports without a practical exploit path.
* Reports that only mention outdated dependencies without showing real impact.

## Response

MoliWarden is maintained on a best-effort basis.

We aim to acknowledge valid private reports within 72 hours, investigate the issue, and release a fix or mitigation when appropriate.

Please do not publicly disclose vulnerability details before a fix or mitigation is available.

## Supported Versions

Security fixes are generally provided for the latest release and the latest code on the default branch.

| Version        | Supported              |
| -------------- | ---------------------- |
| Latest release | Yes                    |
| `main` branch  | Yes                    |
| Older releases | Best effort            |
| Modified forks | Not directly supported |

## Rewards

MoliWarden does not currently operate a paid bug bounty program.
