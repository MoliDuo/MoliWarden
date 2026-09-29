// Every route the server answers, as (method, path, access). This list is the
// contract with Bitwarden clients and the web vault: tests/route-inventory
// checks that each entry is routed (never "route not found" or 405) and that
// non-public routes demand a bearer token.
//
// `:name` segments are filled with sample values by the test. Aliases are
// listed separately because clients call them verbatim.

export type Access = 'public' | 'user' | 'admin';
export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';
export type Route = readonly [Method, string, Access];

const MAIL_BACKED_PUBLIC = [
  '/api/accounts/resend-new-device-otp',
  '/accounts/resend-new-device-otp',
  '/api/accounts/register/send-verification-email',
  '/accounts/register/send-verification-email',
  '/identity/accounts/register/send-verification-email',
  '/api/accounts/register/verification-email-clicked',
  '/accounts/register/verification-email-clicked',
  '/identity/accounts/register/verification-email-clicked',
  '/api/accounts/register/finish',
  '/accounts/register/finish',
  '/identity/accounts/register/finish',
  '/api/accounts/verify-email-token',
  '/accounts/verify-email-token',
  '/api/two-factor/send-email-login',
  '/two-factor/send-email-login',
];

const MAIL_BACKED_ACCOUNT = [
  '/api/accounts/email-token',
  '/accounts/email-token',
  '/api/accounts/verify-email',
  '/accounts/verify-email',
  '/api/accounts/request-otp',
  '/accounts/request-otp',
  '/api/accounts/verify-otp',
  '/accounts/verify-otp',
];

const EMAIL_TWO_FACTOR = [
  '/api/two-factor/get-email',
  '/two-factor/get-email',
  '/api/two-factor/send-email',
  '/two-factor/send-email',
  '/api/two-factor/email',
  '/two-factor/email',
];

function each(methods: Method[], paths: string[], access: Access): Route[] {
  return methods.flatMap((method) => paths.map((path) => [method, path, access] as const));
}

export const ROUTES: readonly Route[] = [
  // --- meta ---
  ['GET', '/.well-known/appspecific/com.chrome.devtools.json', 'public'],
  ...each(['GET'], ['/api/web-bootstrap', '/web-bootstrap'], 'public'),
  ...each(['GET'], ['/config', '/api/config'], 'public'),
  ...each(['GET'], ['/api/alive', '/api/now', '/api/version'], 'public'),
  ['GET', '/fill-assist/manifest.json', 'public'],
  ['GET', '/fill-assist/:form', 'public'],
  ...each(['GET'], ['/v1/assetlinks:check', '/api/v1/assetlinks:check'], 'public'),
  ['GET', '/icons/:host/icon.png', 'public'],
  ['GET', '/api/internal/cron', 'public'],
  ['GET', '/api/tasks', 'user'],
  ['GET', '/api/policies', 'user'],

  // --- identity ---
  ['POST', '/identity/connect/token', 'public'],
  ...each(['POST'], ['/identity/connect/revocation', '/identity/connect/revoke'], 'public'),
  ...each(['POST'], ['/identity/accounts/prelogin', '/api/accounts/prelogin', '/identity/accounts/prelogin/password'], 'public'),
  ['GET', '/identity/accounts/webauthn/assertion-options', 'public'],
  ...each(['POST'], ['/identity/accounts/recover-2fa', '/api/accounts/recover-2fa'], 'public'),
  ...each(['POST'], MAIL_BACKED_PUBLIC, 'public'),

  // --- accounts ---
  ['POST', '/api/accounts/register', 'public'],
  ['POST', '/api/accounts/password-hint', 'public'],
  ...each(['GET', 'PUT', 'POST'], ['/api/accounts/profile'], 'user'),
  ...each(['POST', 'PUT'], ['/api/accounts/password', '/api/accounts/change-password'], 'user'),
  ...each(['GET', 'POST'], ['/api/accounts/keys'], 'user'),
  ['GET', '/api/accounts/revision-date', 'user'],
  ['POST', '/api/accounts/verify-password', 'user'],
  ...each(['PUT', 'POST'], ['/api/accounts/verify-devices'], 'user'),
  ['POST', '/api/accounts/key-management/user-key-id', 'user'],
  ...each(['POST'], ['/api/accounts/api-key', '/api/accounts/api_key'], 'user'),
  ...each(['POST'], ['/api/accounts/rotate-api-key', '/api/accounts/rotate_api_key'], 'user'),
  ...each(['POST', 'PUT'], ['/api/accounts/kdf', '/accounts/kdf'], 'user'),
  ...each(['POST', 'PUT', 'DELETE'], ['/api/accounts/set-password', '/api/accounts/delete', '/api/accounts/delete-account', '/api/accounts/delete-vault'], 'user'),
  ...each(['POST', 'PUT'], MAIL_BACKED_ACCOUNT, 'user'),
  ...each(['GET', 'PUT'], ['/api/settings/domains', '/settings/domains'], 'user'),
  ['POST', '/settings/domains', 'user'],
  ['POST', '/api/settings/domains', 'user'],
  ['GET', '/api/users/:id/public-key', 'user'],

  // --- two-factor ---
  ...each(['GET', 'PUT', 'POST'], ['/api/accounts/totp'], 'user'),
  ...each(['POST'], ['/api/accounts/totp/recovery-code', '/api/two-factor/get-recover'], 'user'),
  ['GET', '/api/two-factor', 'user'],
  ['POST', '/api/two-factor/get-authenticator', 'user'],
  ...each(['PUT', 'POST', 'DELETE'], ['/api/two-factor/authenticator'], 'user'),
  ...each(['POST'], ['/api/two-factor/get-yubikey', '/api/two-factor/get-yubi-key'], 'user'),
  ...each(['PUT', 'POST', 'DELETE'], ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'], 'user'),
  ...each(['PUT', 'POST'], ['/api/two-factor/yubikey/config', '/api/two-factor/yubi-key/config'], 'user'),
  ...each(['POST'], ['/api/two-factor/yubikey/bootstrap', '/api/two-factor/yubi-key/bootstrap'], 'user'),
  ['POST', '/api/two-factor/get-webauthn', 'user'],
  ['POST', '/api/two-factor/get-webauthn-challenge', 'user'],
  ...each(['PUT', 'POST', 'DELETE'], ['/api/two-factor/webauthn'], 'user'),
  ['POST', '/api/two-factor/get-device-verification-settings', 'user'],
  ...each(['PUT', 'POST'], ['/api/two-factor/device-verification-settings'], 'user'),
  ...each(['PUT', 'POST'], ['/api/two-factor/disable'], 'user'),
  ...each(['POST', 'PUT', 'DELETE'], EMAIL_TWO_FACTOR, 'user'),

  // --- account passkeys ---
  ...each(['GET', 'POST', 'PUT'], ['/api/webauthn', '/webauthn'], 'user'),
  ...each(['POST'], ['/api/webauthn/attestation-options', '/webauthn/attestation-options'], 'user'),
  ...each(['POST'], ['/api/webauthn/assertion-options', '/webauthn/assertion-options'], 'user'),
  ...each(['POST'], ['/api/webauthn/:id/delete', '/webauthn/:id/delete'], 'user'),

  // --- devices ---
  ['GET', '/api/devices/knowndevice', 'public'],
  ...each(['GET', 'POST', 'DELETE'], ['/api/devices', '/devices'], 'user'),
  ...each(['POST'], ['/api/devices/lost-trust', '/devices/lost-trust'], 'user'),
  ...each(['GET', 'DELETE'], ['/api/devices/authorized', '/devices/authorized'], 'user'),
  ...each(['DELETE'], ['/api/devices/authorized/:identifier', '/devices/authorized/:identifier'], 'user'),
  ...each(['POST'], ['/api/devices/authorized/:identifier/permanent', '/devices/authorized/:identifier/permanent'], 'user'),
  ...each(['GET', 'DELETE'], ['/api/devices/:identifier', '/devices/:identifier'], 'user'),
  ...each(['PUT'], ['/api/devices/:identifier/name', '/devices/:identifier/name'], 'user'),
  ...each(['GET'], ['/api/devices/identifier/:identifier', '/devices/identifier/:identifier'], 'user'),
  ...each(['PUT', 'POST'], ['/api/devices/:identifier/keys', '/api/devices/identifier/:identifier/keys'], 'user'),
  ...each(['PUT', 'POST'], ['/api/devices/identifier/:identifier/token', '/devices/identifier/:identifier/token'], 'user'),
  ...each(['PUT', 'POST'], ['/api/devices/identifier/:identifier/web-push-auth', '/devices/identifier/:identifier/web-push-auth'], 'user'),
  ...each(['PUT', 'POST'], ['/api/devices/identifier/:identifier/clear-token', '/devices/identifier/:identifier/clear-token'], 'user'),
  ...each(['POST'], ['/api/devices/:identifier/retrieve-keys', '/devices/:identifier/retrieve-keys'], 'user'),
  ...each(['POST', 'DELETE'], ['/api/devices/:identifier/deactivate', '/devices/:identifier/deactivate'], 'user'),
  ...each(['POST'], ['/api/devices/update-trust', '/devices/update-trust'], 'user'),
  ...each(['POST'], ['/api/devices/untrust', '/devices/untrust'], 'user'),

  // --- auth requests (login with device) ---
  ...each(['POST'], ['/api/auth-requests', '/auth-requests'], 'public'),
  ...each(['GET'], ['/api/auth-requests/:id/response', '/auth-requests/:id/response'], 'public'),
  ...each(['GET'], ['/api/auth-requests', '/auth-requests'], 'user'),
  ...each(['GET'], ['/api/auth-requests/pending', '/auth-requests/pending'], 'user'),
  ...each(['POST'], ['/api/auth-requests/admin-request', '/auth-requests/admin-request'], 'user'),
  ...each(['GET', 'PUT'], ['/api/auth-requests/:id', '/auth-requests/:id'], 'user'),

  // --- sync, folders, ciphers ---
  ['GET', '/api/sync', 'user'],
  ...each(['GET', 'POST'], ['/api/folders'], 'user'),
  ['POST', '/api/folders/delete', 'user'],
  ...each(['GET', 'PUT', 'POST', 'DELETE'], ['/api/folders/:id'], 'user'),
  ['POST', '/api/folders/:id/delete', 'user'],
  ['GET', '/api/ciphers', 'user'],
  ...each(['POST'], ['/api/ciphers', '/api/ciphers/create', '/api/ciphers/admin'], 'user'),
  ...each(['DELETE'], ['/api/ciphers', '/api/ciphers/admin'], 'user'),
  ['GET', '/api/ciphers/organization-details', 'user'],
  ...each(['PUT', 'POST'], ['/api/ciphers/share'], 'user'),
  ['POST', '/api/ciphers/bulk-collections', 'user'],
  ['POST', '/api/ciphers/import-organization', 'user'],
  ['POST', '/api/ciphers/import', 'user'],
  ...each(['POST', 'PUT'], ['/api/ciphers/delete', '/api/ciphers/delete-admin'], 'user'),
  ['POST', '/api/ciphers/delete-permanent', 'user'],
  ...each(['POST', 'PUT'], ['/api/ciphers/restore', '/api/ciphers/restore-admin'], 'user'),
  ...each(['POST', 'PUT'], ['/api/ciphers/archive', '/api/ciphers/unarchive', '/api/ciphers/move'], 'user'),
  ...each(['GET', 'PUT', 'POST', 'DELETE'], ['/api/ciphers/:id', '/api/ciphers/:id/admin'], 'user'),
  ['GET', '/api/ciphers/:id/details', 'user'],
  ...each(['PUT'], ['/api/ciphers/:id/delete', '/api/ciphers/:id/delete-admin'], 'user'),
  ...each(['DELETE', 'POST'], ['/api/ciphers/:id/delete', '/api/ciphers/:id/delete-admin'], 'user'),
  ...each(['PUT'], ['/api/ciphers/:id/restore', '/api/ciphers/:id/restore-admin'], 'user'),
  ...each(['PUT', 'POST'], [
    '/api/ciphers/:id/share',
    '/api/ciphers/:id/collections',
    '/api/ciphers/:id/collections_v2',
    '/api/ciphers/:id/collections-admin',
    '/api/ciphers/:id/archive',
    '/api/ciphers/:id/unarchive',
    '/api/ciphers/:id/partial',
  ], 'user'),

  // --- attachments ---
  ...each(['POST'], ['/api/ciphers/:id/attachment/v2', '/api/ciphers/:id/attachment', '/api/ciphers/:id/attachment-admin'], 'user'),
  ...each(['GET', 'POST', 'PUT', 'DELETE'], ['/api/ciphers/:id/attachment/:attachmentId'], 'user'),
  ...each(['POST', 'PUT'], ['/api/ciphers/:id/attachment/:attachmentId/metadata'], 'user'),
  ['DELETE', '/api/ciphers/:id/attachment/:attachmentId/admin', 'user'],
  ...each(['POST'], ['/api/ciphers/:id/attachment/:attachmentId/delete', '/api/ciphers/:id/attachment/:attachmentId/delete-admin'], 'user'),
  // Direct upload/download URLs handed out to clients carry their own token.
  ...each(['POST', 'PUT'], ['/api/ciphers/:id/attachment/:attachmentId?token=:token'], 'public'),
  ['GET', '/api/attachments/:id/:attachmentId?token=:token', 'public'],

  // --- sends ---
  ...each(['GET', 'POST'], ['/api/sends'], 'user'),
  ['POST', '/api/sends/file/v2', 'user'],
  ['POST', '/api/sends/delete', 'user'],
  ...each(['GET', 'PUT', 'DELETE'], ['/api/sends/:id'], 'user'),
  ...each(['PUT', 'POST'], ['/api/sends/:id/remove-password', '/api/sends/:id/remove-auth'], 'user'),
  ...each(['GET', 'POST', 'PUT'], ['/api/sends/:id/file/:fileId'], 'user'),
  ...each(['POST', 'PUT'], ['/api/sends/:id/file/:fileId?token=:token'], 'public'),
  ['POST', '/api/sends/access', 'public'],
  ['POST', '/api/sends/access/:accessId', 'public'],
  ['POST', '/api/sends/access/file/:fileId', 'public'],
  ['POST', '/api/sends/:id/access/file/:fileId', 'public'],
  ['GET', '/api/sends/:id/:fileId?t=:token', 'public'],

  // --- organizations ---
  ['POST', '/api/organizations', 'user'],
  ['GET', '/api/organizations/invitations', 'user'],
  ['GET', '/api/collections', 'user'],
  ...each(['GET', 'PUT', 'POST', 'DELETE'], ['/api/organizations/:orgId'], 'user'),
  ...each(['POST'], ['/api/organizations/:orgId/delete', '/api/organizations/:orgId/leave'], 'user'),
  ...each(['GET'], ['/api/organizations/:orgId/keys', '/api/organizations/:orgId/public-key'], 'user'),
  ['POST', '/api/organizations/:orgId/keys', 'user'],
  ['GET', '/api/organizations/:orgId/export', 'user'],
  ...each(['GET'], [
    '/api/organizations/:orgId/policies',
    '/api/organizations/:orgId/policies/token',
    '/api/organizations/:orgId/policies/0',
    '/api/organizations/:orgId/policies/master-password',
    '/api/organizations/:orgId/billing/metadata',
    '/api/organizations/:orgId/billing/vnext/warnings',
    '/api/organizations/:orgId/billing/vnext/self-host/metadata',
  ], 'user'),
  ...each(['GET', 'DELETE'], ['/api/organizations/:orgId/users'], 'user'),
  ['GET', '/api/organizations/:orgId/users/mini-details', 'user'],
  ...each(['POST'], [
    '/api/organizations/:orgId/users/invite',
    '/api/organizations/:orgId/users/confirm',
    '/api/organizations/:orgId/users/public-keys',
  ], 'user'),
  ...each(['PUT'], ['/api/organizations/:orgId/users/revoke', '/api/organizations/:orgId/users/restore'], 'user'),
  ...each(['GET', 'PUT', 'POST', 'DELETE'], ['/api/organizations/:orgId/users/:memberId'], 'user'),
  ...each(['POST'], [
    '/api/organizations/:orgId/users/:memberId/delete',
    '/api/organizations/:orgId/users/:memberId/accept',
    '/api/organizations/:orgId/users/:memberId/reinvite',
    '/api/organizations/:orgId/users/:memberId/confirm',
  ], 'user'),
  ...each(['PUT'], [
    '/api/organizations/:orgId/users/:memberId/revoke',
    '/api/organizations/:orgId/users/:memberId/restore',
    '/api/organizations/:orgId/users/:memberId/restore/vnext',
  ], 'user'),
  ...each(['GET', 'POST', 'DELETE'], ['/api/organizations/:orgId/collections'], 'user'),
  ['GET', '/api/organizations/:orgId/collections/details', 'user'],
  ['POST', '/api/organizations/:orgId/collections/bulk-access', 'user'],
  ...each(['PUT', 'POST', 'DELETE'], ['/api/organizations/:orgId/collections/:collectionId'], 'user'),
  ['POST', '/api/organizations/:orgId/collections/:collectionId/delete', 'user'],
  ...each(['GET'], ['/api/organizations/:orgId/collections/:collectionId/details', '/api/organizations/:orgId/collections/:collectionId/users'], 'user'),

  // --- admin ---
  ['GET', '/api/admin/users', 'admin'],
  ...each(['PUT', 'POST'], ['/api/admin/users/:id/status'], 'admin'),
  ['DELETE', '/api/admin/users/:id', 'admin'],
  ...each(['GET', 'POST', 'DELETE'], ['/api/admin/invites'], 'admin'),
  ['DELETE', '/api/admin/invites/:code', 'admin'],
  ...each(['GET', 'DELETE'], ['/api/admin/logs'], 'admin'),
  ...each(['GET', 'PUT', 'POST'], ['/api/admin/logs/settings'], 'admin'),

  // --- backup ---
  ['POST', '/api/admin/backup/export', 'admin'],
  ['POST', '/api/admin/backup/import', 'admin'],
  ['POST', '/api/admin/backup/blob', 'admin'],
  ...each(['GET', 'PUT'], ['/api/admin/backup/settings'], 'admin'),
  ...each(['GET', 'POST'], ['/api/admin/backup/settings/repair'], 'admin'),
  ['POST', '/api/admin/backup/run', 'admin'],
  ['GET', '/api/admin/backup/remote', 'admin'],
  ...each(['POST'], ['/api/admin/backup/remote/download', '/api/admin/backup/remote/integrity', '/api/admin/backup/remote/restore'], 'admin'),
  ['DELETE', '/api/admin/backup/remote/file', 'admin'],
];
