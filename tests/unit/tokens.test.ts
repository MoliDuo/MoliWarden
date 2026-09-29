import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { constantTimeEqual, createSecretBox, SecretBoxError, type Sealed } from '../../src/platform/crypto';
import { createTokenService } from '../../src/platform/tokens';

const SECRET = 'unit-test-secret-unit-test-secret-0123456789';

function forge(header: object, claims: object, key: string | Buffer): string {
  const data = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
  return `${data}.${createHmac('sha256', key).update(data).digest('base64url')}`;
}

test('a token verifies only for the purpose it was signed for', () => {
  const tokens = createTokenService(SECRET);
  const token = tokens.sign('attachment-download', { cipherId: 'c', attachmentId: 'a' }, 60);
  assert.deepEqual(
    { ...tokens.verify<{ cipherId: string }>('attachment-download', token), iat: 0, exp: 0 },
    { cipherId: 'c', attachmentId: 'a', typ: 'attachment-download', iat: 0, exp: 0 },
  );
  assert.equal(tokens.verify('attachment-upload', token), null);
  assert.equal(tokens.verify('access', token), null);
});

test('a purpose key is not the JWT secret, but the access key is', () => {
  const tokens = createTokenService(SECRET);
  const now = Math.floor(Date.now() / 1000);
  const claims = { typ: 'send-access', iat: now, exp: now + 60 };
  assert.equal(tokens.verify('send-access', forge({ alg: 'HS256', typ: 'JWT' }, claims, SECRET)), null);
  const access = forge({ alg: 'HS256', typ: 'JWT' }, { ...claims, typ: 'access' }, SECRET);
  assert.ok(tokens.verify('access', access));
});

test('tokens without a typ, with another alg, expired or from the future are refused', () => {
  const tokens = createTokenService(SECRET);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  assert.equal(tokens.verify('access', forge(header, { iat: now, exp: now + 60 }, SECRET)), null);
  assert.equal(tokens.verify('access', forge({ alg: 'none' }, { typ: 'access', iat: now, exp: now + 60 }, SECRET)), null);
  assert.equal(tokens.verify('access', forge({ alg: 'HS512' }, { typ: 'access', iat: now, exp: now + 60 }, SECRET)), null);
  assert.equal(tokens.verify('access', forge(header, { typ: 'access', iat: now - 120, exp: now - 60 }, SECRET)), null);
  assert.equal(tokens.verify('access', forge(header, { typ: 'access', iat: now }, SECRET)), null);
  assert.equal(tokens.verify('access', forge(header, { typ: 'access', iat: now + 600, exp: now + 900 }, SECRET)), null);
  assert.equal(tokens.verify('access', `${forge(header, { typ: 'access', iat: now, exp: now + 60 }, SECRET)}x`), null);
  assert.equal(tokens.verify('access', 'not-a-token'), null);
  assert.equal(tokens.verify('access', null), null);
});

test('expiry follows the clock', () => {
  let clock = Date.now();
  const tokens = createTokenService(SECRET, () => clock);
  const token = tokens.sign('user-verification', {}, 60);
  assert.ok(tokens.verify('user-verification', token));
  clock += 61_000;
  assert.equal(tokens.verify('user-verification', token), null);
});

test('a different JWT secret invalidates every token', () => {
  const token = createTokenService(SECRET).sign('send-download', {}, 60);
  assert.equal(createTokenService(`${SECRET}-rotated`).verify('send-download', token), null);
});

test('sealed secrets open only with the same key and context', () => {
  const box = createSecretBox('encryption-key-encryption-key-0123456789');
  const sealed = box.seal('JBSWY3DPEHPK3PXP', 'totp:user-1');
  assert.match(sealed, /^mw1\.[\w-]+\.[\w-]+$/);
  assert.notEqual(box.seal('JBSWY3DPEHPK3PXP', 'totp:user-1'), sealed);
  assert.equal(box.open(sealed, 'totp:user-1'), 'JBSWY3DPEHPK3PXP');
  assert.throws(() => box.open(sealed, 'totp:user-2'), SecretBoxError);
  assert.throws(() => createSecretBox('another-key-another-key-another-key-0123').open(sealed, 'totp:user-1'), SecretBoxError);
  assert.throws(() => box.open(sealed.slice(0, -2) as Sealed, 'totp:user-1'), SecretBoxError);
  assert.throws(() => box.open('plaintext' as Sealed, 'totp:user-1'), SecretBoxError);
});

test('constant-time comparison', () => {
  assert.equal(constantTimeEqual('abc', 'abc'), true);
  assert.equal(constantTimeEqual('abc', 'abd'), false);
  assert.equal(constantTimeEqual('abc', 'abcd'), false);
  assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
});
