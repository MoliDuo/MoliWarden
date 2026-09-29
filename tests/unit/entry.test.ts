import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ConfigError, readConfig, secretProblem } from '../../src/main/config';
import { canonicalRequest } from '../../src/main/node';

test('the original path Vercel passes as __mwpath is restored, other parameters kept', () => {
  const request = canonicalRequest(new Request('http://vault.example/_moliwarden?__mwpath=%2Fapi%2Fsends%2Fa%2Bb&token=x%2By&t=1'));
  const url = new URL(request.url);
  assert.equal(url.pathname, '/api/sends/a+b');
  assert.equal(url.search, '?token=x%2By&t=1');
});

test('trailing slashes are dropped and the forwarded scheme applies', () => {
  const request = canonicalRequest(new Request('http://vault.example/api/sync/', { headers: { 'X-Forwarded-Proto': 'https' } }));
  assert.equal(request.url, 'https://vault.example/api/sync');
  assert.equal(canonicalRequest(new Request('http://vault.example/')).url, 'http://vault.example/');
});

test('the request body survives', async () => {
  const request = canonicalRequest(new Request('http://vault.example/api/ciphers/', { method: 'POST', body: '{"a":1}' }));
  assert.equal(await request.text(), '{"a":1}');
});

test('only a missing database is fatal', () => {
  assert.throws(() => readConfig({}), (error) => error instanceof ConfigError && /DATABASE_URL/.test(error.message));
  const config = readConfig({ POSTGRES_URL: 'postgres://db', JWT_SECRET: ' short ' });
  assert.equal(config.databaseUrl, 'postgres://db');
  assert.equal(config.jwtSecretProblem, 'too_short');
  assert.deepEqual(secretProblem(config), { name: 'JWT_SECRET', reason: 'too_short' });
  const unsealed = readConfig({ DATABASE_URL: 'postgres://db', JWT_SECRET: 'x'.repeat(32) });
  assert.equal(unsealed.jwtSecretProblem, null);
  assert.deepEqual(secretProblem(unsealed), { name: 'ENCRYPTION_KEY', reason: 'missing' });
  assert.equal(secretProblem(readConfig({ DATABASE_URL: 'postgres://db', JWT_SECRET: 'x'.repeat(32), ENCRYPTION_KEY: 'y'.repeat(32) })), null);
});

test('flags and numbers are parsed', () => {
  const config = readConfig({ DATABASE_URL: 'postgres://db', SHOW_PASSWORD_HINT: '1', DATABASE_POOL_MAX: '3' });
  assert.equal(config.showPasswordHint, true);
  assert.equal(config.databasePoolMax, 3);
  assert.equal(readConfig({ DATABASE_URL: 'postgres://db' }).databasePoolMax, 5);
  assert.throws(() => readConfig({ DATABASE_URL: 'postgres://db', DATABASE_POOL_MAX: 'many' }), /DATABASE_POOL_MAX/);
});
