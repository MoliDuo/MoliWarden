import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sslFor } from '../../src/platform/db';

test('database connections check the server certificate unless told otherwise', () => {
  const verified = { rejectUnauthorized: true };
  assert.deepEqual(sslFor('postgresql://u:p@ep-x.neon.tech/db?sslmode=require'), verified);
  assert.deepEqual(sslFor('postgresql://u:p@db.example.com/db'), verified);
  assert.deepEqual(sslFor('postgresql://u:p@db.example.com/db?sslmode=verify-full'), verified);
  assert.deepEqual(sslFor('postgresql://u:p@localhost/db?sslmode=require'), verified);
  assert.deepEqual(sslFor('postgresql://u:p@db.example.com/db?sslmode=no-verify'), { rejectUnauthorized: false });
  assert.equal(sslFor('postgresql://u:p@db.example.com/db?sslmode=disable'), false);
  assert.equal(sslFor('postgres://mw:mw@localhost:55432/mw'), false);
  assert.equal(sslFor('postgres://mw:mw@127.0.0.1:55432/mw'), false);
});
