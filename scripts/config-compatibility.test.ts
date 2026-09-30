import assert from 'node:assert/strict';
import test from 'node:test';

import { clientConfig } from '../src/modules/meta/client-config';

test('config enables the official Bitwarden desktop settings dialog', () => {
  const body = clientConfig('https://vault.example.test');

  assert.equal(body.featureStates['desktop-ui-settings-dialog'], true);
  assert.equal(body.environment.vault, 'https://vault.example.test');
  assert.equal(body.object, 'config');
});
