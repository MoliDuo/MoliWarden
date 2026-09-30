// Fill-assist rules tell official clients how to fill unusual login forms.
// This server publishes an empty rule set in the format the clients expect,
// and answers Android's digital asset link check with "not linked".

const FORMS_FILE = 'forms.v1.json';
const FORMS_SCHEMA_FILE = 'forms.v1.schema.json';

const forms = { schemaVersion: '1.0.0', hosts: {} };

const formsSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Bitwarden Fill Assist Forms v1',
  type: 'object',
  required: ['schemaVersion', 'hosts'],
  properties: {
    schemaVersion: { type: 'string' },
    hosts: { type: 'object' },
  },
  additionalProperties: true,
};

export const fillAssistManifest = {
  buildId: 'moliwarden-empty-fill-assist-v1',
  timestamp: '2026-07-06T00:00:00.000Z',
  gitSha: 'moliwarden',
  maps: {
    forms: {
      v1: {
        filename: FORMS_FILE,
        // SHA-256 of JSON.stringify(forms).
        cid: 'sha256:189fa7c9bcf8951e65c18b5d9feacf74a5223c75e01667c4235388cbc67091fe',
        schema: FORMS_SCHEMA_FILE,
        deprecated: false,
      },
    },
  },
};

export const fillAssistFiles: Record<string, object> = {
  [FORMS_FILE]: forms,
  [FORMS_SCHEMA_FILE]: formsSchema,
};

export const assetLinkCheck = {
  linked: false,
  maxAge: '86400s',
  debugString: 'No matching digital asset link policy is configured for this server.',
};
