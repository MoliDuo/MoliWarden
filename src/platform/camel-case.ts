// Official clients do not agree on key casing: older ones send PascalCase,
// the iOS app `OrganizationID`. Everything the server reads is normalized
// to camelCase first.

// `Name` -> `name`, `organizationID` -> `organizationId`. Keys that are not
// identifiers (ids used as map keys, for example) are left alone.
function normalizeKey(key: string): string {
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key)) return key;
  const camel = key[0].toLowerCase() + key.slice(1);
  return camel.endsWith('ID') ? `${camel.slice(0, -2)}Id` : camel;
}

export function normalizeKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeKeys);
  if (value === null || typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  const entries = Object.entries(value);
  // A key already in camelCase wins over another spelling of it.
  for (const [key, child] of entries) {
    const normalized = normalizeKey(key);
    if (normalized !== key && Object.hasOwn(value, normalized)) continue;
    out[normalized] = normalizeKeys(child);
  }
  return out;
}
