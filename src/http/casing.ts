// Official clients read a response's fields in camelCase or PascalCase,
// depending on their age; responses carry both.
export function withPascalCase(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key[0].toUpperCase() + key.slice(1)] = value;
    out[key] = value;
  }
  return out;
}
