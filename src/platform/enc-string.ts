// An EncString is how Bitwarden clients serialize encrypted data:
// "<type>.<part>|<part>...". The server stores these without reading them,
// but checks the shape so a broken client cannot save data it will not be
// able to read back.

// The number of parts each encryption type carries.
const PART_COUNTS: Record<string, number> = {
  0: 2, // AES-CBC-256: iv|data
  1: 3, // AES-CBC-128 + HMAC: iv|data|mac
  2: 3, // AES-CBC-256 + HMAC: iv|data|mac
  3: 1, // RSA-OAEP-SHA256: data
  4: 1, // RSA-OAEP-SHA1: data
  5: 2, // RSA-OAEP-SHA256 + HMAC: data|mac
  6: 2, // RSA-OAEP-SHA1 + HMAC: data|mac
  7: 1, // COSE Encrypt0: data
};

export function isEncString(value: string): boolean {
  const [type, body, ...rest] = value.split('.');
  if (rest.length || !body) return false;
  const parts = body.split('|');
  return parts.length === PART_COUNTS[type] && parts.every(Boolean);
}
