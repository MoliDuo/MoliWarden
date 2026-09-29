// Small additions to the shared harness for black-box tests that make many
// unauthenticated calls. Public endpoints are rate limited per client IP, and
// the server trusts X-Forwarded-For as the client IP in tests.

let ipCounter = 0;

// A fresh documentation-range client IP per call.
export function nextIp(): string {
  ipCounter += 1;
  return `198.51.${Math.floor(ipCounter / 250) % 250}.${(ipCounter % 250) + 1}`;
}

// Error bodies differ between API and identity endpoints and will gain a
// `message` field in the rewrite; read them tolerantly.
export function errorText(body: any): string {
  return String(body?.message ?? body?.ErrorModel?.Message ?? body?.error_description ?? body?.error ?? '');
}

export function masterPasswordHash(email: string): string {
  return Buffer.from('hash-' + email).toString('base64');
}
