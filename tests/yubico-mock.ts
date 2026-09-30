// A local stand-in for the Yubico OTP validation service (wsapi 2.0 verify).
//
// Request:  GET /wsapi/2.0/verify?id=<clientId>&nonce=<nonce>&otp=<otp>&h=<sig>
// Response: text/plain, one `key=value` per line, signed with `h`: base64
// HMAC-SHA1 (key = base64-decoded API secret) over the other fields sorted by
// name and joined as `k=v&k=v`.
import { createHmac, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const MODHEX = 'cbdefghijklnrtuv';

export function randomModhex(length: number): string {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += MODHEX[bytes[i] & 0x0f];
  return out;
}

// A YubiKey public id (the first 12 characters of every OTP it types).
export function yubiKeyPublicId(): string {
  return randomModhex(12);
}

// A 44-character OTP: 12-character public id + 32-character encrypted part.
export function yubiKeyOtp(publicId: string): string {
  return publicId + randomModhex(32);
}

function sign(secretKeyBase64: string, fields: Record<string, string>): string {
  const canonical = Object.keys(fields)
    .filter((key) => key !== 'h')
    .sort()
    .map((key) => `${key}=${fields[key]}`)
    .join('&');
  return createHmac('sha1', Buffer.from(secretKeyBase64, 'base64')).update(canonical).digest('base64');
}

export interface YubicoRequest {
  id: string;
  otp: string;
  nonce: string;
  signatureValid: boolean;
}

export interface YubicoMock {
  url: string;
  clientId: string;
  secretKey: string;
  requests: YubicoRequest[];
  // Force the status answered for one OTP (e.g. 'BAD_OTP', 'REPLAYED_OTP').
  statusFor: Map<string, string>;
  // Answer this OTP with status OK but a signature made with the wrong key.
  forgeSignatureFor: Set<string>;
  close(): Promise<void>;
}

export async function startYubicoMock(): Promise<YubicoMock> {
  const clientId = '424242';
  const secretKey = randomBytes(20).toString('base64');
  const seen = new Set<string>();
  const requests: YubicoRequest[] = [];
  const statusFor = new Map<string, string>();
  const forgeSignatureFor = new Set<string>();

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method !== 'GET' || url.pathname !== '/wsapi/2.0/verify') {
      res.statusCode = 404;
      res.end();
      return;
    }
    const params: Record<string, string> = {};
    for (const [key, value] of url.searchParams) params[key] = value;
    const otp = params.otp ?? '';
    const nonce = params.nonce ?? '';
    const signatureValid = !!params.h && sign(secretKey, params) === params.h;
    requests.push({ id: params.id ?? '', otp, nonce, signatureValid });

    let status: string;
    if (params.id !== clientId) status = 'NO_SUCH_CLIENT';
    else if (!signatureValid) status = 'BAD_SIGNATURE';
    else if (statusFor.has(otp)) status = statusFor.get(otp)!;
    else if (seen.has(otp)) status = 'REPLAYED_OTP';
    else status = 'OK';
    if (status === 'OK') seen.add(otp);

    const fields: Record<string, string> = {
      t: new Date().toISOString().replace(/\.\d+Z$/, 'Z0000'),
      otp,
      nonce,
      sl: '100',
      status,
    };
    const h = sign(forgeSignatureFor.has(otp) ? randomBytes(20).toString('base64') : secretKey, fields);
    const body = [`h=${h}`, ...Object.entries(fields).map(([key, value]) => `${key}=${value}`)].join('\r\n') + '\r\n';
    res.setHeader('Content-Type', 'text/plain');
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/wsapi/2.0/verify`,
    clientId,
    secretKey,
    requests,
    statusFor,
    forgeSignatureFor,
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
