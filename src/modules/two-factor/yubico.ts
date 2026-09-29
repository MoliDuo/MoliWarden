import { createHmac, randomBytes } from 'node:crypto';
import { constantTimeEqual } from '../../platform/crypto';

// YubiKey OTPs, checked with Yubico's validation service. An OTP is the
// key's 12-character public id followed by an encrypted one-time part, all
// in modhex.

const MODHEX = /^[cbdefghijklnrtuv]+$/;
const PUBLIC_ID_LENGTH = 12;
const DEFAULT_VALIDATION_URL = 'https://api.yubico.com/wsapi/2.0/verify';
const API_KEY_URL = 'https://upgrade.yubico.com/getapikey/';

export interface YubicoCredentials {
  clientId: string;
  secretKey: string;
}

const normalize = (input: string) => input.replace(/\s+/g, '').toLowerCase();

export function isYubiKeyOtp(input: string): boolean {
  const otp = normalize(input);
  return otp.length >= 32 && otp.length <= 48 && MODHEX.test(otp);
}

// The public id of an OTP; a bare public id is returned as is.
export function yubiKeyPublicId(input: string): string | null {
  const value = normalize(input);
  if (value.length === PUBLIC_ID_LENGTH && MODHEX.test(value)) return value;
  return isYubiKeyOtp(value) ? value.slice(0, PUBLIC_ID_LENGTH) : null;
}

const sign = (secretKey: string, params: Record<string, string>) =>
  createHmac('sha1', Buffer.from(secretKey, 'base64'))
    .update(
      Object.keys(params)
        .sort()
        .map((key) => `${key}=${params[key]}`)
        .join('&'),
    )
    .digest('base64');

export function validationUrls(configured: string | undefined): string[] {
  const urls = (configured ?? '').split(',').map((url) => url.trim()).filter(Boolean);
  return urls.length ? urls : [DEFAULT_VALIDATION_URL];
}

// True when a Yubico server confirms the OTP is valid and unused. Replies
// are signed with the API secret and must echo the OTP and our nonce.
export async function verifyYubiKeyOtp(urls: string[], credentials: YubicoCredentials, input: string): Promise<boolean> {
  const otp = normalize(input);
  if (!isYubiKeyOtp(otp)) return false;
  const params = { id: credentials.clientId, nonce: randomBytes(16).toString('hex'), otp };
  const query = new URLSearchParams({ ...params, h: sign(credentials.secretKey, params) });
  for (const url of urls) {
    try {
      const response = await fetch(`${url}?${query}`, { signal: AbortSignal.timeout(5000) });
      if (!response.ok) continue;
      const reply: Record<string, string> = {};
      for (const line of (await response.text()).split(/\r?\n/)) {
        const at = line.indexOf('=');
        if (at > 0) reply[line.slice(0, at)] = line.slice(at + 1);
      }
      const { h, ...signed } = reply;
      if (reply.status !== 'OK' || reply.otp !== otp || reply.nonce !== params.nonce || !h) continue;
      if (constantTimeEqual(sign(credentials.secretKey, signed), h)) return true;
    } catch {
      // Try the next server.
    }
  }
  return false;
}

// Yubico hands out API credentials to anyone who proves they own a YubiKey,
// which lets the first user with a key set up validation for the server.
export async function requestYubicoCredentials(email: string, input: string): Promise<YubicoCredentials | null> {
  const otp = normalize(input);
  if (!isYubiKeyOtp(otp)) return null;
  try {
    const response = await fetch(API_KEY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email: email.trim().toLowerCase(), otp, terms_conditions: 'consented' }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return null;
    const html = await response.text();
    const clientId = /Client ID:<\/th>\s*<td><b>(\d+)<\/b>/i.exec(html)?.[1];
    const secretKey = /Secret key:<\/th>\s*<td><code>([^<]+)<\/code>/i.exec(html)?.[1];
    return clientId && secretKey ? { clientId, secretKey } : null;
  } catch {
    return null;
  }
}
