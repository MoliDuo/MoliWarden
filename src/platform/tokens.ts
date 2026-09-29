import { createHmac } from 'node:crypto';
import { base64url, constantTimeEqual, deriveKey, fromBase64url } from './crypto';

// Every token the server signs is an HS256 JWT with a `typ` claim naming its
// purpose. Each purpose has its own key derived from JWT_SECRET, so a token
// issued for one purpose never verifies as another. Access tokens use
// JWT_SECRET itself, which no other purpose does, so tokens issued before
// the key derivation existed stayed valid.

export type TokenType =
  | 'access'
  | 'attachment-upload'
  | 'attachment-download'
  | 'send-access'
  | 'send-upload'
  | 'send-download'
  | 'user-verification'
  | 'passkey-challenge'
  | 'webauthn-challenge';

export interface TokenClaims {
  typ: TokenType;
  iat: number;
  exp: number;
}

export interface TokenService {
  sign<T extends object>(typ: TokenType, claims: T, ttlSeconds: number): string;
  verify<T extends object>(typ: TokenType, token: string | null | undefined): (T & TokenClaims) | null;
}

const HEADER = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
// Tolerated difference between the clocks of the instances that sign and verify.
const CLOCK_SKEW_SECONDS = 60;

export function createTokenService(jwtSecret: string, now: () => number = Date.now): TokenService {
  const keys = new Map<TokenType, Buffer>();
  const keyFor = (typ: TokenType): Buffer => {
    let key = keys.get(typ);
    if (!key) {
      key = typ === 'access' ? Buffer.from(jwtSecret, 'utf8') : deriveKey(jwtSecret, `token.${typ}`);
      keys.set(typ, key);
    }
    return key;
  };
  const signature = (typ: TokenType, data: string) => createHmac('sha256', keyFor(typ)).update(data).digest();
  const seconds = () => Math.floor(now() / 1000);

  return {
    sign(typ, claims, ttlSeconds) {
      const iat = seconds();
      const payload = base64url(JSON.stringify({ ...claims, typ, iat, exp: iat + ttlSeconds }));
      const data = `${HEADER}.${payload}`;
      return `${data}.${base64url(signature(typ, data))}`;
    },

    verify<T extends object>(typ: TokenType, token: string | null | undefined) {
      const parts = String(token ?? '').split('.');
      if (parts.length !== 3) return null;
      const [header, payload, sig] = parts;
      const given = fromBase64url(sig);
      if (!given || !constantTimeEqual(given, signature(typ, `${header}.${payload}`))) return null;
      try {
        const { alg } = JSON.parse(fromBase64url(header)?.toString('utf8') ?? '');
        if (alg !== 'HS256') return null;
        const claims = JSON.parse(fromBase64url(payload)?.toString('utf8') ?? '');
        const current = seconds();
        if (!claims || claims.typ !== typ) return null;
        if (!Number.isInteger(claims.exp) || claims.exp <= current) return null;
        if (!Number.isInteger(claims.iat) || claims.iat > current + CLOCK_SKEW_SECONDS) return null;
        return claims as T & TokenClaims;
      } catch {
        return null;
      }
    },
  };
}
