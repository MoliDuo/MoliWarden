import { JWTPayload } from '../types';

const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

// Base64 URL decode
function base64UrlDecode(str: string): Uint8Array<ArrayBuffer> {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getHmacKey(secret: string): Promise<CryptoKey> {
  const cacheKey = secret;
  let cached = hmacKeyCache.get(cacheKey);
  if (cached) return cached;

  const encoder = new TextEncoder();
  cached = crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  hmacKeyCache.set(cacheKey, cached);
  return cached;
}

// Verify JWT
export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: JWTPayload & { typ?: string } = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (payload.typ !== 'access') return null;

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;

    return payload;
  } catch {
    return null;
  }
}
