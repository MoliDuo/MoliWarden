import { Env, JWTPayload, User } from '../types';
import { verifyJWT } from '../utils/jwt';
import { StorageService } from './storage';

// Server-side iterations for second-layer hashing.
// The client already does heavy PBKDF2 (600k iterations).
// This second layer only needs to be non-trivial, not expensive.
const SERVER_HASH_ITERATIONS = 100_000;
const SERVER_HASH_PREFIX = '$s$';

export interface VerifiedAccessContext {
  payload: JWTPayload;
  user: User;
}

export class AuthService {
  private storage: StorageService;
  constructor(private env: Env) {
    this.storage = new StorageService(env.DB);
  }

  private getCachedUser(userId: string): Promise<User | null> {
    return this.storage.getUserById(userId);
  }

  private getFreshUser(userId: string): Promise<User | null> {
    return this.storage.getUserById(userId);
  }

  private getCachedDevice(userId: string, deviceId: string) {
    return this.storage.getDevice(userId, deviceId);
  }

  private getFreshDevice(userId: string, deviceId: string) {
    return this.storage.getDevice(userId, deviceId);
  }

  // Second-layer hash: PBKDF2-SHA256(clientHash, email-salt, iterations).
  // Ensures database contents alone cannot be used to authenticate (pass-the-hash defense).
  // Result is prefixed to distinguish server-hashed credentials from invalid legacy rows.
  async hashPasswordServer(clientHash: string, email: string): Promise<string> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(clientHash),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    const salt = new TextEncoder().encode(email.toLowerCase().trim());
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: SERVER_HASH_ITERATIONS },
      keyMaterial,
      256
    );
    const bytes = new Uint8Array(bits);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return SERVER_HASH_PREFIX + btoa(binary);
  }

  // Verify password: new rows use server-side hashing; legacy rows store the raw client hash.
  async verifyPassword(inputHash: string, storedHash: string, email: string): Promise<boolean> {
    if (!storedHash.startsWith(SERVER_HASH_PREFIX)) {
      return this.constantTimeEquals(inputHash, storedHash);
    }
    const serverHash = await this.hashPasswordServer(inputHash, email);
    return this.constantTimeEquals(serverHash, storedHash);
  }

  private constantTimeEquals(a: string, b: string): boolean {
    const encA = new TextEncoder().encode(a);
    const encB = new TextEncoder().encode(b);
    if (encA.length !== encB.length) return false;
    let diff = 0;
    for (let i = 0; i < encA.length; i++) {
      diff |= encA[i] ^ encB[i];
    }
    return diff === 0;
  }

  async verifyAccessTokenWithUser(authHeader: string | null): Promise<VerifiedAccessContext | null> {
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return null;
    }

    const payload = await verifyJWT(parts[1], this.env.JWT_SECRET);
    if (!payload) return null;

    let user = await this.getCachedUser(payload.sub);
    if (!user || user.status !== 'active' || payload.sstamp !== user.securityStamp) {
      user = await this.getFreshUser(payload.sub);
    }
    if (!user) return null;
    if (user.status !== 'active') return null;

    if (payload.sstamp !== user.securityStamp) {
      return null;
    }

    if (payload.did) {
      let device = await this.getCachedDevice(user.id, payload.did);
      if (!device || !payload.dstamp || payload.dstamp !== device.sessionStamp) {
        device = await this.getFreshDevice(user.id, payload.did);
      }
      if (!device) return null;
      if (!payload.dstamp || payload.dstamp !== device.sessionStamp) return null;
    }

    return { payload, user };
  }
}
