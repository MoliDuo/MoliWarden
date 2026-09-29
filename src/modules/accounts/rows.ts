import type { Row } from '../../platform/db/schema';
import type { User } from '../../types';

export function toUser(row: Row<'users'>): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    masterPasswordHint: row.master_password_hint,
    masterPasswordHash: row.master_password_hash,
    key: row.key,
    privateKey: row.private_key,
    publicKey: row.public_key,
    kdfType: row.kdf_type,
    kdfIterations: row.kdf_iterations,
    kdfMemory: row.kdf_memory ?? undefined,
    kdfParallelism: row.kdf_parallelism ?? undefined,
    securityStamp: row.security_stamp,
    role: row.role,
    status: row.status,
    verifyDevices: row.verify_devices,
    recoveryCode: row.recovery_code,
    apiKey: row.api_key,
    keyId: row.key_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
