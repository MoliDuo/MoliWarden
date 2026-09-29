import { z } from 'zod';
import { integer } from '../../http/body';

// Admin actions that change accounts are confirmed with the admin's master
// password; auth/password checks it and says when it is missing.
const confirmed = { masterPasswordHash: z.string().nullish() };

export const confirmBody = z.object(confirmed);

export const inviteBody = z.object({
  ...confirmed,
  expiresInHours: integer
    .pipe(z.number().min(1).max(24 * 30))
    .nullish()
    .transform((value) => value ?? 24 * 7),
});

export const userStatusBody = z.object({
  ...confirmed,
  status: z.enum(['active', 'banned'], 'status must be active or banned'),
});
