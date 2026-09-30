import { z } from 'zod';
import { integer, isoDate } from '../../http/body';

const blankAsMissing = (value: unknown) => (value === '' ? undefined : value);
const optional = <S extends z.ZodType>(schema: S) => z.preprocess(blankAsMissing, schema.optional());

// The query string of the log view.
export const auditLogQuery = z.object({
  limit: optional(integer.pipe(z.number().min(1).max(200))).default(50),
  offset: optional(integer.pipe(z.number().min(0))).default(0),
  category: optional(z.enum(['auth', 'security', 'device', 'data', 'system'])),
  level: optional(z.enum(['info', 'warn', 'error', 'security'])),
  q: optional(z.string().trim().max(48)),
  from: optional(isoDate),
  to: optional(isoDate),
});
export type AuditLogQuery = z.output<typeof auditLogQuery>;

// Choices the web vault offers; 0 or null means no limit.
const RETENTION_DAYS = [7, 30, 90, 180, 365] as const;
const MAX_ENTRIES = [1_000, 5_000, 10_000, 50_000] as const;

const choice = (allowed: readonly number[]) =>
  integer
    .nullish()
    .transform((value) => value || null)
    .refine((value) => value === null || allowed.includes(value), `Must be one of ${allowed.join(', ')}.`);

export const auditRetentionBody = z
  .object({ retentionDays: choice(RETENTION_DAYS), maxEntries: choice(MAX_ENTRIES) })
  .refine((value) => !(value.retentionDays && value.maxEntries), 'Keep entries either for a time or up to a number, not both.');
