import { z } from 'zod';

export const createBody = z.object({
  // The admin-approval request defaults to the signed-in user's.
  email: z.string().trim().toLowerCase().optional(),
  publicKey: z.string().trim().min(1, 'Required.').max(8192, 'Must be 8192 characters or fewer.'),
  deviceIdentifier: z.string().trim().max(128, 'Must be 128 characters or fewer.').optional(),
  accessCode: z.string().trim().min(1, 'Required.').max(25, 'Must be 25 characters or fewer.'),
  type: z.coerce.number().int().default(0),
});
export type CreateInput = z.output<typeof createBody>;

export const answerBody = z.object({
  requestApproved: z.boolean().nullish().transform((value) => value ?? false),
  key: z.string().trim().nullish().transform((value) => value || null),
  deviceIdentifier: z.string().trim().max(128).nullish(),
});
export type AnswerInput = z.output<typeof answerBody>;
