import type { Context } from 'hono';
import { z } from 'zod';
import { normalizeKeys } from '../platform/camel-case';
import { isEncString } from '../platform/enc-string';
import { badRequest, type ValidationErrors } from './errors';

// Request bodies are read through a zod schema, after their keys are
// normalized to camelCase; every schema is written in camelCase only.

function validationErrors(error: z.ZodError): ValidationErrors {
  const errors: ValidationErrors = {};
  for (const issue of error.issues) {
    const path = issue.path.map(String).join('.') || 'body';
    (errors[path] ??= []).push(issue.message);
  }
  return errors;
}

export function parseInput<S extends z.ZodType>(schema: S, input: unknown): z.output<S> {
  const result = schema.safeParse(normalizeKeys(input));
  if (result.success) return result.data;
  const errors = validationErrors(result.error);
  const [path, [first]] = Object.entries(errors)[0];
  throw badRequest(`${path}: ${first}`, errors);
}

export async function readJson<S extends z.ZodType>(c: Context, schema: S): Promise<z.output<S>> {
  const text = await c.req.text();
  let input: unknown;
  try {
    input = text.trim() ? JSON.parse(text) : {};
  } catch {
    throw badRequest('The request body is not valid JSON.');
  }
  return parseInput(schema, input);
}

// Reads a form-encoded body (the OAuth token endpoint) the same way.
export async function readForm<S extends z.ZodType>(c: Context, schema: S): Promise<z.output<S>> {
  const text = await c.req.text();
  return parseInput(schema, Object.fromEntries(new URLSearchParams(text)));
}

// For routes some clients post as a form and others as JSON.
export function readBody<S extends z.ZodType>(c: Context, schema: S): Promise<z.output<S>> {
  const form = (c.req.header('Content-Type') ?? '').includes('application/x-www-form-urlencoded');
  return form ? readForm(c, schema) : readJson(c, schema);
}

// Shared field types.
export const id = z.string().trim().toLowerCase().uuid('Must be an id.');
export const optionalText = z.string().nullish().transform((value) => value ?? null);
export const encString = z.string().trim().refine(isEncString, 'Must be an encrypted string.');
// Text a client may send as a string, a number or not at all; missing is ''.
export const text = z.preprocess((value) => (value == null ? '' : String(value)), z.string());
