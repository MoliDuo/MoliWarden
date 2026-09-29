import type { Context } from 'hono';
import { z } from 'zod';
import { badRequest, type ValidationErrors } from './errors';

// Request bodies are read through a zod schema. Official clients do not
// agree on key casing (the iOS app sends `OrganizationID`, older clients
// PascalCase), so keys are normalized to camelCase first and every schema
// is written in camelCase only.

// `Name` -> `name`, `organizationID` -> `organizationId`. Keys that are not
// identifiers (ids used as map keys, for example) are left alone.
function normalizeKey(key: string): string {
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key)) return key;
  const camel = key[0].toLowerCase() + key.slice(1);
  return camel.endsWith('ID') ? `${camel.slice(0, -2)}Id` : camel;
}

export function normalizeKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeKeys);
  if (value === null || typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  const entries = Object.entries(value);
  // A key already in camelCase wins over another spelling of it.
  for (const [key, child] of entries) {
    const normalized = normalizeKey(key);
    if (normalized !== key && Object.hasOwn(value, normalized)) continue;
    out[normalized] = normalizeKeys(child);
  }
  return out;
}

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
export const encString = z.string().min(1, 'Required.');
// Text a client may send as a string, a number or not at all; missing is ''.
export const text = z.preprocess((value) => (value == null ? '' : String(value)), z.string());
