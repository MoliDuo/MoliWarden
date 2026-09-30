import type { Context } from 'hono';
import { id } from './body';
import { badRequest, notFound } from './errors';

// A path parameter of a route registered under several paths, where Hono
// cannot type it.
export function pathParam(c: Context, name: string): string {
  const value = c.req.param(name)?.trim();
  if (!value) throw notFound();
  return value;
}

// A resource id in the path; anything else names no resource.
export function idParam(c: Context, name = 'id'): string {
  const parsed = id.safeParse(pathParam(c, name));
  if (!parsed.success) throw notFound();
  return parsed.data;
}

// A required id in the query string.
export function idQuery(c: Context, name: string): string {
  const parsed = id.safeParse(c.req.query(name)?.trim() ?? '');
  if (!parsed.success) throw badRequest(`${name} must be an id.`);
  return parsed.data;
}
