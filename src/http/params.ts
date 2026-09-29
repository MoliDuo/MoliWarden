import type { Context } from 'hono';
import { id } from './body';
import { notFound } from './errors';

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
