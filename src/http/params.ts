import type { Context } from 'hono';
import { notFound } from './errors';

// A path parameter of a route registered under several paths, where Hono
// cannot type it.
export function pathParam(c: Context, name: string): string {
  const value = c.req.param(name)?.trim();
  if (!value) throw notFound();
  return value;
}
