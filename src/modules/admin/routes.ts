import { Hono, type Context } from 'hono';
import { authenticate, callerOf, requireAdmin, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { idParam, pathParam } from '../../http/params';
import type { Deps } from '../../main/deps';
import { confirmBody, inviteBody, userStatusBody } from './schemas';
import { changeUserStatus, createInvite, invitesJson, removeInvite, removeInvites, removeUser, usersJson } from './service';

const origin = (c: Context) => new URL(c.req.url).origin;

// Accounts and invites, for admins.
export function adminRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const admin = [authenticate(deps), requireAdmin] as const;

  app.get('/api/admin/users', ...admin, async (c) => c.json(await usersJson(deps)));
  app.on(['PUT', 'POST'], '/api/admin/users/:id/status', ...admin, async (c) =>
    c.json(await changeUserStatus(deps, callerOf(c), idParam(c), await readJson(c, userStatusBody))),
  );
  app.delete('/api/admin/users/:id', ...admin, async (c) => {
    await removeUser(deps, callerOf(c), idParam(c), (await readJson(c, confirmBody)).masterPasswordHash);
    return c.body(null, 204);
  });

  app.get('/api/admin/invites', ...admin, async (c) =>
    c.json(await invitesJson(deps, origin(c), c.req.query('includeInactive') === 'true')),
  );
  app.post('/api/admin/invites', ...admin, async (c) =>
    c.json(await createInvite(deps, callerOf(c), origin(c), await readJson(c, inviteBody)), 201),
  );
  // ?scope=invalid removes only the used and expired invites.
  app.delete('/api/admin/invites', ...admin, async (c) => {
    const all = c.req.query('scope') !== 'invalid';
    return c.json(await removeInvites(deps, callerOf(c), all, (await readJson(c, confirmBody)).masterPasswordHash));
  });
  app.delete('/api/admin/invites/:code', ...admin, async (c) => {
    await removeInvite(deps, callerOf(c), pathParam(c, 'code'), (await readJson(c, confirmBody)).masterPasswordHash);
    return c.body(null, 204);
  });

  return app;
}
