import { Hono } from 'hono';
import { authenticate, callerOf, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { idParam } from '../../http/params';
import type { Deps } from '../../main/deps';
import { folderBody, idsBody } from './schemas';
import { folderById, foldersJson, removeFolder, removeFolders, saveFolder } from './service';

export function folderRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);

  app.get('/api/folders', authed, async (c) => c.json(await foldersJson(deps, c.var.actor.user)));
  app.post('/api/folders', authed, async (c) => c.json(await saveFolder(deps, callerOf(c), null, await readJson(c, folderBody))));
  app.post('/api/folders/delete', authed, async (c) => {
    await removeFolders(deps, callerOf(c), (await readJson(c, idsBody)).ids);
    return c.body(null, 204);
  });

  app.get('/api/folders/:id', authed, async (c) => c.json(await folderById(deps, c.var.actor.user, idParam(c))));
  app.on(['PUT', 'POST'], '/api/folders/:id', authed, async (c) =>
    c.json(await saveFolder(deps, callerOf(c), idParam(c), await readJson(c, folderBody))),
  );
  app.on('DELETE', '/api/folders/:id', authed, async (c) => {
    await removeFolder(deps, callerOf(c), idParam(c));
    return c.body(null, 204);
  });
  app.post('/api/folders/:id/delete', authed, async (c) => {
    await removeFolder(deps, callerOf(c), idParam(c));
    return c.body(null, 204);
  });

  return app;
}
