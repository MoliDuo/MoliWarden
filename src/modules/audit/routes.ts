import { Hono } from 'hono';
import { authenticate, callerOf, requireAdmin, type AuthedEnv } from '../../http/authenticate';
import { parseInput, readJson } from '../../http/body';
import type { Deps } from '../../main/deps';
import { auditLogQuery, auditRetentionBody } from './schemas';
import { auditLogs, auditRetention, clearAuditLog, setAuditRetention } from './service';

// The audit log, for admins.
export function auditRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const admin = [authenticate(deps), requireAdmin] as const;
  const settings = (retention: { retentionDays: number | null; maxEntries: number | null }) => ({
    object: 'auditLogSettings',
    ...retention,
  });

  app.get('/api/admin/logs', ...admin, async (c) => c.json(await auditLogs(deps, parseInput(auditLogQuery, c.req.query()))));
  app.delete('/api/admin/logs', ...admin, async (c) =>
    c.json({ object: 'auditLogClear', deleted: await clearAuditLog(deps, callerOf(c)) }),
  );
  app.get('/api/admin/logs/settings', ...admin, async (c) => c.json(settings(await auditRetention(deps))));
  app.on(['PUT', 'POST'], '/api/admin/logs/settings', ...admin, async (c) =>
    c.json(settings(await setAuditRetention(deps, callerOf(c), await readJson(c, auditRetentionBody)))),
  );

  return app;
}
