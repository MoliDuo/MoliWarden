import { Hono, type Context } from 'hono';
import { authenticate, callerOf, requireAdmin, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { badRequest, HttpError, payloadTooLarge } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { MAX_ARCHIVE_BYTES } from './archive';
import {
  attachmentFileBody,
  exportBody,
  remoteFileBody,
  remoteRestoreBody,
  repairBody,
  runBody,
  settingsBody,
  type ImportForm,
} from './schemas';
import {
  attachmentFile,
  deleteRemote,
  downloadRemote,
  exportArchive,
  importArchive,
  inspectRemote,
  listRemote,
  repairSettings,
  repairState,
  restoreRemote,
  runBackup,
  settingsJson,
  updateSettings,
} from './service';

const MULTIPART_OVERHEAD_BYTES = 256 * 1024;
const TOO_LARGE = `Backup file too large. Maximum size is ${MAX_ARCHIVE_BYTES / 1024 / 1024}MB`;

function zipDownload(bytes: Uint8Array<ArrayBuffer>, fileName: string): Response {
  return new Response(bytes, {
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${fileName.replace(/[\\/\r\n"]/g, '_')}"`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// The archive an admin uploads, as a multipart form.
async function readImportForm(c: Context): Promise<ImportForm> {
  const notMultipart = () => badRequest('Content-Type must be multipart/form-data');
  if (!(c.req.header('Content-Type') ?? '').includes('multipart/form-data')) throw notMultipart();
  if (Number(c.req.header('Content-Length')) > MAX_ARCHIVE_BYTES + MULTIPART_OVERHEAD_BYTES) throw payloadTooLarge(TOO_LARGE);
  const form = await c.req.formData().catch(() => {
    throw notMultipart();
  });
  const file = form.get('file');
  if (!(file instanceof File)) throw badRequest('Backup file is required');
  if (file.size > MAX_ARCHIVE_BYTES) throw payloadTooLarge(TOO_LARGE);
  const field = (name: string) => String(form.get(name) ?? '').trim();
  return {
    bytes: new Uint8Array(await file.arrayBuffer()),
    fileName: file.name,
    replaceExisting: field('replaceExisting') === '1',
    allowChecksumMismatch: field('allowChecksumMismatch') === '1',
    masterPasswordHash: field('masterPasswordHash') || null,
  };
}

// Instance backups, for admins.
export function backupRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const admin = [authenticate(deps), requireAdmin] as const;
  const base = '/api/admin/backup';

  app.post(`${base}/export`, ...admin, async (c) => {
    const archive = await exportArchive(deps, callerOf(c), await readJson(c, exportBody));
    return zipDownload(archive.bytes, archive.fileName);
  });
  // POST only: the body carries the master password hash, which in a URL
  // would end up in logs and browser history.
  app.get(`${base}/blob`, ...admin, () => {
    throw new HttpError(405, 'Use POST with a JSON body for this endpoint. Credentials must not be sent in the URL.');
  });
  app.post(`${base}/blob`, authenticate(deps, 'bulk'), requireAdmin, async (c) => {
    const object = await attachmentFile(deps, callerOf(c), await readJson(c, attachmentFileBody));
    return new Response(object.body, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(object.size),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  });
  app.post(`${base}/import`, ...admin, async (c) => c.json(await importArchive(deps, callerOf(c), await readImportForm(c))));

  app.get(`${base}/settings`, ...admin, async (c) => c.json(await settingsJson(deps)));
  app.put(`${base}/settings`, ...admin, async (c) => c.json(await updateSettings(deps, callerOf(c), await readJson(c, settingsBody))));
  app.get(`${base}/settings/repair`, ...admin, async (c) => c.json(await repairState(deps)));
  app.post(`${base}/settings/repair`, ...admin, async (c) =>
    c.json(await repairSettings(deps, callerOf(c), await readJson(c, repairBody))),
  );

  app.post(`${base}/run`, ...admin, async (c) => c.json(await runBackup(deps, callerOf(c), await readJson(c, runBody))));
  app.get(`${base}/remote`, ...admin, async (c) =>
    c.json(await listRemote(deps, c.req.query('destinationId') || null, c.req.query('path') ?? '')),
  );
  app.post(`${base}/remote/download`, ...admin, async (c) => {
    const file = await downloadRemote(deps, callerOf(c), await readJson(c, remoteFileBody));
    return zipDownload(file.bytes, file.fileName);
  });
  app.post(`${base}/remote/integrity`, ...admin, async (c) =>
    c.json(await inspectRemote(deps, callerOf(c), await readJson(c, remoteFileBody))),
  );
  app.delete(`${base}/remote/file`, ...admin, async (c) =>
    c.json(await deleteRemote(deps, callerOf(c), await readJson(c, remoteFileBody))),
  );
  app.post(`${base}/remote/restore`, ...admin, async (c) =>
    c.json(await restoreRemote(deps, callerOf(c), await readJson(c, remoteRestoreBody))),
  );

  return app;
}
