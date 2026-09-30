import { Hono, type Context } from 'hono';
import { authenticate, authenticateUpload, callerOf, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { readUpload, uploadUrl } from '../../http/files';
import { idParam } from '../../http/params';
import { rateLimit } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { attachmentKey } from '../../platform/blob';
import { attachmentBody, metadataBody } from './schemas';
import {
  attachmentDownloadInfo,
  createAttachment,
  downloadAttachment,
  removeAttachment,
  updateAttachmentMetadata,
  uploadAttachment,
  uploadLimits,
} from './service';

const attachment = (...suffixes: string[]) => suffixes.map((suffix) => `/api/ciphers/:id/attachment/:attachmentId${suffix}`);
const cipherId = (c: Context) => idParam(c);
const attachmentId = (c: Context) => idParam(c, 'attachmentId');

export function attachmentRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);

  app.post('/api/ciphers/:id/attachment/v2', authed, async (c) => {
    const id = cipherId(c);
    const { attachment, cipherResponse } = await createAttachment(deps, callerOf(c), id, await readJson(c, attachmentBody));
    const path = `/api/ciphers/${id}/attachment/${attachment.id}`;
    return c.json({
      object: 'attachment-fileUpload',
      attachmentId: attachment.id,
      url: uploadUrl(c, deps.tokens, 'attachment-upload', c.var.actor, path, attachmentKey(id, attachment.id)),
      fileUploadType: 1,
      cipherResponse,
    });
  });

  const uploader = authenticateUpload(deps, 'attachment-upload', (c) => attachmentKey(cipherId(c), attachmentId(c)));
  app.on(['PUT', 'POST'], attachment(''), uploader, async (c) => {
    const read = (expectedSize: number | null) =>
      readUpload(c, { ...uploadLimits(deps), expectedSize, sizeMismatch: 'File size does not match.' });
    await uploadAttachment(deps, callerOf(c), cipherId(c), attachmentId(c), read);
    return c.body(null, 201);
  });
  app.get('/api/ciphers/:id/attachment/:attachmentId', authed, async (c) =>
    c.json(await attachmentDownloadInfo(deps, callerOf(c), new URL(c.req.url).origin, cipherId(c), attachmentId(c))),
  );
  app.on(['PUT', 'POST'], attachment('/metadata'), authed, async (c) =>
    c.json(await updateAttachmentMetadata(deps, callerOf(c), cipherId(c), attachmentId(c), await readJson(c, metadataBody))),
  );
  const remove = async (c: Context<AuthedEnv>) => c.json(await removeAttachment(deps, callerOf(c), cipherId(c), attachmentId(c)));
  app.on('DELETE', attachment('', '/admin'), authed, remove);
  app.on('POST', attachment('/delete', '/delete-admin'), authed, remove);

  app.get('/api/attachments/:id/:attachmentId', rateLimit(deps.limiter, 'public-read'), async (c) =>
    downloadAttachment(deps, cipherId(c), attachmentId(c), c.req.query('token') ?? null),
  );

  return app;
}
