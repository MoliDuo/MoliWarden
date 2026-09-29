import { Hono, type Context } from 'hono';
import { authenticate, authenticateUpload, callerOf, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { readUpload, uploadUrl } from '../../http/files';
import { idParam, pathParam } from '../../http/params';
import { rateLimit, requireClientAddress } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { sendFileKey } from '../../platform/blob';
import { idsBody } from '../ciphers/schemas';
import {
  accessSend,
  accessSendFile,
  accessSendFileWithToken,
  accessSendWithToken,
  downloadSendFile,
} from './access';
import type { Send } from './model';
import { sendJson } from './responses';
import { accessBody, sendBody, sendUpdateBody } from './schemas';
import {
  createFileSend,
  createTextSend,
  deleteSend,
  deleteSendsById,
  removeSendPassword,
  requireFileSend,
  sendById,
  sendsJson,
  updateSend,
  uploadSendFile,
} from './service';

const origin = (c: Context) => new URL(c.req.url).origin;
const bearer = (c: Context) => c.req.header('Authorization')?.match(/^Bearer\s+(.+)$/i)?.[1].trim() ?? null;
const ok = (c: Context) => c.body(null, 200);

export function sendRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);
  const pub = rateLimit(deps.limiter, 'public');

  // Where the file of a new file Send goes.
  const fileUpload = (c: Context<AuthedEnv>, send: Send) => {
    const fileId = send.file!.id;
    return {
      fileUploadType: 1,
      object: 'send-fileUpload',
      url: uploadUrl(c, deps.tokens, 'send-upload', c.var.actor, `/api/sends/${send.id}/file/${fileId}`, sendFileKey(send.id, fileId)),
      sendResponse: sendJson(send),
    };
  };

  // Recipients.
  app.post('/api/sends/access/file/:fileId', pub, async (c) =>
    c.json(await accessSendFileWithToken(deps, origin(c), bearer(c), idParam(c, 'fileId'))),
  );
  app.post('/api/sends/access/:accessId', pub, async (c) => {
    const { password } = await readJson(c, accessBody);
    return c.json(await accessSend(deps, requireClientAddress(c.req.raw), pathParam(c, 'accessId'), password ?? null));
  });
  app.post('/api/sends/access', pub, async (c) => c.json(await accessSendWithToken(deps, bearer(c))));
  app.post('/api/sends/:id/access/file/:fileId', pub, async (c) => {
    const { password } = await readJson(c, accessBody);
    const address = requireClientAddress(c.req.raw);
    return c.json(await accessSendFile(deps, address, origin(c), pathParam(c, 'id'), idParam(c, 'fileId'), password ?? null));
  });

  // Their owner.
  app.get('/api/sends', authed, async (c) => c.json(await sendsJson(deps, callerOf(c))));
  app.post('/api/sends', authed, async (c) => c.json(await createTextSend(deps, callerOf(c), await readJson(c, sendBody))));
  app.post('/api/sends/file/v2', authed, async (c) =>
    c.json(fileUpload(c, await createFileSend(deps, callerOf(c), await readJson(c, sendBody)))),
  );
  app.post('/api/sends/delete', authed, async (c) => {
    await deleteSendsById(deps, callerOf(c), (await readJson(c, idsBody)).ids);
    return ok(c);
  });

  app.get('/api/sends/:id', authed, async (c) => c.json(await sendById(deps, callerOf(c), idParam(c))));
  app.put('/api/sends/:id', authed, async (c) =>
    c.json(await updateSend(deps, callerOf(c), idParam(c), await readJson(c, sendUpdateBody))),
  );
  app.delete('/api/sends/:id', authed, async (c) => {
    await deleteSend(deps, callerOf(c), idParam(c));
    return ok(c);
  });
  app.on(['PUT', 'POST'], '/api/sends/:id/remove-password', authed, async (c) =>
    c.json(await removeSendPassword(deps, callerOf(c), idParam(c), 'send.password.remove')),
  );
  app.on(['PUT', 'POST'], '/api/sends/:id/remove-auth', authed, async (c) =>
    c.json(await removeSendPassword(deps, callerOf(c), idParam(c), 'send.auth.remove')),
  );

  // The file of a file Send: where to upload it, the upload, the download.
  app.get('/api/sends/:id/file/:fileId', authed, async (c) =>
    c.json(fileUpload(c, await requireFileSend(deps, callerOf(c), idParam(c), idParam(c, 'fileId')))),
  );
  const uploader = authenticateUpload(deps, 'send-upload', (c) => sendFileKey(idParam(c), idParam(c, 'fileId')));
  app.on(['PUT', 'POST'], '/api/sends/:id/file/:fileId', uploader, async (c) => {
    const read = (expectedSize: number) =>
      readUpload(c, {
        maxBytes: deps.config.maxUploadBytes,
        tooLarge: 'Send storage limit exceeded with this file',
        expectedSize,
        sizeMismatch: 'Send file size does not match.',
      });
    await uploadSendFile(deps, callerOf(c), idParam(c), idParam(c, 'fileId'), read);
    return c.body(null, 201);
  });
  app.get('/api/sends/:id/:fileId', rateLimit(deps.limiter, 'public-read'), async (c) =>
    downloadSendFile(deps, idParam(c), idParam(c, 'fileId'), c.req.query('t') ?? null),
  );

  return app;
}
