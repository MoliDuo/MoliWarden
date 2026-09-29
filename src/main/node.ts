import type { IncomingMessage, ServerResponse } from 'node:http';
import { handleAppRequest } from '../app';
import { createEnv } from '../platform/env';
import { toWebRequest, writeWebResponse } from '../platform/node-http';
import type { Env } from '../types';
import { errorResponse } from '../utils/response';

// The one way to run the server: the Vercel function, the local dev server
// and the test suites all build a handler here from a set of environment
// variables. Configuration is read on the first request, so a deployment
// with missing settings still answers with an error that names them.

export interface NodeHandler {
  fetch(request: Request): Promise<Response>;
  handler(req: IncomingMessage, res: ServerResponse): Promise<void>;
  dispose(): Promise<void>;
}

export function createNodeHandler(source: Record<string, string | undefined> = process.env): NodeHandler {
  let runtime: ReturnType<typeof createEnv> | null = null;

  function resolveEnv(): Env | Response {
    if (runtime) return runtime.env;
    try {
      runtime = createEnv(source);
      return runtime.env;
    } catch (error) {
      const message = `Server configuration error: ${error instanceof Error ? error.message : String(error)}`;
      console.error(message);
      return errorResponse(message, 500);
    }
  }

  async function fetch(request: Request): Promise<Response> {
    const env = resolveEnv();
    if (env instanceof Response) return env;
    return handleAppRequest(request, env);
  }

  async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      await writeWebResponse(res, await fetch(toWebRequest(req)));
    } catch (error) {
      console.error('Unhandled request error:', error);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Internal server error' }));
      } else {
        res.destroy(error as Error);
      }
    }
  }

  return {
    fetch,
    handler,
    async dispose() {
      const current = runtime;
      runtime = null;
      await current?.dispose();
    },
  };
}
