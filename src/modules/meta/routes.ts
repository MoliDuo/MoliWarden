import { Hono } from 'hono';
import { LIMITS } from '../../config/limits';
import { rateLimit } from '../../http/rate-limit';
import { secretProblem } from '../../main/config';
import type { Deps } from '../../main/deps';
import { getConfiguredWebAuthnAllowedOrigins } from '../../utils/origins';
import { countUsers } from '../accounts/repo';
import { clientConfig } from './client-config';
import { assetLinkCheck, fillAssistFiles, fillAssistManifest } from './fill-assist';

// What the web vault needs to know before anyone signs in.
export interface WebBootstrap {
  defaultKdfIterations: number;
  // A secret the operator still has to set.
  secretProblem: ReturnType<typeof secretProblem>;
  secretMinLength: number;
  registrationInviteRequired: boolean;
  webAuthnAllowedOrigins: string[];
  websiteIconsEnabled: boolean;
  passwordHintEnabled: boolean;
}

// Public descriptions of the server. These answer even when JWT_SECRET or
// ENCRYPTION_KEY is unusable, so the web vault can explain what to fix.
export function metaRoutes(deps: Deps): Hono {
  const app = new Hono();
  const read = rateLimit(deps.limiter, 'public-read');
  const noStore = { 'Cache-Control': 'no-store' };
  const cached = { 'Cache-Control': 'public, max-age=3600' };

  for (const path of ['/config', '/api/config']) {
    app.get(path, read, (c) => c.json(clientConfig(new URL(c.req.url).origin), 200, noStore));
  }

  for (const path of ['/web-bootstrap', '/api/web-bootstrap']) {
    app.get(path, read, async (c) => {
      const { config } = deps;
      const body: WebBootstrap = {
        defaultKdfIterations: LIMITS.auth.defaultKdfIterations,
        secretProblem: secretProblem(config),
        secretMinLength: LIMITS.auth.secretMinLength,
        registrationInviteRequired: (await countUsers(deps.db)) > 0,
        webAuthnAllowedOrigins: getConfiguredWebAuthnAllowedOrigins(config.webauthn.allowedOrigins),
        websiteIconsEnabled: config.iconSource !== 'off',
        passwordHintEnabled: config.showPasswordHint,
      };
      return c.json(body);
    });
  }

  app.get('/api/version', read, (c) => c.json(LIMITS.compatibility.bitwardenServerVersion));
  for (const path of ['/api/alive', '/api/now']) {
    app.get(path, read, (c) => c.json(new Date().toISOString(), 200, noStore));
  }

  app.get('/fill-assist/manifest.json', read, (c) => c.json(fillAssistManifest, 200, cached));
  app.get('/fill-assist/:file', read, (c) => {
    const file = fillAssistFiles[c.req.param('file')];
    return file ? c.json(file, 200, cached) : c.text('Not found', 404);
  });
  for (const path of ['/v1/assetlinks:check', '/api/v1/assetlinks:check']) {
    app.get(path, read, (c) => c.json(assetLinkCheck, 200, cached));
  }

  // Chrome DevTools probes this on every page load.
  app.get('/.well-known/appspecific/com.chrome.devtools.json', (c) => c.json({}, 200, noStore));

  return app;
}
