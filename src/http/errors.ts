import type { ContentfulStatusCode } from 'hono/utils/http-status';

// Errors a request can end with. Services throw them; the app's error
// handler turns them into responses, so no handler builds an error body.

export type ValidationErrors = Record<string, string[]>;

// Bitwarden's ErrorResponseModel. Official clients show `message`, or the
// first entry of `validationErrors` when there is one.
export interface ErrorBody {
  message: string;
  validationErrors: ValidationErrors | null;
  object: 'error';
}

export class HttpError extends Error {
  constructor(
    readonly status: ContentfulStatusCode,
    message: string,
    readonly validationErrors: ValidationErrors | null = null,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
    this.name = 'HttpError';
  }

  get body(): ErrorBody {
    return { message: this.message, validationErrors: this.validationErrors, object: 'error' };
  }
}

export const badRequest = (message: string, validationErrors?: ValidationErrors) =>
  new HttpError(400, message, validationErrors ?? null);
export const unauthorized = (message = 'Unauthorized') => new HttpError(401, message);
export const forbidden = (message = 'Forbidden') => new HttpError(403, message);
export const notFound = (message = 'Not found') => new HttpError(404, message);
export const conflict = (message: string) => new HttpError(409, message);
export const payloadTooLarge = (message = 'Request body too large') => new HttpError(413, message);
export const notImplemented = (message = 'This feature is not supported by this server.') =>
  new HttpError(501, message);
export const tooManyRequests = (retryAfterSeconds: number) =>
  new HttpError(429, `Rate limit exceeded. Try again in ${retryAfterSeconds} seconds.`, null, {
    'Retry-After': String(retryAfterSeconds),
  });

// A deployment setting is missing or unusable; the message names it.
export const misconfigured = (message: string) => new HttpError(500, `Server configuration error: ${message}`);

// Errors of the OAuth token endpoint (RFC 6749 section 5.2). Official
// clients show ErrorModel.Message; `extra` carries fields such as the
// two-factor providers a login still needs.
export class IdentityError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status: ContentfulStatusCode = 400,
    readonly extra: Record<string, unknown> = {},
    readonly headers: Record<string, string> = {},
  ) {
    super(description);
    this.name = 'IdentityError';
  }

  get body(): Record<string, unknown> {
    return {
      error: this.error,
      error_description: this.description,
      ...this.extra,
      ErrorModel: { Message: this.description, Object: 'error' },
    };
  }
}

export const invalidGrant = (description = 'Username or password is incorrect. Try again') =>
  new IdentityError('invalid_grant', description);
