
// JSON response helper
export function jsonResponse(data: any, status: number = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

// Error response helper
export function errorResponse(message: string, status: number = 400): Response {
  return jsonResponse(
    {
      error: message,
      error_description: message,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    status
  );
}

export function unsupportedResponse(message: string = 'This feature is not supported by this server.'): Response {
  return errorResponse(message, 501);
}

// Identity endpoint error response (for /identity/connect/token)
export function identityErrorResponse(
  message: string,
  error: string = 'invalid_grant',
  status: number = 400,
  headers: Record<string, string> = {}
): Response {
  return jsonResponse(
    {
      error: error,
      error_description: message,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    status,
    { 'Cache-Control': 'no-store', Pragma: 'no-cache', ...headers }
  );
}

// HTML response helper
export function htmlResponse(html: string, status: number = 200): Response {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
    },
  });
}
