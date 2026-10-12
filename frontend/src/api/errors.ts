/* Errors from the PhishHawk API. Every API error is JSON
   {"error": "<code>", "detail": "<human text>"}; `detail` is safe to show as text. */

export const NETWORK_MESSAGE = 'The PhishHawk server could not be reached. Check the connection and try again.';
export const UNREADABLE_MESSAGE = 'The PhishHawk server sent an answer this page could not read. Try again.';
export const TIMEOUT_MESSAGE = 'The analysis is taking longer than expected. It is still running on the server.';

/** The exact `detail` of the 403 the server sends for a missing or stale CSRF token. */
export const CSRF_DETAIL = 'the form is out of date: reload the page and try again';

const FALLBACK: Record<number, [string, string]> = {
  400: ['bad_request', 'The request was not accepted.'],
  401: ['unauthorized', 'Your session has ended. Sign in again.'],
  403: ['forbidden', 'You are not allowed to do that.'],
  404: ['not_found', 'Not found.'],
  409: ['conflict', 'This message is on hold. An admin must release it first.'],
  410: ['gone', 'The message and its reports were deleted after the retention period.'],
  413: ['too_large', 'The file is over the upload limit.'],
  415: ['unsupported', 'That is not an .eml or .msg message.'],
  422: ['invalid', 'A value is not valid.'],
  429: ['throttled', 'Too many tries. Wait and try again.'],
};

export class ApiError extends Error {
  /** HTTP status; 0 when the server could not be reached or the answer was unreadable. */
  readonly status: number;
  /** The server's error code ("not_found", "conflict", ...), or "network", "invalid_response", "timeout". */
  readonly code: string;
  /** Text that is safe to show to the user. */
  readonly detail: string;
  /** Seconds from the Retry-After header (429 only). */
  readonly retryAfter: number | null;

  constructor(status: number, code: string, detail: string, retryAfter: number | null = null) {
    super(detail);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.retryAfter = retryAfter;
  }

  get isCsrf() {
    return this.status === 403 && this.detail === CSRF_DETAIL;
  }
}

export async function errorFrom(res: Response): Promise<ApiError> {
  const [fallbackCode, fallbackDetail] = FALLBACK[res.status] ?? ['error', 'The server could not do that. Try again.'];
  const retry = res.headers.get('Retry-After');
  const retryAfter = retry && /^\d+$/.test(retry) ? Number(retry) : null;
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object') {
      const { error, detail } = body as { error?: unknown; detail?: unknown };
      return new ApiError(
        res.status,
        typeof error === 'string' ? error : fallbackCode,
        typeof detail === 'string' && detail ? detail : fallbackDetail,
        retryAfter,
      );
    }
  } catch {
    // not JSON (a proxy's HTML error page, for example): use the fallback text
  }
  return new ApiError(res.status, fallbackCode, fallbackDetail, retryAfter);
}

/** True for a request the page cancelled itself (the user left the screen): show nothing. */
export function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}
