/* The only module that talks to the PhishHawk API.

   - Relative URLs on the same origin; the session cookie goes with them.
   - The CSRF token lives in this module's memory only, and goes out as the
     X-CSRF-Token header on every POST, PATCH and DELETE except the login.
   - A 403 whose detail is the server's CSRF text refreshes the session once
     and retries the request once. Every other 403 is a permission refusal.
   - A 401 clears the token and calls the handler the app registers (which
     clears its state and shows the login screen).
   - In development (vite dev server, so also the AI Studio preview) requests
     go to a mock backend with the same contract; `vite build` leaves the mock
     out of the bundle. Set VITE_PHISHHAWK_MOCK=off to use a real server in dev. */

import { ApiError, CSRF_DETAIL, NETWORK_MESSAGE, UNREADABLE_MESSAGE, errorFrom, isAbort } from './errors';
import type {
  Analysis,
  AnalysisSummary,
  AuditEntry,
  Batch,
  BatchCreated,
  Campaign,
  CampaignSummary,
  Health,
  NewToken,
  Role,
  Session,
  Settings,
  SettingsPatch,
  Submission,
  Token,
  User,
  Verdict,
} from './types';

type Transport = (url: string, init: RequestInit) => Promise<Response>;

let transportPromise: Promise<Transport> | null = null;
function transport(): Promise<Transport> {
  if (!transportPromise) {
    transportPromise =
      import.meta.env.DEV && import.meta.env.VITE_PHISHHAWK_MOCK !== 'off'
        ? import('../mocks/mockTransport').then((m) => m.mockFetch)
        : Promise.resolve((url: string, init: RequestInit) => fetch(url, init));
  }
  return transportPromise;
}

let csrf: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

/** The app registers what to do when the session has ended (clear state, show login). */
export function onUnauthorized(handler: () => void) {
  unauthorizedHandler = handler;
}

/** Forget the CSRF token (on sign out, or when the app clears its state). */
export function forgetSession() {
  csrf = null;
}

type Options = {
  json?: unknown;
  form?: FormData;
  signal?: AbortSignal;
  /** internal: the one CSRF retry has been used */
  retried?: boolean;
};

async function request<T>(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, options: Options = {}): Promise<T> {
  const { json, form, signal, retried = false } = options;
  const isLogin = method === 'POST' && url === '/api/v1/session';
  const changes = method !== 'GET' && !isLogin;
  const headers: Record<string, string> = { Accept: 'application/json' };
  let body: BodyInit | undefined;
  if (json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(json);
  } else if (form) {
    body = form; // the browser sets the multipart boundary
  }
  if (changes) {
    if (!csrf) await getSession(signal);
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  let res: Response;
  try {
    res = await (await transport())(url, { method, headers, body, signal, credentials: 'same-origin', cache: 'no-store' });
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new ApiError(0, 'network', NETWORK_MESSAGE);
  }

  if (!res.ok) {
    const error = await errorFrom(res);
    if (res.status === 401 && !isLogin) {
      csrf = null;
      unauthorizedHandler?.();
    } else if (res.status === 403 && changes && !retried && error.detail === CSRF_DETAIL) {
      csrf = null;
      await getSession(signal);
      return request<T>(method, url, { json, form, signal, retried: true });
    }
    throw error;
  }
  if (res.status === 204) return undefined as T;
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(0, 'invalid_response', UNREADABLE_MESSAGE);
  }
}

const enc = encodeURIComponent;

/* ---- session ---- */

/** Who is signed in; also refreshes the CSRF token. Throws ApiError 401 when nobody is. */
export async function getSession(signal?: AbortSignal): Promise<Session> {
  const session = await request<Session>('GET', '/api/v1/session', { signal });
  csrf = session.csrf;
  return session;
}

/** Signs in, then reads the session for the user and role. 401: wrong details; 429: see error.retryAfter. */
export async function login(username: string, password: string): Promise<Session> {
  const { csrf: token } = await request<{ csrf: string }>('POST', '/api/v1/session', { json: { username, password } });
  csrf = token;
  return getSession();
}

export async function logout(): Promise<void> {
  try {
    await request<void>('DELETE', '/api/v1/session');
  } finally {
    csrf = null;
  }
}

/* ---- submissions and analyses ---- */

/** One message is a Submission; several (several files, an .mbox or a .zip) are a batch: see isBatch(). */
export function submit(input: { files?: File[]; raw?: string; offline: boolean }, signal?: AbortSignal): Promise<Submission | BatchCreated> {
  const form = new FormData();
  if (input.files?.length) input.files.forEach((file) => form.append('files', file));
  else form.append('raw', input.raw ?? '');
  form.append('offline', input.offline ? 'true' : 'false');
  return request<Submission | BatchCreated>('POST', '/api/v1/submissions', { form, signal });
}

export function isBatch(created: Submission | BatchCreated): created is BatchCreated {
  return 'submission_ids' in created;
}

export function getSubmission(id: number, signal?: AbortSignal): Promise<Submission> {
  return request<Submission>('GET', `/api/v1/submissions/${id}`, { signal });
}

export type AnalysisQuery = {
  q?: string;
  verdict?: Verdict | '';
  source?: 'upload' | 'paste' | 'batch' | '';
  /** a user's ID */
  user?: number | null;
  /** days, YYYY-MM-DD (UTC), both included */
  since?: string;
  until?: string;
  offset?: number;
};

/** 50 per page, newest first; an empty page means there are no more. */
export function listAnalyses(query: AnalysisQuery, signal?: AbortSignal) {
  const params = new URLSearchParams();
  if (query.q) params.set('q', query.q);
  if (query.verdict) params.set('verdict', query.verdict);
  if (query.source) params.set('source', query.source);
  if (query.user != null) params.set('user', String(query.user));
  if (query.since) params.set('since', query.since);
  if (query.until) params.set('until', query.until);
  if (query.offset) params.set('offset', String(query.offset));
  const qs = params.toString();
  return request<AnalysisSummary[]>('GET', `/api/v1/analyses${qs ? `?${qs}` : ''}`, { signal });
}

export function getAnalysis(id: number, signal?: AbortSignal): Promise<Analysis> {
  return request<Analysis>('GET', `/api/v1/analyses/${id}`, { signal });
}

export function reanalyze(id: number): Promise<Submission> {
  return request<Submission>('POST', `/api/v1/analyses/${id}/reanalyze`);
}

/** "tier1" removes the message and its reports and keeps the verdict; "all" (admin) removes everything. */
export function deleteMessage(messageId: number, scope: 'tier1' | 'all'): Promise<{ deleted: 'tier1' | 'all' }> {
  return request('DELETE', `/api/v1/messages/${messageId}?scope=${scope}`);
}

/* ---- batches and campaigns ---- */

export function getBatch(id: number, signal?: AbortSignal): Promise<Batch> {
  return request<Batch>('GET', `/api/v1/batches/${id}`, { signal });
}

/** Largest first. A shared subject or display name is always null here: the campaign itself shows it. */
export function listCampaigns(signal?: AbortSignal): Promise<CampaignSummary[]> {
  return request<CampaignSummary[]>('GET', '/api/v1/campaigns', { signal });
}

export function getCampaign(id: number, signal?: AbortSignal): Promise<Campaign> {
  return request<Campaign>('GET', `/api/v1/campaigns/${id}`, { signal });
}

export function holdMessage(messageId: number): Promise<{ hold: boolean }> {
  return request('POST', `/api/v1/messages/${messageId}/hold`);
}

export function releaseMessage(messageId: number): Promise<{ hold: boolean }> {
  return request('DELETE', `/api/v1/messages/${messageId}/hold`);
}

/* ---- file URLs (for <a href> and the report <iframe src>; never built from report values) ---- */

/** `name` must be a `files[].name` from the analysis, never an attachment's file name. */
export function fileUrl(analysisId: number, name: string, download = false): string {
  return `/api/v1/analyses/${analysisId}/files/${enc(name)}${download ? '?download=1' : ''}`;
}

/** `name` must be a `files[].name` from the batch. */
export function batchFileUrl(batchId: number, name: string, download = false): string {
  return `/api/v1/batches/${batchId}/files/${enc(name)}${download ? '?download=1' : ''}`;
}

export function rawMessageUrl(messageId: number): string {
  return `/api/v1/messages/${messageId}/raw`;
}

/* ---- admin ---- */

export function getSettings(signal?: AbortSignal): Promise<Settings> {
  return request<Settings>('GET', '/api/v1/settings', { signal });
}

export function patchSettings(patch: SettingsPatch): Promise<Settings> {
  return request<Settings>('PATCH', '/api/v1/settings', { json: patch });
}

export function listUsers(signal?: AbortSignal): Promise<User[]> {
  return request<User[]>('GET', '/api/v1/users', { signal });
}

export function createUser(user: { username: string; password: string; role: Role }): Promise<User> {
  return request<User>('POST', '/api/v1/users', { json: user });
}

export function updateUser(id: number, patch: { role?: Role; disabled?: boolean; password?: string }): Promise<User> {
  return request<User>('PATCH', `/api/v1/users/${id}`, { json: patch });
}

export function listTokens(signal?: AbortSignal): Promise<Token[]> {
  return request<Token[]>('GET', '/api/v1/tokens', { signal });
}

/** The returned token is shown once; do not keep it after the dialog closes. */
export function createToken(token: { name: string; scope: 'read' | 'submit'; user_id: number }): Promise<NewToken> {
  return request<NewToken>('POST', '/api/v1/tokens', { json: token });
}

export function revokeToken(id: number): Promise<{ revoked: boolean }> {
  return request('DELETE', `/api/v1/tokens/${id}`);
}

/* ---- audit and health ---- */

/** 100 per page, newest first. Analysts get their own entries. */
export function listAudit(offset = 0, signal?: AbortSignal): Promise<AuditEntry[]> {
  return request<AuditEntry[]>('GET', `/api/v1/audit${offset ? `?offset=${offset}` : ''}`, { signal });
}

export function getHealth(signal?: AbortSignal): Promise<Health> {
  return request<Health>('GET', '/healthz', { signal });
}
