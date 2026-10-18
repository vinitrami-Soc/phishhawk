/* The only module that talks to the PhishHawk API.

   - Relative URLs on the same origin; the session cookie goes with them.
   - The CSRF token lives in this module's memory only, and goes out as the
     X-CSRF-Token header on every POST, PATCH and DELETE except those of
     someone not signed in yet: the login, setup, sign-up and joining.
   - A 403 whose detail is the server's CSRF text refreshes the session once
     and retries the request once. Every other 403 is a permission refusal.
   - A 401 clears the token and calls the handler the app registers (which
     clears its state and shows the login screen).
   - In development (vite dev server, so also the AI Studio preview) requests
     go to a mock backend with the same contract; `vite build` leaves the mock
     out of the bundle. Set VITE_PHISHHAWK_MOCK=off to use a real server in dev. */

import { ApiError, CSRF_DETAIL, NETWORK_MESSAGE, UNREADABLE_MESSAGE, errorFrom, isAbort } from './errors';
import type {
  AccountFields,
  Analysis,
  AnalysisSummary,
  AuditEntry,
  Batch,
  BatchCreated,
  Campaign,
  CampaignSummary,
  Feedback,
  Health,
  Invitation,
  Invite,
  Mailbox,
  MailboxPatch,
  Me,
  NewInvite,
  NewFeedback,
  NewMailbox,
  NewToken,
  Opinion,
  ProfilePatch,
  Role,
  ServerSettings,
  Session,
  Settings,
  SettingsPatch,
  SetupFields,
  SignupFields,
  Submission,
  Token,
  User,
  Verdict,
  VerdictAnswer,
  VerdictFeedback,
  VerdictSummary,
  WorkspaceSummary,
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

/** Requests of someone not signed in yet: no CSRF token, and a 401 is theirs, not an ended session. */
function signingIn(method: string, url: string): boolean {
  return method === 'POST' && (url === '/api/v1/session' || url === '/api/v1/setup' || url === '/api/v1/signup' || url.startsWith('/api/v1/join/'));
}

async function request<T>(method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, options: Options = {}): Promise<T> {
  const { json, form, signal, retried = false } = options;
  const isLogin = signingIn(method, url);
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

/* ---- getting in: setup, sign-up, invitations; each new account is signed in, as a login is ---- */

async function enter(url: string, fields: unknown): Promise<Session> {
  const { csrf: token } = await request<{ csrf: string }>('POST', url, { json: fields });
  csrf = token;
  return getSession();
}

/** open: no one has an account on this server yet, so it waits for its owner. */
export function getSetupState(signal?: AbortSignal): Promise<{ open: boolean }> {
  return request('GET', '/api/v1/setup', { signal });
}

/** The owner's account and organization. 403: wrong code (429 after a few); 404: set up already. */
export function setUp(fields: SetupFields): Promise<Session> {
  return enter('/api/v1/setup', fields);
}

/** open: anyone may create an account now. While it is false, show no "Create an account". */
export function getSignupState(signal?: AbortSignal): Promise<{ open: boolean }> {
  return request('GET', '/api/v1/signup', { signal });
}

/** A workspace of their own, or a new organization with them as its admin. 409: username taken; 429: see retryAfter. */
export function signUp(fields: SignupFields): Promise<Session> {
  return enter('/api/v1/signup', fields);
}

/** The organization and role of an invitation; 404 when it was used, withdrawn or is over 7 days old. */
export function getInvitation(token: string, signal?: AbortSignal): Promise<Invitation> {
  return request<Invitation>('GET', `/api/v1/join/${enc(token)}`, { signal });
}

export function joinInvitation(token: string, fields: AccountFields): Promise<Session> {
  return enter(`/api/v1/join/${enc(token)}`, fields);
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
  source?: 'upload' | 'paste' | 'batch' | 'mailbox' | '';
  /** a user's ID */
  user?: number | null;
  /** days, YYYY-MM-DD (UTC), both included */
  since?: string;
  until?: string;
  offset?: number;
  /** only the analyses someone answered missed or false_alarm on */
  disputed?: boolean;
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
  if (query.disputed) params.set('disputed', 'true');
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

/** What they submitted stays the workspace's. 422 for yourself, 403 for the server's owner. */
export function deleteUser(id: number): Promise<void> {
  return request<void>('DELETE', `/api/v1/users/${id}`);
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

/** The invitations of the caller's organization that can still be used (admins). */
export function listInvites(signal?: AbortSignal): Promise<Invite[]> {
  return request<Invite[]>('GET', '/api/v1/invites', { signal });
}

/** The token is shown once: build the link from it, and do not keep it after the dialog closes. */
export function createInvite(invite: { role: Role; note: string }): Promise<NewInvite> {
  return request<NewInvite>('POST', '/api/v1/invites', { json: invite });
}

export function revokeInvite(id: number): Promise<void> {
  return request<void>('DELETE', `/api/v1/invites/${id}`);
}

/** The link that opens an invitation in this frontend. */
export function inviteLink(token: string): string {
  return `${window.location.origin}/app/join/${enc(token)}`;
}

/* ---- the profile, and the owner's settings for the whole server ---- */

export function getMe(signal?: AbortSignal): Promise<Me> {
  return request<Me>('GET', '/api/v1/me', { signal });
}

/** 403 when current_password is wrong, or when someone who is not an organization's admin renames it. */
export function patchMe(patch: ProfilePatch): Promise<Me> {
  return request<Me>('PATCH', '/api/v1/me', { json: patch });
}

/** Someone on their own deletes their account, and with it their workspace and everything in it. 403 when the
    password is wrong, or in an organization, where its admins delete accounts. The session ends with it. */
export async function deleteMyAccount(password: string): Promise<void> {
  await request<void>('DELETE', '/api/v1/me', { json: { password } });
  csrf = null;
}

/** The setup after sign-up is finished or skipped: the console stops opening it. */
export function finishOnboarding(): Promise<void> {
  return request<void>('POST', '/api/v1/me/onboarded');
}

export function getServerSettings(signal?: AbortSignal): Promise<ServerSettings> {
  return request<ServerSettings>('GET', '/api/v1/server-settings', { signal });
}

export function patchServerSettings(patch: Partial<ServerSettings>): Promise<ServerSettings> {
  return request<ServerSettings>('PATCH', '/api/v1/server-settings', { json: patch });
}

/** For the owner: every workspace by name, kind and number of members, and no one's profile. */
export function listWorkspaces(signal?: AbortSignal): Promise<WorkspaceSummary[]> {
  return request<WorkspaceSummary[]>('GET', '/api/v1/workspaces', { signal });
}

/** The owner deletes a workspace with everything in it; 409 for their own. */
export function deleteWorkspace(id: number): Promise<void> {
  return request<void>('DELETE', `/api/v1/workspaces/${id}`);
}

/* ---- mailboxes (admin) ---- */

export function listMailboxes(signal?: AbortSignal): Promise<Mailbox[]> {
  return request<Mailbox[]>('GET', '/api/v1/mailboxes', { signal });
}

export function createMailbox(mailbox: NewMailbox): Promise<Mailbox> {
  return request<Mailbox>('POST', '/api/v1/mailboxes', { json: mailbox });
}

export function updateMailbox(id: number, patch: MailboxPatch): Promise<Mailbox> {
  return request<Mailbox>('PATCH', `/api/v1/mailboxes/${id}`, { json: patch });
}

export function deleteMailbox(id: number): Promise<{ deleted: boolean }> {
  return request('DELETE', `/api/v1/mailboxes/${id}`);
}

/** Poll now. queued is false when a poll was already waiting. 409 when the mailbox is switched off. */
export function pollMailbox(id: number): Promise<{ queued: boolean }> {
  return request('POST', `/api/v1/mailboxes/${id}/poll`);
}

/* ---- audit and health ---- */

/** 100 per page, newest first. Analysts get their own entries. */
export function listAudit(offset = 0, signal?: AbortSignal): Promise<AuditEntry[]> {
  return request<AuditEntry[]>('GET', `/api/v1/audit${offset ? `?offset=${offset}` : ''}`, { signal });
}

export function getHealth(signal?: AbortSignal): Promise<Health> {
  return request<Health>('GET', '/healthz', { signal });
}

/* ---- feedback ---- */

/** 422 names the field (`message: required`); 429 past 10 an hour (see retryAfter). */
export function sendFeedback(feedback: NewFeedback): Promise<Feedback> {
  return request<Feedback>('POST', '/api/v1/feedback', { json: feedback });
}

export function listFeedback(signal?: AbortSignal): Promise<Feedback[]> {
  return request<Feedback[]>('GET', '/api/v1/feedback', { signal });
}

/** The owner's. */
export function markFeedback(id: number, status: Feedback['status']): Promise<Feedback> {
  return request<Feedback>('PATCH', `/api/v1/feedback/${id}`, { json: { status } });
}

export function deleteFeedback(id: number): Promise<void> {
  return request<void>('DELETE', `/api/v1/feedback/${id}`);
}

export function getVerdictFeedback(analysisId: number, signal?: AbortSignal): Promise<VerdictFeedback> {
  return request<VerdictFeedback>('GET', `/api/v1/analyses/${analysisId}/feedback`, { signal });
}

/** Makes or changes the caller's answer. */
export function answerVerdict(analysisId: number, answer: { opinion: Opinion; note: string }): Promise<VerdictAnswer> {
  return request<VerdictAnswer>('PUT', `/api/v1/analyses/${analysisId}/feedback`, { json: answer });
}

/** The caller's own answer; with an answer's ID, anyone's (its author or an admin). */
export function withdrawVerdictAnswer(analysisId: number, answerId?: number): Promise<void> {
  return request<void>('DELETE', `/api/v1/analyses/${analysisId}/feedback${answerId === undefined ? '' : `/${answerId}`}`);
}

/** Admins: the workspace's answers. */
export function getVerdictSummary(signal?: AbortSignal): Promise<VerdictSummary> {
  return request<VerdictSummary>('GET', '/api/v1/feedback/verdicts', { signal });
}

/** The owner's download: every workspace's disputed verdicts, without messages, notes or people. */
export const DISPUTED_CSV = '/api/v1/feedback/verdicts?format=csv';
