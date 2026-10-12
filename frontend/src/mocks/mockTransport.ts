/* DEVELOPMENT ONLY. A fake PhishHawk backend with the same contract as the
   real one, used by src/api/client.ts when the app runs on the vite dev server
   (and so in the AI Studio preview). `vite build` drops this file.

   The analyses in fixtures.json are real responses from the PhishHawk server
   for the repository's sample messages and the hostile test message, all
   analysed offline. Nothing on any screen may mention this mock, its users or
   its password: there is no UI for it.

   No password hassle while building: the preview starts signed in as the
   admin "boss". After "Sign out", any existing user ("boss", "alice", or one
   added on the Users screen) signs in with any password. An unknown username
   is refused, and three refusals in a row throttle sign-in for 8 seconds, as
   on the real server. The real server always checks the password. */

import fixtures from './fixtures.json';
import type { Analysis, AuditEntry, Settings, Submission, Token, User } from '../api/types';

const CSRF_DETAIL = 'the form is out of date: reload the page and try again';
const THROTTLE_MS = 8_000;

const analyses: Analysis[] = structuredClone(fixtures as unknown as Analysis[]);
const submissions = new Map<number, Submission & { ready: number; analysisSource: number }>();
let nextSubmission = 100;
let nextAnalysis = Math.max(...analyses.map((a) => a.id)) + 1;
let failedLogins = 0;
let throttledUntil = 0;
const audit: AuditEntry[] = [];
let nextAudit = 1;
const settings: Settings = {
  providers: [],
  protected_domains: ['example-corp.co.uk'],
  allow_domains: [],
  block_domains: [],
  trusted_authserv: [],
  retention_days: 30,
  max_upload_mb: 25,
  max_batch_messages: 500,
  campaign_window_days: 90,
  keys: { virustotal: '', urlscan: '', abuseipdb: '' },
};
const users: User[] = [
  { id: 1, username: 'boss', role: 'admin', disabled: false, last_login_at: null },
  { id: 2, username: 'alice', role: 'analyst', disabled: false, last_login_at: null },
];
const tokens: Token[] = [];

type MockSession = { user_id: number; username: string; role: 'analyst' | 'admin'; csrf: string };
const sessionFor = (user: User): MockSession => ({ user_id: user.id, username: user.username, role: user.role, csrf: crypto.randomUUID() });
// direct admin access in development: no sign-in screen at start
let session: MockSession | null = sessionFor(users[0]);
users[0].last_login_at = new Date().toISOString();

function record(actor: string, action: string, objectType = '', objectId: unknown = '', details: Record<string, unknown> = {}) {
  audit.unshift({ id: nextAudit++, at: new Date().toISOString(), actor, action, object_type: objectType, object_id: String(objectId), details });
}

record(users[0].username, 'login');

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
const error = (status: number, code: string, detail: string, headers?: Record<string, string>) =>
  json(status, { error: code, detail }, headers);

function summaryOf(a: Analysis) {
  const { report: _report, ...summary } = a;
  return summary;
}

export async function mockFetch(url: string, init: RequestInit): Promise<Response> {
  await new Promise((r) => setTimeout(r, 120 + Math.random() * 180));
  if (init.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
  const method = (init.method ?? 'GET').toUpperCase();
  const { pathname, searchParams } = new URL(url, 'http://mock.local');
  const headers = new Headers(init.headers);
  const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body;

  if (pathname === '/healthz') {
    return json(200, { status: 'ok', version: '3.0.0-dev', queue: [...submissions.values()].filter((s) => s.status !== 'done').length, last_heartbeat: new Date().toISOString(), disk_free_mb: 20480 });
  }

  // logging in
  if (pathname === '/api/v1/session' && method === 'POST') {
    const { username = '' } = (body ?? {}) as { username?: string; password?: string };
    const now = Date.now();
    if (now < throttledUntil) {
      const wait = Math.ceil((throttledUntil - now) / 1000);
      return error(429, 'throttled', `too many attempts: wait ${wait} s`, { 'Retry-After': String(wait) });
    }
    const user = users.find((u) => u.username === username.trim().toLowerCase() && !u.disabled);
    if (!user) {
      failedLogins += 1;
      if (failedLogins >= 3) {
        failedLogins = 0;
        throttledUntil = now + THROTTLE_MS;
      }
      record(username.slice(0, 64) || '?', 'login_failed');
      return error(401, 'unauthorized', 'wrong username or password');
    }
    failedLogins = 0;
    throttledUntil = 0;
    session = sessionFor(user);
    user.last_login_at = new Date().toISOString();
    record(user.username, 'login');
    return json(200, { csrf: session.csrf });
  }

  if (!session) return error(401, 'unauthorized', 'log in first');
  const me = session;
  if (method !== 'GET' && headers.get('X-CSRF-Token') !== me.csrf) return error(403, 'forbidden', CSRF_DETAIL);
  const admin = me.role === 'admin';
  const adminOnly = () => error(403, 'forbidden', 'only an admin can do that');
  let m: RegExpMatchArray | null;

  if (pathname === '/api/v1/session') {
    if (method === 'GET') return json(200, { user_id: me.user_id, username: me.username, role: me.role, via: 'session', scope: 'full', csrf: me.csrf });
    if (method === 'DELETE') {
      record(me.username, 'logout');
      session = null;
      return json(204, null);
    }
  }

  if (pathname === '/api/v1/submissions' && method === 'POST') {
    const form = body as FormData;
    const file = form.get('file');
    const raw = form.get('raw');
    if (!(file instanceof File) && !(typeof raw === 'string' && raw.trim())) return error(400, 'bad_request', 'send a file or paste a message');
    if (file instanceof File && !/\.(eml|msg)$/i.test(file.name)) return error(415, 'unsupported', 'only .eml and .msg messages are accepted');
    const id = nextSubmission++;
    // the preview re-uses a real analysis: the hostile message for pasted text, a sample for files
    const source = typeof raw === 'string' && raw.trim() ? analyses.find((a) => a.source === 'paste') ?? analyses[0] : analyses[0];
    const sub = { id, status: 'queued' as const, error: '', analysis_id: null, submitted_at: new Date().toISOString(), ready: Date.now() + 3000, analysisSource: source.id };
    submissions.set(id, sub);
    record(me.username, 'submit', 'submission', id, { sha256: source.sha256, source: file instanceof File ? 'upload' : 'paste', offline: form.get('offline') === 'true' });
    const { ready: _r, analysisSource: _s, ...view } = sub;
    return json(202, view);
  }

  if ((m = pathname.match(/^\/api\/v1\/submissions\/(\d+)$/)) && method === 'GET') {
    const sub = submissions.get(Number(m[1]));
    if (!sub) return error(404, 'not_found', 'no such submission');
    if (sub.status !== 'done') {
      const left = sub.ready - Date.now();
      if (left <= 0) {
        const copy: Analysis = structuredClone(analyses.find((a) => a.id === sub.analysisSource)!);
        copy.id = nextAnalysis++;
        copy.submission_id = sub.id;
        copy.submitted_by = me.user_id;
        copy.submitted_by_name = me.username;
        copy.created_at = new Date().toISOString();
        analyses.unshift(copy);
        Object.assign(sub, { status: 'done', analysis_id: copy.id });
        record('system', 'analyze', 'analysis', copy.id, { submission: sub.id, verdict: copy.verdict, providers: [], lookups: 0 });
      } else if (left < 2000) {
        sub.status = 'running';
      }
    }
    const { ready: _r, analysisSource: _s, ...view } = sub;
    return json(200, view);
  }

  if (pathname === '/api/v1/analyses' && method === 'GET') {
    const q = (searchParams.get('q') ?? '').toLowerCase();
    const verdict = searchParams.get('verdict') ?? '';
    const offset = Number(searchParams.get('offset') ?? 0);
    const rows = analyses
      .filter((a) => !verdict || a.verdict === verdict)
      .filter((a) => !q || a.sha256.startsWith(q) || a.report_id.toLowerCase() === q || JSON.stringify(a.report?.iocs ?? []).toLowerCase().includes(q))
      .slice(offset, offset + 50)
      .map(summaryOf);
    return json(200, rows);
  }

  if ((m = pathname.match(/^\/api\/v1\/analyses\/(\d+)$/)) && method === 'GET') {
    const a = analyses.find((x) => x.id === Number(m![1]));
    return a ? json(200, a) : error(404, 'not_found', 'no such analysis');
  }

  if ((m = pathname.match(/^\/api\/v1\/analyses\/(\d+)\/reanalyze$/)) && method === 'POST') {
    const a = analyses.find((x) => x.id === Number(m![1]));
    if (!a) return error(404, 'not_found', 'no such analysis');
    if (a.tier1_deleted_at) return error(410, 'gone', 'the message was deleted after the retention period');
    const id = nextSubmission++;
    const sub = { id, status: 'queued' as const, error: '', analysis_id: null, submitted_at: new Date().toISOString(), ready: Date.now() + 3000, analysisSource: a.id };
    submissions.set(id, sub);
    record(me.username, 'reanalyze', 'analysis', a.id, { submission: id });
    const { ready: _r, analysisSource: _s, ...view } = sub;
    return json(202, view);
  }

  if ((m = pathname.match(/^\/api\/v1\/messages\/(\d+)(\/hold)?$/))) {
    const messageId = Number(m[1]);
    const mine = analyses.filter((a) => a.message_id === messageId);
    if (!mine.length) return error(404, 'not_found', 'no such message');
    if (m[2]) {
      if (!admin) return adminOnly();
      const hold = method === 'POST';
      mine.forEach((a) => (a.hold = hold));
      record(me.username, hold ? 'hold' : 'release', 'message', messageId);
      return json(200, { hold });
    }
    if (method === 'DELETE') {
      if (mine[0].hold) return error(409, 'conflict', 'this message is on hold; an admin must release it first');
      const scope = searchParams.get('scope') ?? 'tier1';
      if (scope === 'all') {
        if (!admin) return error(403, 'forbidden', 'only an admin can delete completely');
        for (const a of mine) analyses.splice(analyses.indexOf(a), 1);
        record(me.username, 'delete_completely', 'message', messageId, { sha256: mine[0].sha256 });
        return json(200, { deleted: 'all' });
      }
      if (!admin && !mine.some((a) => a.submitted_by === me.user_id)) return error(403, 'forbidden', 'only the submitter or an admin can delete this message');
      for (const a of mine) {
        a.tier1_deleted_at = new Date().toISOString();
        a.subject = null;
        a.report = null;
        a.files = a.files.map((f) => ({ ...f, available: false }));
      }
      record(me.username, 'delete_tier1', 'message', messageId, { sha256: mine[0].sha256 });
      return json(200, { deleted: 'tier1' });
    }
  }

  if (pathname === '/api/v1/audit' && method === 'GET') {
    const offset = Number(searchParams.get('offset') ?? 0);
    const rows = admin ? audit : audit.filter((e) => e.actor === me.username);
    return json(200, rows.slice(offset, offset + 100));
  }

  if (pathname.startsWith('/api/v1/settings') || pathname.startsWith('/api/v1/users') || pathname.startsWith('/api/v1/tokens')) {
    if (!admin) return adminOnly();
  }

  if (pathname === '/api/v1/settings') {
    if (method === 'GET') return json(200, settings);
    if (method === 'PATCH') {
      const patch = body as Partial<Settings>;
      const changed: string[] = [];
      for (const [key, value] of Object.entries(patch)) {
        if (key === 'keys') {
          for (const [provider, secret] of Object.entries(value as Record<string, string>)) {
            settings.keys[provider] = secret ? `...${secret.slice(-4)}` : '';
            changed.push(`key:${provider}`);
          }
        } else if (value !== undefined) {
          (settings as Record<string, unknown>)[key] = value;
          changed.push(key);
        }
      }
      record(me.username, 'settings', '', '', { changed });
      return json(200, settings);
    }
  }

  if (pathname === '/api/v1/users') {
    if (method === 'GET') return json(200, users);
    if (method === 'POST') {
      const { username, password, role } = body as { username: string; password: string; role: 'admin' | 'analyst' };
      if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username)) return error(422, 'invalid', 'usernames are 3 to 64 lowercase letters, digits, dots, dashes or underscores');
      if (!password || password.length < 12) return error(422, 'invalid', 'passwords need at least 12 characters');
      if (users.some((u) => u.username === username)) return error(422, 'invalid', 'that username is taken');
      const user: User = { id: Math.max(...users.map((u) => u.id)) + 1, username, role, disabled: false, last_login_at: null };
      users.push(user);
      record(me.username, 'user_create', 'user', user.id, { username, role });
      return json(201, user);
    }
  }
  if ((m = pathname.match(/^\/api\/v1\/users\/(\d+)$/)) && method === 'PATCH') {
    const user = users.find((u) => u.id === Number(m![1]));
    if (!user) return error(404, 'not_found', 'no such user');
    const patch = body as { role?: 'admin' | 'analyst'; disabled?: boolean; password?: string };
    if (user.id === me.user_id && (patch.disabled || (patch.role && patch.role !== 'admin'))) return error(422, 'invalid', 'you cannot disable yourself or remove your own admin role');
    if (patch.role) user.role = patch.role;
    if (patch.disabled !== undefined) user.disabled = patch.disabled;
    record(me.username, 'user_change', 'user', user.id, { role: patch.role ?? null, disabled: patch.disabled ?? null, password_changed: Boolean(patch.password) });
    return json(200, user);
  }

  if (pathname === '/api/v1/tokens') {
    if (method === 'GET') return json(200, tokens);
    if (method === 'POST') {
      const { name, scope, user_id } = body as { name: string; scope: 'read' | 'submit'; user_id: number };
      if (scope !== 'read' && scope !== 'submit') return error(422, 'invalid', 'scope must be read or submit');
      if (!name || name.length > 64) return error(422, 'invalid', 'a token needs a name of 1 to 64 characters');
      const token: Token = { id: tokens.length + 1, name, scope, user_id, created_at: new Date().toISOString(), revoked: false };
      tokens.push(token);
      record(me.username, 'token_create', 'user', user_id, { name, scope });
      return json(201, { token: `phk_preview_${crypto.randomUUID().replaceAll('-', '')}`, note: 'shown once: store it now' });
    }
  }
  if ((m = pathname.match(/^\/api\/v1\/tokens\/(\d+)$/)) && method === 'DELETE') {
    const token = tokens.find((t) => t.id === Number(m![1]));
    if (!token) return error(404, 'not_found', 'no such token');
    token.revoked = true;
    record(me.username, 'token_revoke', 'token', token.id, { name: token.name });
    return json(200, { revoked: true });
  }

  return error(404, 'not_found', 'Not Found');
}
