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
import type { Analysis, AnalysisFile, AuditEntry, Batch, Settings, Submission, Token, User } from '../api/types';

const CSRF_DETAIL = 'the form is out of date: reload the page and try again';
const THROTTLE_MS = 8_000;

const analyses: Analysis[] = structuredClone(fixtures as unknown as Analysis[]);
type MockSubmission = Submission & { ready: number; analysisSource: number; position: number };
const submissions = new Map<number, MockSubmission>();
let nextSubmission = 100;
type MockBatch = { id: number; created_at: string; user_id: number; username: string; offline: boolean; submissionIds: number[] };
const batches = new Map<number, MockBatch>();
let nextBatch = 1;
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

function viewOf(sub: MockSubmission): Submission {
  const { ready: _r, analysisSource: _s, position: _p, ...view } = sub;
  return view;
}

/** A submission moves on with the clock: queued, running, then done with a copy of a real analysis. */
function advance(sub: MockSubmission, me: { user_id: number; username: string }) {
  if (sub.status === 'done') return;
  const left = sub.ready - Date.now();
  if (left <= 0) {
    const copy: Analysis = structuredClone(analyses.find((a) => a.id === sub.analysisSource)!);
    copy.id = nextAnalysis++;
    copy.submission_id = sub.id;
    copy.submitted_by = me.user_id;
    copy.submitted_by_name = me.username;
    copy.created_at = new Date().toISOString();
    if (sub.batch_id) copy.source = 'batch';
    analyses.unshift(copy);
    Object.assign(sub, { status: 'done', analysis_id: copy.id });
    record('system', 'analyze', 'analysis', copy.id, { submission: sub.id, verdict: copy.verdict, providers: [], lookups: 0 });
  } else if (left < 2000) {
    sub.status = 'running';
  }
}

const KIND_ORDER = ['json', 'stix', 'misp', 'md', 'csv', 'html', 'manifest'];

function batchView(batch: MockBatch, me: { user_id: number; username: string }): Batch {
  const subs = batch.submissionIds.map((id) => submissions.get(id)!);
  subs.forEach((sub) => advance(sub, me));
  const counts = { queued: 0, running: 0, done: 0, failed: 0 };
  const verdicts: Batch['verdicts'] = {};
  const messages = subs.map((sub) => {
    counts[sub.status] += 1;
    const a = sub.analysis_id ? analyses.find((x) => x.id === sub.analysis_id) : undefined;
    if (a) verdicts[a.verdict] = (verdicts[a.verdict] ?? 0) + 1;
    return {
      position: sub.position, submission_id: sub.id, status: sub.status, error: sub.error,
      message_id: a?.message_id ?? 0, analysis_id: a?.id ?? null, verdict: a?.verdict ?? null, score: a?.score ?? null,
      sender: a?.sender ?? '', sender_domain: a?.sender_domain ?? '',
    };
  });
  const done = counts.queued + counts.running === 0;
  // the combined reports: the shape of a real analysis's files, named for the batch
  const files: AnalysisFile[] = done
    ? KIND_ORDER.map((kind) => {
        const like = analyses[analyses.length - 1].files.find((f) => f.kind === kind)!;
        return { ...like, name: like.name.replace(/report-[0-9a-f]+/, `batch-${batch.id}`), available: true };
      })
    : [];
  return {
    id: batch.id, created_at: batch.created_at, submitted_by: batch.user_id, submitted_by_name: batch.username,
    offline: batch.offline, total: subs.length, status: done ? 'done' : 'running', error: '', counts, verdicts, messages,
    finished_at: done ? new Date().toISOString() : null, files, files_deleted_at: null,
  };
}

/** Two campaigns among the sample analyses, as the server would find them. */
const CAMPAIGNS = [
  { members: [1, 4], shared: [{ kind: 'domain', value: 'example-corp-mfa.top', messages: 2 }, { kind: 'display name', value: 'it service desk', messages: 2 }] },
  { members: [3, 6], shared: [{ kind: 'originating IP', value: '45.148.10.77', messages: 2 }, { kind: 'subject', value: 'action required: unusual sign-in activity', messages: 2 }] },
];
const HIDDEN = ['subject', 'display name'];

function campaignView(spec: (typeof CAMPAIGNS)[number], detail: boolean) {
  const members = spec.members.map((id) => analyses.find((a) => a.id === id)).filter((a): a is Analysis => Boolean(a));
  const verdicts: Record<string, number> = {};
  members.forEach((a) => (verdicts[a.verdict] = (verdicts[a.verdict] ?? 0) + 1));
  const kept = members.filter((a) => a.report);
  const recipients = [...new Set(kept.flatMap((a) => (a.report?.to ?? '').match(/[\w.+-]+@[\w.-]+/g) ?? []))].sort();
  const order = ['MALICIOUS', 'LIKELY PHISHING', 'SUSPICIOUS', 'NO STRONG INDICATORS'];
  const view = {
    id: members[0]?.message_id ?? 0, size: members.length, first_seen: '2026-10-05T09:00:00Z', last_seen: '2026-10-06T18:30:00Z',
    verdicts, worst_verdict: order.find((v) => verdicts[v]) ?? 'NO STRONG INDICATORS',
    shared: spec.shared.map((s) => (HIDDEN.includes(s.kind) && (!detail || !kept.length) ? { ...s, value: null } : s)),
    senders: [...new Set(members.map((a) => a.sender))].sort(), recipient_count: members.length,
    rebuilt_at: new Date().toISOString(),
  };
  if (!detail) return view;
  return {
    ...view,
    messages: members.map((a) => ({ message_id: a.message_id, analysis_id: a.id, sha256: a.sha256, verdict: a.verdict, score: a.score, sender: a.sender, subject: a.subject, date: '2026-10-05T09:00:00Z' })),
    recipients: kept.length ? recipients : [],
    recipients_complete: kept.length === members.length,
  };
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
    const files = [...form.getAll('files'), ...form.getAll('file')].filter((f): f is File => f instanceof File);
    const raw = form.get('raw');
    const offline = form.get('offline') === 'true';
    if (!files.length && !(typeof raw === 'string' && raw.trim())) return error(400, 'bad_request', 'send a file or paste a message');
    if (files.some((f) => !/\.(eml|msg|mbox|zip)$/i.test(f.name))) return error(415, 'unsupported', 'this is not an .eml, .msg, .mbox or .zip file');
    // the preview re-uses real analyses: the hostile message for pasted text, the samples for files;
    // an .mbox or a .zip stands for three messages
    const count = files.reduce((n, f) => n + (/\.(mbox|zip)$/i.test(f.name) ? 3 : 1), 0);
    const samples = analyses.filter((a) => a.source === 'upload');
    const queue = (source: Analysis, batchId: number | null, position: number): MockSubmission => {
      const id = nextSubmission++;
      const sub: MockSubmission = { id, status: 'queued', error: '', analysis_id: null, submitted_at: new Date().toISOString(), batch_id: batchId, ready: Date.now() + 3000 + position * 1500, analysisSource: source.id, position };
      submissions.set(id, sub);
      record(me.username, 'submit', 'submission', id, { sha256: source.sha256, source: batchId ? 'batch' : files.length ? 'upload' : 'paste', offline });
      return sub;
    };
    if (count <= 1) {
      const source = files.length ? samples[0] ?? analyses[0] : analyses.find((a) => a.source === 'paste') ?? analyses[0];
      return json(202, viewOf(queue(source, null, 0)));
    }
    const batch: MockBatch = { id: nextBatch++, created_at: new Date().toISOString(), user_id: me.user_id, username: me.username, offline, submissionIds: [] };
    batches.set(batch.id, batch);
    for (let i = 0; i < count; i++) batch.submissionIds.push(queue(samples[i % samples.length] ?? analyses[0], batch.id, i + 1).id);
    record(me.username, 'submit_batch', 'batch', batch.id, { messages: count, offline });
    return json(202, { batch_id: batch.id, total: count, submission_ids: batch.submissionIds, skipped: 0 });
  }

  if ((m = pathname.match(/^\/api\/v1\/submissions\/(\d+)$/)) && method === 'GET') {
    const sub = submissions.get(Number(m[1]));
    if (!sub) return error(404, 'not_found', 'no such submission');
    advance(sub, me);
    return json(200, viewOf(sub));
  }

  if ((m = pathname.match(/^\/api\/v1\/batches\/(\d+)$/)) && method === 'GET') {
    const batch = batches.get(Number(m[1]));
    return batch ? json(200, batchView(batch, me)) : error(404, 'not_found', 'no such batch');
  }

  if (pathname === '/api/v1/campaigns' && method === 'GET') {
    return json(200, CAMPAIGNS.map((c) => campaignView(c, false)).filter((c) => c.size >= 2));
  }

  if ((m = pathname.match(/^\/api\/v1\/campaigns\/(\d+)$/)) && method === 'GET') {
    const spec = CAMPAIGNS.find((c) => campaignView(c, false).id === Number(m![1]) && campaignView(c, false).size >= 2);
    return spec ? json(200, campaignView(spec, true)) : error(404, 'not_found', 'no such campaign');
  }

  if (pathname === '/api/v1/analyses' && method === 'GET') {
    const q = (searchParams.get('q') ?? '').toLowerCase();
    const verdict = searchParams.get('verdict') ?? '';
    const source = searchParams.get('source') ?? '';
    const user = searchParams.get('user');
    const day = /^\d{4}-\d{2}-\d{2}$/;
    const since = searchParams.get('since') ?? '';
    const until = searchParams.get('until') ?? '';
    if ((since && !day.test(since)) || (until && !day.test(until))) return error(422, 'invalid', 'the request is not valid');
    const offset = Number(searchParams.get('offset') ?? 0);
    const rows = analyses
      .filter((a) => !verdict || a.verdict === verdict)
      .filter((a) => !source || a.source === source)
      .filter((a) => user === null || a.submitted_by === Number(user))
      .filter((a) => (!since || a.created_at.slice(0, 10) >= since) && (!until || a.created_at.slice(0, 10) <= until))
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
    const sub: MockSubmission = { id, status: 'queued', error: '', analysis_id: null, submitted_at: new Date().toISOString(), batch_id: null, ready: Date.now() + 3000, analysisSource: a.id, position: 0 };
    submissions.set(id, sub);
    record(me.username, 'reanalyze', 'analysis', a.id, { submission: id });
    return json(202, viewOf(sub));
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
