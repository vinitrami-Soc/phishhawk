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
   on the real server. The real server always checks the password.

   The server is set up already, with "boss" as its owner in the organization
   "Example Corp", and anyone may create an account: an individual or a new
   organization. A new workspace starts empty and sees nothing of the others.

   The preview sends mail, as a server with mail settings does: an email address
   is needed to create an account, and "Forgot password?" works. Each message
   goes to mockOutbox and, in a browser, to the console, so its link can be
   opened: /app/reset/<token> or /app/verify-email/<token>. "boss" has a
   confirmed address. Five reset requests in a row wait a minute here (an hour on
   the real server). */

import fixtures from './fixtures.json';
import type { Analysis, AnalysisFile, AuditEntry, Batch, Feedback, Invite, Mailbox, MailboxConfig, MailboxKind, Opinion, Profile, ServerSettings, Settings, Submission, Token, User, VerdictAnswer, Workspace, WorkspaceSummary } from '../api/types';

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

/* Workspaces: who is in which, with their profile. The users list stays the server's shape. */
const workspaces: Workspace[] = [{ id: 1, name: 'Example Corp', kind: 'organization' }];
const workspaceMade = new Map<number, string>([[1, new Date(Date.now() - 90 * 86_400_000).toISOString()]]);
type Member = { workspace_id: number; owner: boolean; profile: Profile; onboarded: boolean; email: string; email_verified: boolean };
const blank: Profile = { first_name: '', last_name: '', location: '', job_title: '' };
const members = new Map<number, Member>([
  [1, { workspace_id: 1, owner: true, profile: { first_name: 'Sam', last_name: 'Boss', location: 'London', job_title: 'SOC lead' }, onboarded: true, email: 'sam.boss@example-corp.co.uk', email_verified: true }],
  [2, { workspace_id: 1, owner: false, profile: { ...blank }, onboarded: true, email: '', email_verified: false }],
]);
const memberOf = (userId: number): Member => members.get(userId) ?? { workspace_id: 1, owner: false, profile: { ...blank }, onboarded: true, email: '', email_verified: false };
/* Analyses made in the preview belong to the workspace that submitted them; the sample ones to Example Corp. */
const analysisWorkspace = new Map<number, number>();
const workspaceOf = (a: Analysis) => analysisWorkspace.get(a.id) ?? 1;
const serverSettings: ServerSettings = { signup_open: true, signup_daily_cap: 100, max_upload_mb: 25, max_batch_messages: 500, daily_messages_organization: 500, daily_messages_individual: 100 };
type MockInvite = Invite & { token: string; workspace_id: number; used: boolean };
const invites: MockInvite[] = [];
/* Feedback: notes to the owner, and each person's answer on a verdict, as the server keeps them. */
const feedbackRows: (Feedback & { user_id: number })[] = [];
const answers: (VerdictAnswer & { analysis_id: number })[] = [];
let lastFeedbackId = 0;
let lastAnswerId = 0;
const OPINIONS: Opinion[] = ['right', 'missed', 'false_alarm'];
const disputedIds = () => new Set(answers.filter((a) => a.opinion !== 'right').map((a) => a.analysis_id));
const countsOf = (rows: { opinion: Opinion }[]) => Object.fromEntries(OPINIONS.map((o) => [o, rows.filter((r) => r.opinion === o).length])) as Record<Opinion, number>;
/** Free text as the server takes it: trimmed, at most `most` characters, lines but no other control characters. */
function freeText(field: string, value: unknown, most: number, required = true): string {
  const written = typeof value === 'string' ? value.trim() : '';
  if (required && !written) throw `${field}: required`;
  if (written.length > most) throw `${field}: ${most} characters at most`;
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(written)) throw `${field}: control characters are not allowed`;
  return written;
}
const PROFILE_FIELDS = ['first_name', 'last_name', 'location', 'job_title'] as const;

/** A profile field as the server checks it: trimmed, at most 80 characters, no control characters. */
function clean(field: string, value: unknown, required = true): string {
  const text = typeof value === 'string' ? value.trim() : '';
  if (required && !text) throw `${field}: required`;
  if (text.length > 80) throw `${field}: 80 characters at most`;
  if (/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/.test(text)) throw `${field}: control characters are not allowed`;
  return text;
}

/** An email address as the server takes it: trimmed, lower case, one an email can be sent to; "" for none. */
const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
function cleanEmail(value: unknown, required: boolean): string {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!text) {
    if (required) throw 'email: required';
    return '';
  }
  if (text.length > 254 || !EMAIL.test(text)) throw 'email: an address such as name@example.org';
  return text;
}

/** A token as the server makes one: 32 random bytes, URL-safe base64. */
function urlToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* Mail the preview "sends": a reset link (an hour, once) or a confirmation link (24 hours, once). */
export const mockOutbox: { to: string; subject: string; link: string }[] = [];
type MailLink = { purpose: 'reset' | 'verify'; user_id: number; email: string; expires: number; used: boolean };
const mailLinks = new Map<string, MailLink>();
const RESET_WINDOW_MS = 60_000;
let resetAsks: number[] = [];

function sendLink(userId: number, purpose: MailLink['purpose']) {
  const { email } = memberOf(userId);
  const token = urlToken();
  mailLinks.set(token, { purpose, user_id: userId, email, expires: Date.now() + (purpose === 'reset' ? 3_600_000 : 86_400_000), used: false });
  const link = `/app/${purpose === 'reset' ? 'reset' : 'verify-email'}/${token}`;
  mockOutbox.push({ to: email, subject: purpose === 'reset' ? 'Reset your PhishHawk password' : 'Confirm your email for PhishHawk', link });
  if (typeof window !== 'undefined') console.info(`Mail to ${email}: ${window.location.origin}${link}`);
}

/** The new account's profile, credentials and address, or the refusal (status and detail) the server would send. */
function newAccount(given: Record<string, unknown>): { username: string; profile: Profile; email: string } | [number, string] {
  try {
    const profile = Object.fromEntries(PROFILE_FIELDS.map((f) => [f, clean(f, given[f], f !== 'job_title')])) as Profile;
    const email = cleanEmail(given.email, true);
    const username = String(given.username ?? '');
    if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username)) return [422, 'username: 3 to 64 lowercase letters, digits, dots, dashes or underscores'];
    if (String(given.password ?? '').length < 12) return [422, 'password: at least 12 characters'];
    if (users.some((u) => u.username === username)) return [409, 'username: that username is taken'];
    return { username, profile, email };
  } catch (refusal) {
    return [422, String(refusal)];
  }
}

/** Someone who signed up or joined (`signedUp`) sees the setup once; someone an admin added does not. An address
    given is sent its confirmation link. */
function addMember(username: string, role: 'admin' | 'analyst', workspaceId: number, profile: Profile, signedUp = true, email = ''): User {
  const user: User = { id: Math.max(...users.map((u) => u.id)) + 1, username, role, disabled: false, last_login_at: new Date().toISOString() };
  users.push(user);
  members.set(user.id, { workspace_id: workspaceId, owner: false, profile, onboarded: !signedUp, email, email_verified: false });
  if (email) sendLink(user.id, 'verify');
  return user;
}

/** A deleted account: its sessions, tokens, feedback and answers go; what it submitted stays the workspace's. */
function removeUser(userId: number) {
  users.splice(users.findIndex((u) => u.id === userId), 1);
  members.delete(userId);
  tokens.splice(0, tokens.length, ...tokens.filter((t) => t.user_id !== userId));
  feedbackRows.splice(0, feedbackRows.length, ...feedbackRows.filter((f) => f.user_id !== userId));
  answers.splice(0, answers.length, ...answers.filter((a) => a.user_id !== userId));
}

/** A deleted workspace: everything in it, its people too. */
function removeWorkspace(workspaceId: number) {
  for (const user of users.filter((u) => memberOf(u.id).workspace_id === workspaceId)) removeUser(user.id);
  analyses.splice(0, analyses.length, ...analyses.filter((a) => workspaceOf(a) !== workspaceId));
  invites.splice(0, invites.length, ...invites.filter((i) => i.workspace_id !== workspaceId));
  workspaces.splice(workspaces.findIndex((w) => w.id === workspaceId), 1);
  workspaceMade.delete(workspaceId);
}

/* Two report mailboxes: one polled a few minutes ago, one whose sign-in Google refuses. A poll of an enabled
   mailbox that is not in error imports one copy of a sample analysis, as the real worker would import a report. */
const minutesFromNow = (m: number) => new Date(Date.now() + m * 60_000).toISOString();
const mailboxes: Mailbox[] = [
  {
    id: 1, name: 'Phish reports', kind: 'imap', enabled: true, interval_minutes: 5,
    config: { host: 'outlook.office365.com', port: 993, starttls: false, user: 'phish@example-corp.co.uk', folder: 'INBOX' },
    secret_set: true, status: 'ok', error: '', last_poll_at: minutesFromNow(-3), next_poll_at: minutesFromNow(2),
    last_counts: { imported: 2, duplicates: 1, skipped: 0 }, created_at: minutesFromNow(-60 * 24 * 7),
  },
  {
    id: 2, name: 'Workspace reports', kind: 'gmail', enabled: true, interval_minutes: 10,
    config: { address: 'phish@example-corp.co.uk', label: 'Phish reports', service_account: 'phishhawk@reports-project.iam.gserviceaccount.com' },
    secret_set: true, status: 'error',
    error: 'Gmail: sign-in refused (unauthorized_client): check the key, and that the service account has domain-wide delegation for the gmail.readonly scope',
    last_poll_at: minutesFromNow(-20), next_poll_at: minutesFromNow(40), last_counts: { imported: 0, duplicates: 0, skipped: 0 },
    created_at: minutesFromNow(-60 * 24),
  },
];
const GUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const ADDRESS = /^[^\s@"<>()[\],;:\\]{1,64}@[a-z0-9.-]+\.[a-z]{2,63}$/i;

/** The settings a mailbox of this kind keeps, with the server's defaults; a string when something is refused. */
function mailboxConfig(kind: MailboxKind, given: MailboxConfig): MailboxConfig | string {
  const text = (v: unknown) => String(v ?? '').trim();
  if (kind === 'imap') {
    const starttls = Boolean(given.starttls);
    const port = given.port === undefined || String(given.port) === '' ? (starttls ? 143 : 993) : Number(given.port);
    if (!HOST.test(text(given.host))) return 'host must be a host name or an IP address, without imaps:// or a path';
    if (!Number.isInteger(port) || port < 1 || port > 65535) return 'port must be between 1 and 65535';
    if (!text(given.user)) return 'user is required';
    return { host: text(given.host).toLowerCase(), port, starttls, user: text(given.user), folder: text(given.folder) || 'INBOX' };
  }
  if (kind === 'graph') {
    if (!GUID.test(text(given.tenant_id)) && !/^[a-z0-9.-]+\.[a-z]{2,63}$/i.test(text(given.tenant_id))) return 'tenant must be a directory (tenant) ID or a domain such as contoso.onmicrosoft.com';
    if (!GUID.test(text(given.client_id))) return 'client ID must be the application (client) ID, a GUID';
    if (!ADDRESS.test(text(given.address))) return "address must be the report mailbox's address";
    return { tenant_id: text(given.tenant_id).toLowerCase(), client_id: text(given.client_id).toLowerCase(), address: text(given.address), folder: text(given.folder) || 'inbox' };
  }
  if (!ADDRESS.test(text(given.address))) return "address must be the report mailbox's address";
  return { address: text(given.address), label: text(given.label) || 'INBOX', ...(given.service_account ? { service_account: given.service_account } : {}) };
}

/** What a credential tells the config (a service account's address), or why it is refused. */
function mailboxSecret(kind: MailboxKind, secret: string): MailboxConfig | string {
  if (kind === 'imap') return secret ? {} : 'a password is required';
  if (kind === 'graph') return secret.trim() ? {} : 'a client secret is required';
  try {
    const key = JSON.parse(secret);
    if (key?.type === 'service_account' && ADDRESS.test(String(key.client_email ?? '')) && String(key.private_key ?? '').includes('PRIVATE KEY')) {
      return { service_account: key.client_email };
    }
  } catch {
    // not JSON: refused below
  }
  return 'the key must be the JSON key file of a service account';
}

type MockSession = { user_id: number; username: string; role: 'analyst' | 'admin'; csrf: string; workspace_id: number; owner: boolean };
const sessionFor = (user: User): MockSession => ({
  user_id: user.id, username: user.username, role: user.role, csrf: crypto.randomUUID(),
  workspace_id: memberOf(user.id).workspace_id, owner: memberOf(user.id).owner,
});
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
function advance(sub: MockSubmission, me: { user_id: number; username: string; workspace_id?: number }) {
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
    analysisWorkspace.set(copy.id, me.workspace_id ?? 1);
    Object.assign(sub, { status: 'done', analysis_id: copy.id });
    record('system', 'analyze', 'analysis', copy.id, { submission: sub.id, verdict: copy.verdict, providers: [], lookups: 0 });
  } else if (left < 2000) {
    sub.status = 'running';
  }
}

const KIND_ORDER = ['json', 'stix', 'misp', 'md', 'csv', 'html', 'manifest'];

function batchView(batch: MockBatch, me: { user_id: number; username: string; workspace_id?: number }): Batch {
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

  let m: RegExpMatchArray | null;
  // getting in: setup (done already in the preview), sign-up and invitations, signed in or not
  if (pathname === '/api/v1/setup') {
    if (method === 'GET') return json(200, { open: false });
    return error(404, 'not_found', 'this server is set up already: sign in');
  }
  if (pathname === '/api/v1/signup') {
    if (method === 'GET') return json(200, { open: serverSettings.signup_open });
    if (!serverSettings.signup_open) return error(404, 'not_found', 'sign-up is closed: ask an admin for an invitation');
    const given = (body ?? {}) as Record<string, unknown>;
    if (given.kind !== 'individual' && given.kind !== 'organization') return error(422, 'invalid', 'kind: individual or organization');
    const account = newAccount(given);
    if (Array.isArray(account)) return error(account[0], account[0] === 409 ? 'conflict' : 'invalid', account[1]);
    let organization: string;
    try {
      organization = clean('organization', given.organization, given.kind === 'organization');
    } catch (refusal) {
      return error(422, 'invalid', String(refusal));
    }
    const { first_name, last_name } = account.profile;
    const workspace: Workspace = { id: Math.max(...workspaces.map((w) => w.id)) + 1, name: given.kind === 'organization' ? organization : `${first_name} ${last_name}`, kind: given.kind };
    workspaces.push(workspace);
    workspaceMade.set(workspace.id, new Date().toISOString());
    const user = addMember(account.username, 'admin', workspace.id, account.profile, true, account.email);
    session = sessionFor(user);
    record(user.username, 'signup', '', '', { kind: workspace.kind, workspace: workspace.id });
    return json(201, { csrf: session.csrf });
  }
  if ((m = pathname.match(/^\/api\/v1\/join\/([A-Za-z0-9_-]+)$/))) {
    const invite = invites.find((i) => i.token === m![1] && !i.used && Date.parse(i.expires_at) > Date.now());
    if (!invite) return error(404, 'not_found', 'this invitation is not valid: it was used, withdrawn, or is over 7 days old');
    const workspace = workspaces.find((w) => w.id === invite.workspace_id)!;
    if (method === 'GET') return json(200, { organization: workspace.name, role: invite.role });
    const account = newAccount((body ?? {}) as Record<string, unknown>);
    if (Array.isArray(account)) return error(account[0], account[0] === 409 ? 'conflict' : 'invalid', account[1]);
    invite.used = true;
    const user = addMember(account.username, invite.role, workspace.id, account.profile, true, account.email);
    session = sessionFor(user);
    record(user.username, 'join', 'invite', invite.id, { role: invite.role });
    return json(201, { csrf: session.csrf });
  }

  // a forgotten password, and the links mail sends: no one signed in
  if (pathname === '/api/v1/password-reset') {
    if (method === 'GET') return json(200, { available: true });
    const now = Date.now();
    resetAsks = resetAsks.filter((at) => now - at < RESET_WINDOW_MS);
    if (resetAsks.length >= 5) {
      const wait = Math.ceil((resetAsks[0] + RESET_WINDOW_MS - now) / 1000);
      return error(429, 'throttled', 'too many requests: try again later', { 'Retry-After': String(wait) });
    }
    resetAsks.push(now);
    const login = String((body as { login?: unknown } | undefined)?.login ?? '').trim().toLowerCase();
    const matches = (u: User) => (login.includes('@') ? memberOf(u.id).email === login : u.username === login);
    for (const u of users) if (login && !u.disabled && memberOf(u.id).email_verified && matches(u)) sendLink(u.id, 'reset');
    return json(202, { detail: 'if an account matches, a link is on its way to its confirmed email address' });
  }
  if ((m = pathname.match(/^\/api\/v1\/(password-reset|verify-email)\/([A-Za-z0-9_-]+)$/))) {
    const purpose = m[1] === 'password-reset' ? 'reset' : 'verify';
    const link = mailLinks.get(m[2]);
    const user = link && users.find((u) => u.id === link.user_id && !u.disabled);
    if (!link || !user || link.purpose !== purpose || link.used || link.expires < Date.now() || memberOf(user.id).email !== link.email) {
      return error(404, 'not_found', 'this link is not valid: it was used, is too old, or is for another address');
    }
    if (purpose === 'reset' && method === 'GET') return json(200, { username: user.username });
    if (method !== 'POST') return error(405, 'method_not_allowed', 'method not allowed');
    if (purpose === 'verify') {
      link.used = true;
      members.get(user.id)!.email_verified = true;
      record(user.username, 'email_verified', 'user', user.id);
      return json(204, null);
    }
    if (String((body as { password?: unknown } | undefined)?.password ?? '').length < 12) return error(422, 'invalid', 'password: at least 12 characters');
    for (const other of mailLinks.values()) if (other.user_id === user.id && other.purpose === 'reset') other.used = true;
    if (session?.user_id === user.id) session = null; // every session of the account ends
    record(user.username, 'password_reset', 'user', user.id);
    return json(204, null);
  }

  if (!session) return error(401, 'unauthorized', 'log in first');
  const me = session;
  const workspace = workspaces.find((w) => w.id === me.workspace_id)!;
  const home = (a: Analysis) => workspaceOf(a) === me.workspace_id;
  if (method !== 'GET' && headers.get('X-CSRF-Token') !== me.csrf) return error(403, 'forbidden', CSRF_DETAIL);
  const admin = me.role === 'admin';
  const adminOnly = () => error(403, 'forbidden', 'only an admin can do that');

  if (pathname === '/api/v1/session') {
    if (method === 'GET') {
      return json(200, { user_id: me.user_id, username: me.username, role: me.role, via: 'session', scope: 'full', csrf: me.csrf, owner: me.owner, onboarded: memberOf(me.user_id).onboarded, workspace, profile: memberOf(me.user_id).profile, email: memberOf(me.user_id).email, email_verified: memberOf(me.user_id).email_verified });
    }
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
    if (me.workspace_id !== 1) return json(200, []);
    return json(200, CAMPAIGNS.map((c) => campaignView(c, false)).filter((c) => c.size >= 2));
  }

  if ((m = pathname.match(/^\/api\/v1\/campaigns\/(\d+)$/)) && method === 'GET') {
    const spec = me.workspace_id === 1 ? CAMPAIGNS.find((c) => campaignView(c, false).id === Number(m![1]) && campaignView(c, false).size >= 2) : undefined;
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
      .filter(home)
      .filter((a) => !verdict || a.verdict === verdict)
      .filter((a) => !source || a.source === source)
      .filter((a) => user === null || a.submitted_by === Number(user))
      .filter((a) => searchParams.get('disputed') !== 'true' || disputedIds().has(a.id))
      .filter((a) => (!since || a.created_at.slice(0, 10) >= since) && (!until || a.created_at.slice(0, 10) <= until))
      .filter((a) => !q || a.sha256.startsWith(q) || a.report_id.toLowerCase() === q || JSON.stringify(a.report?.iocs ?? []).toLowerCase().includes(q))
      .slice(offset, offset + 50)
      .map(summaryOf);
    return json(200, rows);
  }

  if ((m = pathname.match(/^\/api\/v1\/analyses\/(\d+)$/)) && method === 'GET') {
    const a = analyses.find((x) => x.id === Number(m![1]) && home(x));
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
    const names = new Set(users.filter((u) => memberOf(u.id).workspace_id === me.workspace_id).map((u) => u.username));
    const rows = admin ? audit.filter((e) => names.has(e.actor) || (me.workspace_id === 1 && e.actor === 'system')) : audit.filter((e) => e.actor === me.username);
    return json(200, rows.slice(offset, offset + 100));
  }

  // feedback: to the owner, and on verdicts
  if (pathname === '/api/v1/feedback') {
    if (method === 'GET') return json(200, feedbackRows.filter((f) => me.owner || f.user_id === me.user_id).slice().reverse().map(({ user_id: _u, ...f }) => f));
    const sent = (body ?? {}) as Record<string, unknown>;
    try {
      if (!['bug', 'idea', 'question', 'other'].includes(String(sent.kind))) throw 'kind: bug, idea, question or other';
      const message = freeText('message', sent.message, 4000);
      const page = typeof sent.page === 'string' ? sent.page : '';
      if (page && !/^\/(?!\/)[\x21-\x7e]{0,199}$/.test(page)) throw 'page: a path in this app, such as /app/analyses/3';
      const row = { id: ++lastFeedbackId, kind: sent.kind as Feedback['kind'], message, page, status: 'open' as const, created_at: new Date().toISOString(), username: me.username, workspace: { id: workspace.id, name: workspace.name }, user_id: me.user_id };
      feedbackRows.push(row);
      const { user_id: _u, ...view } = row;
      return json(201, view);
    } catch (refusal) {
      return error(422, 'invalid', String(refusal));
    }
  }
  if (pathname === '/api/v1/feedback/verdicts' && method === 'GET') {
    if (!admin) return error(403, 'forbidden', 'only an admin can do that');
    const mine = answers.filter((a) => workspaceOf(analyses.find((x) => x.id === a.analysis_id)!) === me.workspace_id);
    const disputed = [...new Set(mine.map((a) => a.analysis_id))]
      .map((id) => ({ id, rows: mine.filter((a) => a.analysis_id === id) }))
      .filter(({ rows }) => rows.some((r) => r.opinion !== 'right'))
      .map(({ id, rows }) => {
        const a = analyses.find((x) => x.id === id)!;
        return { analysis_id: id, report_id: a.report_id, verdict: a.verdict, score: a.score, ...countsOf(rows), last_answer_at: rows.map((r) => r.updated_at).sort().at(-1)! };
      });
    return json(200, { counts: countsOf(mine), disputed });
  }
  m = pathname.match(/^\/api\/v1\/feedback\/(\d+)$/);
  if (m) {
    const row = feedbackRows.find((f) => f.id === Number(m![1]) && (me.owner || f.user_id === me.user_id));
    if (!row) return error(404, 'not_found', 'no such feedback');
    if (method === 'DELETE') {
      feedbackRows.splice(feedbackRows.indexOf(row), 1);
      return json(204, null);
    }
    if (!me.owner) return error(403, 'forbidden', "only the server's owner marks feedback done");
    const status = (body as { status?: string } | undefined)?.status;
    if (status !== 'open' && status !== 'done') return error(422, 'invalid', 'status: open or done');
    row.status = status;
    const { user_id: _u, ...view } = row;
    return json(200, view);
  }
  m = pathname.match(/^\/api\/v1\/analyses\/(\d+)\/feedback(?:\/(\d+))?$/);
  if (m) {
    const analysis = analyses.find((a) => a.id === Number(m![1]) && home(a));
    if (!analysis) return error(404, 'not_found', 'no such analysis');
    const here = answers.filter((a) => a.analysis_id === analysis.id);
    const strip = ({ analysis_id: _a, ...view }: VerdictAnswer & { analysis_id: number }) => view;
    if (m[2]) {
      const row = here.find((a) => a.id === Number(m![2]));
      if (!row || method !== 'DELETE') return error(404, 'not_found', 'no such answer');
      if (row.user_id !== me.user_id && !admin) return error(403, 'forbidden', 'only its author or an admin removes an answer');
      answers.splice(answers.indexOf(row), 1);
      return json(204, null);
    }
    const mine = here.find((a) => a.user_id === me.user_id);
    if (method === 'GET') return json(200, { mine: mine ? strip(mine) : null, answers: here.map(strip), counts: countsOf(here) });
    if (method === 'DELETE') {
      if (mine) answers.splice(answers.indexOf(mine), 1);
      return json(204, null);
    }
    const sent = (body ?? {}) as Record<string, unknown>;
    try {
      if (!OPINIONS.includes(sent.opinion as Opinion)) throw 'opinion: right, missed or false_alarm';
      const note = freeText('note', sent.note, 1000, false);
      const now = new Date().toISOString();
      const row = mine ?? { id: ++lastAnswerId, analysis_id: analysis.id, user_id: me.user_id, username: me.username, opinion: 'right' as Opinion, note: '', created_at: now, updated_at: now };
      Object.assign(row, { opinion: sent.opinion as Opinion, note, updated_at: now });
      if (!mine) answers.push(row);
      return json(200, strip(row));
    } catch (refusal) {
      return error(422, 'invalid', String(refusal));
    }
  }

  // the profile: everyone's own
  if (pathname === '/api/v1/me/onboarded' && method === 'POST') {
    const mine = members.get(me.user_id);
    if (mine) mine.onboarded = true;
    return json(204, null);
  }
  if (pathname === '/api/v1/me') {
    const mine = memberOf(me.user_id);
    const view = () => ({ username: me.username, role: me.role, owner: me.owner, profile: mine.profile, workspace, email: mine.email, email_verified: mine.email_verified });
    if (method === 'GET') return json(200, view());
    if (method === 'DELETE') {
      if (me.owner) return error(403, 'forbidden', "the server's owner cannot delete their own account");
      if (workspace.kind !== 'individual') return error(403, 'forbidden', `in an organization its admins delete accounts: ask an admin of ${workspace.name}`);
      // the preview takes any password that is not empty; the server checks it
      if (!(body as { password?: string } | undefined)?.password) return error(403, 'forbidden', 'the current password is not right');
      record(me.username, 'account_delete', 'workspace', workspace.id, { workspace: workspace.id, kind: workspace.kind });
      removeWorkspace(workspace.id);
      session = null;
      return json(204, null);
    }
    const patch = (body ?? {}) as Record<string, string | undefined>;
    try {
      const changes: Partial<Profile> = {};
      for (const f of PROFILE_FIELDS) if (patch[f] !== undefined) changes[f] = clean(f, patch[f], f !== 'job_title');
      let rename: string | null = null;
      if (patch.organization !== undefined) {
        if (!admin || workspace.kind !== 'organization') return error(403, 'forbidden', 'only an admin of an organization can rename it');
        rename = clean('organization', patch.organization);
      }
      const email = patch.email === undefined ? null : cleanEmail(patch.email, false);
      // whoever has the address can reset the password: a new one needs the current password (the preview takes any)
      if (email !== null && !patch.current_password) return error(403, 'forbidden', 'the current password is not right');
      if (patch.password !== undefined) {
        if (patch.password.length < 12) return error(422, 'invalid', 'password: at least 12 characters');
        // the preview takes any current password that is not empty; the server checks it
        if (!patch.current_password) return error(403, 'forbidden', 'the current password is not right');
        record(me.username, 'password_change', 'user', me.user_id);
      }
      Object.assign(mine.profile, changes);
      if (rename) workspace.name = rename;
      if (email !== null && (email !== mine.email || !mine.email_verified)) {
        Object.assign(mine, { email, email_verified: false });
        if (email) sendLink(me.user_id, 'verify'); // unconfirmed until its link is opened
      }
      members.set(me.user_id, mine);
      return json(200, view());
    } catch (refusal) {
      return error(422, 'invalid', String(refusal));
    }
  }

  if (pathname === '/api/v1/server-settings') {
    if (!admin || !me.owner) return error(403, 'forbidden', 'only the server\'s owner can do that');
    if (method === 'GET') return json(200, serverSettings);
    const patch = (body ?? {}) as Partial<ServerSettings>;
    for (const key of ['signup_daily_cap', 'max_upload_mb', 'max_batch_messages', 'daily_messages_organization', 'daily_messages_individual'] as const) {
      const value = patch[key];
      if (value !== undefined && (!Number.isInteger(value) || value < 1 || value > 100000)) return error(422, 'invalid', `${key}: between 1 and 100000`);
    }
    Object.assign(serverSettings, Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined)));
    settings.max_upload_mb = serverSettings.max_upload_mb;
    settings.max_batch_messages = serverSettings.max_batch_messages;
    record(me.username, 'server_settings', '', '', { changed: Object.keys(patch) });
    return json(200, serverSettings);
  }

  if (pathname === '/api/v1/workspaces' || pathname.startsWith('/api/v1/workspaces/')) {
    if (!admin) return adminOnly();
    if (method === 'GET') {
      if (!me.owner) return error(403, 'forbidden', "only the server's owner can do that");
      const listed: WorkspaceSummary[] = workspaces.map((w) => ({ ...w, created_at: workspaceMade.get(w.id) ?? new Date().toISOString(), members: users.filter((u) => memberOf(u.id).workspace_id === w.id).length }));
      return json(200, listed);
    }
    const gone = workspaces.find((w) => `/api/v1/workspaces/${w.id}` === pathname);
    if (method !== 'DELETE' || !gone || !me.owner) return error(404, 'not_found', 'no such workspace');
    if (gone.id === me.workspace_id) return error(409, 'conflict', 'this is your own workspace: it holds your account');
    record(me.username, 'workspace_delete', 'workspace', gone.id, { name: gone.name, kind: gone.kind });
    removeWorkspace(gone.id);
    return json(204, null);
  }

  if (pathname.startsWith('/api/v1/settings') || pathname.startsWith('/api/v1/users') || pathname.startsWith('/api/v1/tokens') || pathname.startsWith('/api/v1/mailboxes') || pathname.startsWith('/api/v1/invites')) {
    if (!admin) return adminOnly();
  }

  if (pathname === '/api/v1/invites') {
    if (method === 'GET') {
      return json(200, invites.filter((i) => i.workspace_id === me.workspace_id && !i.used && Date.parse(i.expires_at) > Date.now()).map(({ token: _t, workspace_id: _w, used: _u, ...view }) => view));
    }
    if (workspace.kind !== 'organization') return error(403, 'forbidden', 'an individual workspace has one member: create an organization to work as a team');
    const { role, note = '' } = (body ?? {}) as { role?: string; note?: string };
    if (role !== 'admin' && role !== 'analyst') return error(422, 'invalid', 'role: admin or analyst');
    if (note.length > 120) return error(422, 'invalid', 'note: 120 characters at most');
    const token = urlToken();
    const invite: MockInvite = { id: invites.length + 1, role, note: note.trim(), created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 7 * 86_400_000).toISOString(), created_by_name: me.username, token, workspace_id: me.workspace_id, used: false };
    invites.push(invite);
    record(me.username, 'invite_create', 'invite', invite.id, { role, note: invite.note });
    const { workspace_id: _w, used: _u, ...made } = invite;
    return json(201, { ...made, link: `/join/${token}` });
  }
  if ((m = pathname.match(/^\/api\/v1\/invites\/(\d+)$/)) && method === 'DELETE') {
    const invite = invites.find((i) => i.id === Number(m![1]) && i.workspace_id === me.workspace_id);
    if (!invite) return error(404, 'not_found', 'no such invitation');
    if (invite.used) return error(409, 'conflict', 'this invitation was used already');
    invite.used = true;
    record(me.username, 'invite_revoke', 'invite', invite.id, { role: invite.role });
    return json(204, null);
  }

  if (pathname === '/api/v1/mailboxes') {
    if (method === 'GET') return json(200, [...mailboxes].sort((a, b) => a.name.localeCompare(b.name)));
    if (method === 'POST') {
      const given = body as { name?: string; kind?: MailboxKind; config?: MailboxConfig; secret?: string; interval_minutes?: number; enabled?: boolean };
      const name = String(given.name ?? '').trim();
      const kind = given.kind;
      if (!name || name.length > 48) return error(422, 'invalid', 'name is required');
      if (kind !== 'imap' && kind !== 'graph' && kind !== 'gmail') return error(422, 'invalid', 'kind must be imap, graph or gmail');
      const interval = given.interval_minutes ?? 5;
      if (!Number.isInteger(interval) || interval < 5 || interval > 1440) return error(422, 'invalid', 'interval must be between 5 and 1440 minutes');
      const config = mailboxConfig(kind, given.config ?? {});
      if (typeof config === 'string') return error(422, 'invalid', config);
      const learnt = mailboxSecret(kind, String(given.secret ?? ''));
      if (typeof learnt === 'string') return error(422, 'invalid', learnt);
      if (mailboxes.some((b) => b.name === name)) return error(409, 'conflict', `a mailbox called '${name}' exists`);
      const made: Mailbox = {
        id: Math.max(0, ...mailboxes.map((b) => b.id)) + 1, name, kind, enabled: given.enabled ?? true, interval_minutes: interval,
        config: { ...config, ...learnt }, secret_set: true, status: 'never', error: '', last_poll_at: null, next_poll_at: null,
        last_counts: {}, created_at: new Date().toISOString(),
      };
      mailboxes.push(made);
      record(me.username, 'mailbox_create', 'mailbox', made.id, { name, kind, config: made.config });
      return json(201, made);
    }
  }
  if ((m = pathname.match(/^\/api\/v1\/mailboxes\/(\d+)(\/poll)?$/))) {
    const found = mailboxes.find((b) => b.id === Number(m![1]));
    if (!found) return error(404, 'not_found', 'no such mailbox');
    if (m[2] && method === 'POST') {
      if (!found.enabled) return error(409, 'conflict', 'the mailbox is switched off: switch it on first');
      record(me.username, 'mailbox_poll_now', 'mailbox', found.id, { name: found.name, queued: true });
      found.last_poll_at = new Date().toISOString();
      if (found.status === 'error') {
        found.next_poll_at = minutesFromNow(60);
        found.last_counts = { imported: 0, duplicates: 0, skipped: 0 };
        record('system', 'mailbox_poll_failed', 'mailbox', found.id, { name: found.name, reason: found.error });
      } else {
        const copy: Analysis = structuredClone(analyses.find((a) => a.source === 'upload') ?? analyses[0]);
        Object.assign(copy, { id: nextAnalysis++, source: 'mailbox', submitted_by: null, submitted_by_name: found.name, created_at: new Date().toISOString() });
        analyses.unshift(copy);
        record(`mailbox:${found.name}`, 'submit', 'submission', copy.submission_id, { sha256: copy.sha256, source: 'mailbox', mailbox: found.id });
        Object.assign(found, { status: 'ok', error: '', next_poll_at: minutesFromNow(found.interval_minutes), last_counts: { imported: 1, duplicates: 0, skipped: 0 } });
      }
      return json(202, { queued: true });
    }
    if (!m[2] && method === 'GET') return json(200, found);
    if (!m[2] && method === 'PATCH') {
      const patch = body as { name?: string; config?: MailboxConfig; secret?: string; interval_minutes?: number; enabled?: boolean; kind?: string };
      if (patch.kind && patch.kind !== found.kind) return error(422, 'invalid', 'a mailbox keeps its kind: add another mailbox for another kind');
      const changed: string[] = [];
      if (patch.interval_minutes !== undefined) {
        if (!Number.isInteger(patch.interval_minutes) || patch.interval_minutes < 5 || patch.interval_minutes > 1440) return error(422, 'invalid', 'interval must be between 5 and 1440 minutes');
        if (patch.interval_minutes !== found.interval_minutes) changed.push('interval_minutes');
      }
      let config = found.config;
      if (patch.config) {
        const next = mailboxConfig(found.kind, { ...found.config, ...patch.config });
        if (typeof next === 'string') return error(422, 'invalid', next);
        config = { ...next, ...(found.config.service_account ? { service_account: found.config.service_account } : {}) };
        changed.push(...Object.keys(next).filter((k) => next[k as keyof MailboxConfig] !== found.config[k as keyof MailboxConfig]));
      }
      let learnt: MailboxConfig = {};
      if (patch.secret) {
        const result = mailboxSecret(found.kind, patch.secret);
        if (typeof result === 'string') return error(422, 'invalid', result);
        learnt = result;
        changed.push('secret');
      }
      const name = patch.name?.trim();
      if (name !== undefined && name !== found.name) {
        if (!name || name.length > 48) return error(422, 'invalid', 'name is required');
        if (mailboxes.some((b) => b.name === name && b.id !== found.id)) return error(409, 'conflict', `a mailbox called '${name}' exists`);
        found.name = name;
        changed.push('name');
      }
      if (patch.enabled !== undefined && patch.enabled !== found.enabled) {
        found.enabled = patch.enabled;
        changed.push('enabled');
      }
      if (patch.interval_minutes !== undefined) found.interval_minutes = patch.interval_minutes;
      found.config = { ...config, ...learnt };
      if (patch.secret) Object.assign(found, { status: found.status === 'error' ? 'never' : found.status, error: '', next_poll_at: null });
      record(me.username, 'mailbox_change', 'mailbox', found.id, { name: found.name, changed });
      return json(200, found);
    }
    if (!m[2] && method === 'DELETE') {
      mailboxes.splice(mailboxes.indexOf(found), 1);
      record(me.username, 'mailbox_delete', 'mailbox', found.id, { name: found.name });
      return json(200, { deleted: true });
    }
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
    if (method === 'GET') return json(200, users.filter((u) => memberOf(u.id).workspace_id === me.workspace_id));
    if (method === 'POST' && workspace.kind === 'individual') return error(403, 'forbidden', 'an individual workspace has one member: create an organization to work as a team');
    if (method === 'POST') {
      const { username, password, role } = body as { username: string; password: string; role: 'admin' | 'analyst' };
      if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username)) return error(422, 'invalid', 'usernames are 3 to 64 lowercase letters, digits, dots, dashes or underscores');
      if (!password || password.length < 12) return error(422, 'invalid', 'passwords need at least 12 characters');
      if (users.some((u) => u.username === username)) return error(422, 'invalid', 'that username is taken');
      const user = addMember(username, role, me.workspace_id, { ...blank }, false);
      user.last_login_at = null;
      record(me.username, 'user_create', 'user', user.id, { username, role });
      return json(201, user);
    }
  }
  if ((m = pathname.match(/^\/api\/v1\/users\/(\d+)$/)) && method === 'DELETE') {
    const user = users.find((u) => u.id === Number(m![1]) && memberOf(u.id).workspace_id === me.workspace_id);
    if (!user) return error(404, 'not_found', 'no such user');
    if (user.id === me.user_id) return error(422, 'invalid', 'you cannot delete yourself');
    if (memberOf(user.id).owner) return error(403, 'forbidden', "the server's owner cannot be deleted");
    record(me.username, 'user_delete', 'user', user.id, { username: user.username, role: user.role });
    removeUser(user.id);
    return json(204, null);
  }
  if ((m = pathname.match(/^\/api\/v1\/users\/(\d+)$/)) && method === 'PATCH') {
    const user = users.find((u) => u.id === Number(m![1]) && memberOf(u.id).workspace_id === me.workspace_id);
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
