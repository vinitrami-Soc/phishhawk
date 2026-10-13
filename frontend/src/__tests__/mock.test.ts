import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mockFetch } from '../mocks/mockTransport';

/* The development mock: no password hassle while building the frontend, and
   still the server's contract (CSRF, 401, 429, 422). */

let csrf = '';

async function call(method: string, url: string, body?: unknown) {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrf && method !== 'GET' && url !== '/api/v1/session') headers['X-CSRF-Token'] = csrf;
  if (csrf && method === 'DELETE') headers['X-CSRF-Token'] = csrf;
  const res = await mockFetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, retryAfter: res.headers.get('Retry-After'), body: res.status === 204 ? null : await res.json() };
}

async function signIn(username: string, password: string) {
  const res = await call('POST', '/api/v1/session', { username, password });
  if (res.status === 200) csrf = res.body.csrf;
  return res;
}

test('the preview starts signed in as an admin, with no sign-in screen', async () => {
  const res = await call('GET', '/api/v1/session');
  assert.equal(res.status, 200);
  assert.equal(res.body.role, 'admin');
  csrf = res.body.csrf;
});

test('after signing out, an existing user signs in with any password', async () => {
  assert.equal((await call('DELETE', '/api/v1/session')).status, 204);
  assert.equal((await call('GET', '/api/v1/session')).status, 401);
  const res = await signIn('alice', 'x');
  assert.equal(res.status, 200);
  assert.equal((await call('GET', '/api/v1/session')).body.role, 'analyst');
  await call('DELETE', '/api/v1/session');
});

test('an unknown user is refused; three refusals throttle for 8 seconds, then it lets go', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    for (let i = 0; i < 3; i++) assert.equal((await signIn('nobody', 'x')).status, 401);
    const throttled = await signIn('boss', 'x');
    assert.equal(throttled.status, 429);
    assert.equal(throttled.retryAfter, '8');
    now += 8_001;
    assert.equal((await signIn('boss', 'x')).status, 200);
  } finally {
    Date.now = realNow;
  }
});

test('a user created on the Users screen can sign in', async () => {
  const bad = await call('POST', '/api/v1/users', { username: 'New User', password: 'long-enough-password', role: 'analyst' });
  assert.equal(bad.status, 422);
  assert.match(bad.body.detail, /lowercase/);
  const made = await call('POST', '/api/v1/users', { username: 'carol', password: 'long-enough-password', role: 'analyst' });
  assert.equal(made.status, 201);
  await call('DELETE', '/api/v1/session');
  assert.equal((await signIn('carol', 'anything')).status, 200);
  assert.equal((await call('GET', '/api/v1/session')).body.username, 'carol');
});

test('several files are one batch, which finishes with combined reports', async () => {
  csrf = (await signIn('boss', 'x')).body.csrf;
  const form = new FormData();
  form.append('files', new File(['From: a@b.example\r\n'], 'one.eml'));
  form.append('files', new File(['From: c@d.example\r\n'], 'two.eml'));
  form.append('offline', 'true');
  const sent = await mockFetch('/api/v1/submissions', { method: 'POST', headers: { 'X-CSRF-Token': csrf }, body: form });
  assert.equal(sent.status, 202);
  const created = await sent.json();
  assert.equal(created.total, 2);
  assert.equal(created.submission_ids.length, 2);
  const realNow = Date.now;
  const later = realNow() + 60_000;
  Date.now = () => later;
  try {
    const batch = (await call('GET', `/api/v1/batches/${created.batch_id}`)).body;
    assert.equal(batch.status, 'done');
    assert.equal(batch.counts.done, 2);
    assert.ok(batch.messages.every((m: { analysis_id: number | null }) => m.analysis_id));
    assert.deepEqual(batch.files.map((f: { kind: string }) => f.kind), ['json', 'stix', 'misp', 'md', 'csv', 'html', 'manifest']);
  } finally {
    Date.now = realNow;
  }
});

test('one file is not a batch', async () => {
  const form = new FormData();
  form.append('files', new File(['From: a@b.example\r\n'], 'one.eml'));
  const sent = await mockFetch('/api/v1/submissions', { method: 'POST', headers: { 'X-CSRF-Token': csrf }, body: form });
  assert.equal((await sent.json()).batch_id, null);
});

test('campaigns: a list, and each one with its messages', async () => {
  const list = (await call('GET', '/api/v1/campaigns')).body;
  assert.ok(list.length >= 1);
  assert.ok(list.every((c: { shared: { kind: string; value: string | null }[] }) =>
    c.shared.every((s) => !['subject', 'display name'].includes(s.kind) || s.value === null)));
  const detail = (await call('GET', `/api/v1/campaigns/${list[0].id}`)).body;
  assert.equal(detail.messages.length, detail.size);
  assert.equal(typeof detail.recipients_complete, 'boolean');
  assert.equal((await call('GET', '/api/v1/campaigns/999999')).status, 404);
});

test('the queue filters by source and by who submitted', async () => {
  const batch = (await call('GET', '/api/v1/analyses?source=batch')).body;
  assert.ok(batch.length >= 2 && batch.every((a: { source: string }) => a.source === 'batch'));
  const none = (await call('GET', '/api/v1/analyses?user=999')).body;
  assert.deepEqual(none, []);
  assert.equal((await call('GET', '/api/v1/analyses?since=yesterday')).status, 422);
});

test('mailboxes: listed without their credentials, added, changed, polled and deleted', async () => {
  const listed = (await call('GET', '/api/v1/mailboxes')).body;
  assert.ok(listed.length >= 2);
  assert.ok(listed.every((m: { secret_set: boolean }) => m.secret_set === true && !('secret' in m)));
  assert.ok(listed.some((m: { status: string; error: string }) => m.status === 'error' && m.error));

  const refused = await call('POST', '/api/v1/mailboxes', { name: 'X', kind: 'imap', secret: 'pw', config: { host: 'imaps://imap.example.com', user: 'soc' } });
  assert.equal(refused.status, 422);
  assert.match(refused.body.detail, /host/);
  const secret = 'app-password-for-the-preview';
  const made = await call('POST', '/api/v1/mailboxes', { name: 'Reports', kind: 'imap', secret, config: { host: 'imap.example-corp.co.uk', user: 'soc' } });
  assert.equal(made.status, 201);
  assert.equal(made.body.config.port, 993);
  assert.equal(made.body.status, 'never');
  assert.ok(!JSON.stringify(made.body).includes(secret));
  assert.equal((await call('POST', '/api/v1/mailboxes', { name: 'Reports', kind: 'imap', secret, config: { host: 'imap.example-corp.co.uk', user: 'soc' } })).status, 409);

  const id = made.body.id;
  assert.equal((await call('PATCH', `/api/v1/mailboxes/${id}`, { interval_minutes: 15 })).body.interval_minutes, 15);
  assert.equal((await call('PATCH', `/api/v1/mailboxes/${id}`, { interval_minutes: 4 })).status, 422);
  assert.deepEqual((await call('POST', `/api/v1/mailboxes/${id}/poll`)).body, { queued: true });
  const polled = (await call('GET', '/api/v1/mailboxes')).body.find((m: { id: number }) => m.id === id);
  assert.equal(polled.status, 'ok');
  assert.equal(polled.last_counts.imported, 1);
  const imported = (await call('GET', '/api/v1/analyses?source=mailbox')).body;
  assert.ok(imported.some((a: { submitted_by_name: string }) => a.submitted_by_name === 'Reports'));

  await call('PATCH', `/api/v1/mailboxes/${id}`, { enabled: false });
  assert.equal((await call('POST', `/api/v1/mailboxes/${id}/poll`)).status, 409);
  assert.equal((await call('DELETE', `/api/v1/mailboxes/${id}`)).status, 200);
  assert.ok(!(await call('GET', '/api/v1/mailboxes')).body.some((m: { id: number }) => m.id === id));
  assert.equal((await call('POST', `/api/v1/mailboxes/${id}/poll`)).status, 404);
});

const PERSON = { username: 'sam', password: 'long-enough-password', first_name: 'Sam', last_name: 'Lee', location: 'Leeds', organization: '', job_title: '' };

test('the preview is set up already, and anyone may create an account in it', async () => {
  assert.deepEqual((await call('GET', '/api/v1/setup')).body, { open: false });
  assert.equal((await call('POST', '/api/v1/setup', { code: 'ABCD-EFGH-JKLM-NPQR' })).status, 404);
  assert.deepEqual((await call('GET', '/api/v1/signup')).body, { open: true });
  const me = (await call('GET', '/api/v1/session')).body;
  assert.deepEqual([me.owner, me.workspace.name, me.workspace.kind], [true, 'Example Corp', 'organization']);
});

test('an individual signs up without a CSRF token, and works alone', async () => {
  await call('DELETE', '/api/v1/session');
  csrf = '';
  const bad = await call('POST', '/api/v1/signup', { ...PERSON, kind: 'individual', last_name: ' ' });
  assert.equal(bad.status, 422);
  assert.match(bad.body.detail, /^last_name: /);
  assert.equal((await call('POST', '/api/v1/signup', { ...PERSON, kind: 'organization' })).status, 422);
  assert.equal((await call('POST', '/api/v1/signup', { ...PERSON, kind: 'individual', username: 'alice' })).status, 409);
  const made = await call('POST', '/api/v1/signup', { ...PERSON, kind: 'individual' });
  assert.equal(made.status, 201);
  csrf = made.body.csrf;
  const me = (await call('GET', '/api/v1/session')).body;
  assert.deepEqual([me.username, me.role, me.owner, me.workspace.kind, me.workspace.name], ['sam', 'admin', false, 'individual', 'Sam Lee']);
  assert.deepEqual(me.profile, { first_name: 'Sam', last_name: 'Lee', location: 'Leeds', job_title: '' });
  assert.deepEqual((await call('GET', '/api/v1/analyses')).body, []);
  assert.deepEqual((await call('GET', '/api/v1/campaigns')).body, []);
  assert.deepEqual((await call('GET', '/api/v1/users')).body.map((u: { username: string }) => u.username), ['sam']);
  assert.equal((await call('POST', '/api/v1/invites', { role: 'analyst', note: '' })).status, 403);
  assert.equal((await call('POST', '/api/v1/users', { username: 'friend', password: 'long-enough-password', role: 'analyst' })).status, 403);
  assert.equal((await call('GET', '/api/v1/server-settings')).status, 403);
});

test('an organization admin invites, and the person joins with that role, once', async () => {
  await call('DELETE', '/api/v1/session');
  csrf = (await signIn('boss', 'x')).body.csrf;
  const invite = await call('POST', '/api/v1/invites', { role: 'analyst', note: 'for Priya' });
  assert.equal(invite.status, 201);
  const { token } = invite.body;
  assert.ok(token.length >= 40);
  const pending = (await call('GET', '/api/v1/invites')).body;
  assert.deepEqual(pending.map((i: { note: string }) => i.note), ['for Priya']);
  assert.ok(!JSON.stringify(pending).includes(token));
  await call('DELETE', '/api/v1/session');
  csrf = '';
  assert.deepEqual((await call('GET', `/api/v1/join/${token}`)).body, { organization: 'Example Corp', role: 'analyst' });
  const joined = await call('POST', `/api/v1/join/${token}`, { ...PERSON, username: 'priya' });
  assert.equal(joined.status, 201);
  csrf = joined.body.csrf;
  const me = (await call('GET', '/api/v1/session')).body;
  assert.deepEqual([me.username, me.role, me.workspace.name], ['priya', 'analyst', 'Example Corp']);
  assert.equal((await call('GET', `/api/v1/join/${token}`)).status, 404);
  assert.equal((await call('GET', '/api/v1/join/not-a-token')).status, 404);
});

test('everyone edits their own profile; the owner alone sets the server', async () => {
  const changed = await call('PATCH', '/api/v1/me', { first_name: 'Priya', job_title: 'Analyst' });
  assert.equal(changed.status, 200);
  assert.deepEqual([changed.body.profile.first_name, changed.body.profile.job_title], ['Priya', 'Analyst']);
  assert.equal((await call('GET', '/api/v1/session')).body.profile.first_name, 'Priya');
  assert.equal((await call('PATCH', '/api/v1/me', { organization: 'Renamed' })).status, 403);
  assert.equal((await call('PATCH', '/api/v1/me', { last_name: '' })).status, 422);
  assert.equal((await call('PATCH', '/api/v1/me', { password: 'another long password', current_password: '' })).status, 403);
  await call('DELETE', '/api/v1/session');
  csrf = (await signIn('boss', 'x')).body.csrf;
  assert.deepEqual((await call('GET', '/api/v1/server-settings')).body, { signup_open: true, signup_daily_cap: 100, max_upload_mb: 25, max_batch_messages: 500 });
  assert.equal((await call('PATCH', '/api/v1/server-settings', { signup_open: false })).body.signup_open, false);
  assert.deepEqual((await call('GET', '/api/v1/signup')).body, { open: false });
  assert.equal((await call('PATCH', '/api/v1/server-settings', { signup_daily_cap: 0 })).status, 422);
  await call('PATCH', '/api/v1/server-settings', { signup_open: true });
  assert.equal((await call('PATCH', '/api/v1/me', { organization: 'Example Corp Ltd' })).body.workspace.name, 'Example Corp Ltd');
});

test('the setup after sign-up opens once: a new account has it, the preview account does not', async () => {
  assert.equal((await call('GET', '/api/v1/session')).body.onboarded, true); // boss
  await call('DELETE', '/api/v1/session');
  csrf = '';
  const made = await call('POST', '/api/v1/signup', { ...PERSON, username: 'noor', kind: 'individual' });
  assert.equal(made.status, 201);
  csrf = made.body.csrf;
  assert.equal((await call('GET', '/api/v1/session')).body.onboarded, false);
  assert.equal((await call('POST', '/api/v1/me/onboarded')).status, 204);
  assert.equal((await call('GET', '/api/v1/session')).body.onboarded, true);
});
