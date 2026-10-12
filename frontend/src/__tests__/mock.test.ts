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
