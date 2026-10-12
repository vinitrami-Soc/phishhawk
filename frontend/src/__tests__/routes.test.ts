import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PUBLIC_ROUTES, pageTitle, parseRoute } from '../app/routes';

test('the app routes under /app/', () => {
  assert.deepEqual(parseRoute('/app/'), { name: 'triage' });
  assert.deepEqual(parseRoute('/app'), { name: 'triage' });
  assert.deepEqual(parseRoute('/'), { name: 'triage' });
  assert.deepEqual(parseRoute('/app/analyses'), { name: 'queue' });
  assert.deepEqual(parseRoute('/app/analyses/'), { name: 'queue' });
  assert.deepEqual(parseRoute('/app/analyses/6'), { name: 'analysis', id: 6 });
  for (const name of ['audit', 'health', 'settings', 'users', 'tokens', 'login', 'privacy', 'help'] as const) {
    assert.deepEqual(parseRoute(`/app/${name}`), { name });
  }
});

test('an analysis id is digits only; anything else is not found', () => {
  for (const path of ['/app/analyses/6a', '/app/analyses/-1', '/app/analyses/1.5', '/app/analyses/%31', '/app/nope', '/elsewhere']) {
    assert.deepEqual(parseRoute(path), { name: 'not-found' }, path);
  }
});

test('privacy and help can be read before signing in; nothing else can', () => {
  assert.deepEqual([...PUBLIC_ROUTES].sort(), ['help', 'privacy']);
});

test('every page has its own title', () => {
  assert.equal(pageTitle({ name: 'triage' }, true), 'Triage · PhishHawk');
  assert.equal(pageTitle({ name: 'analysis', id: 42 }, true), 'Analysis 42 · PhishHawk');
  assert.equal(pageTitle({ name: 'tokens' }, true), 'API tokens · PhishHawk');
  assert.equal(pageTitle({ name: 'not-found' }, true), 'Page not found · PhishHawk');
  assert.equal(pageTitle({ name: 'privacy' }, false), 'Privacy and terms · PhishHawk');
  assert.equal(pageTitle({ name: 'help' }, false), 'Help · PhishHawk');
  // signed out, every other page is the sign-in page
  assert.equal(pageTitle({ name: 'queue' }, false), 'Sign in · PhishHawk');
});
