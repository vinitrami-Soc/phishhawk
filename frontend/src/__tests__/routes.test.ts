import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ADMIN_ONLY, PUBLIC_ROUTES, pageTitle, parseRoute, signedOutView } from '../app/routes';

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

test('batches and campaigns have pages of their own', () => {
  assert.deepEqual(parseRoute('/app/batches/7'), { name: 'batch', id: 7 });
  assert.deepEqual(parseRoute('/app/campaigns'), { name: 'campaigns' });
  assert.deepEqual(parseRoute('/app/campaigns/12/'), { name: 'campaign', id: 12 });
  for (const path of ['/app/batches', '/app/batches/x', '/app/campaigns/-3']) {
    assert.deepEqual(parseRoute(path), { name: 'not-found' }, path);
  }
  assert.equal(pageTitle({ name: 'batch', id: 7 }, true), 'Batch 7 · PhishHawk');
  assert.equal(pageTitle({ name: 'campaigns' }, true), 'Campaigns · PhishHawk');
  assert.equal(pageTitle({ name: 'campaign', id: 12 }, true), 'Campaign 12 · PhishHawk');
});

test('mailboxes have a page of their own, for admins only', () => {
  assert.deepEqual(parseRoute('/app/mailboxes'), { name: 'mailboxes' });
  assert.deepEqual(parseRoute('/app/mailboxes/'), { name: 'mailboxes' });
  assert.deepEqual(parseRoute('/app/mailboxes/3'), { name: 'not-found' });
  assert.ok(ADMIN_ONLY.includes('mailboxes'));
  assert.equal(pageTitle({ name: 'mailboxes' }, true), 'Mailboxes · PhishHawk');
});

test('an analysis id is digits only; anything else is not found', () => {
  for (const path of ['/app/analyses/6a', '/app/analyses/-1', '/app/analyses/1.5', '/app/analyses/%31', '/app/nope', '/elsewhere']) {
    assert.deepEqual(parseRoute(path), { name: 'not-found' }, path);
  }
});

test('the product page, privacy and help can be read before signing in; nothing else can', () => {
  assert.deepEqual([...PUBLIC_ROUTES].sort(), ['about', 'help', 'privacy']);
});

test('the product page has an address of its own', () => {
  assert.deepEqual(parseRoute('/app/about'), { name: 'about' });
  assert.deepEqual(parseRoute('/app/about/'), { name: 'about' });
  assert.deepEqual(parseRoute('/app/about/x'), { name: 'not-found' });
});

test('signed out, the start page is the product page and every private page asks to sign in', () => {
  assert.equal(signedOutView(parseRoute('/')), 'landing');
  assert.equal(signedOutView(parseRoute('/app/')), 'landing');
  assert.equal(signedOutView(parseRoute('/app/about')), 'landing');
  assert.equal(signedOutView(parseRoute('/app/privacy')), 'public');
  assert.equal(signedOutView(parseRoute('/app/help')), 'public');
  for (const path of ['/app/login', '/app/analyses', '/app/analyses/6', '/app/users', '/app/campaigns/2', '/app/nope']) {
    assert.equal(signedOutView(parseRoute(path)), 'login', path);
  }
});

test('every page has its own title', () => {
  assert.equal(pageTitle({ name: 'triage' }, true), 'Triage · PhishHawk');
  assert.equal(pageTitle({ name: 'analysis', id: 42 }, true), 'Analysis 42 · PhishHawk');
  assert.equal(pageTitle({ name: 'tokens' }, true), 'API tokens · PhishHawk');
  assert.equal(pageTitle({ name: 'not-found' }, true), 'Page not found · PhishHawk');
  assert.equal(pageTitle({ name: 'privacy' }, false), 'Privacy and terms · PhishHawk');
  assert.equal(pageTitle({ name: 'help' }, false), 'Help · PhishHawk');
  assert.equal(pageTitle({ name: 'about' }, true), 'Phishing email triage · PhishHawk');
  // signed out, the start page is the product page and every private page is the sign-in page
  assert.equal(pageTitle({ name: 'triage' }, false), 'Phishing email triage · PhishHawk');
  assert.equal(pageTitle({ name: 'about' }, false), 'Phishing email triage · PhishHawk');
  assert.equal(pageTitle({ name: 'queue' }, false), 'Sign in · PhishHawk');
  assert.equal(pageTitle({ name: 'login' }, false), 'Sign in · PhishHawk');
});

test('setup, sign-up and joining are reached signed out; the profile signed in', () => {
  const token = 'Ab3_-'.repeat(9);
  assert.deepEqual(parseRoute('/app/setup'), { name: 'setup' });
  assert.deepEqual(parseRoute('/app/signup/'), { name: 'signup' });
  assert.deepEqual(parseRoute('/app/profile'), { name: 'profile' });
  assert.deepEqual(parseRoute(`/app/join/${token}`), { name: 'join', token });
  for (const path of ['/app/join', '/app/join/short', '/app/join/a%20b', `/app/join/${token}/x`, `/app/join/${'a'.repeat(129)}`]) {
    assert.deepEqual(parseRoute(path), { name: 'not-found' }, path);
  }
  for (const path of ['/app/setup', '/app/signup', `/app/join/${token}`]) {
    assert.equal(signedOutView(parseRoute(path)), 'account', path);
  }
  assert.equal(signedOutView(parseRoute('/app/profile')), 'login');
  assert.equal(pageTitle({ name: 'setup' }, false), 'Set up PhishHawk · PhishHawk');
  assert.equal(pageTitle({ name: 'signup' }, false), 'Create an account · PhishHawk');
  assert.equal(pageTitle({ name: 'join', token }, false), 'Join an organization · PhishHawk');
  assert.equal(pageTitle({ name: 'profile' }, true), 'Your profile · PhishHawk');
  assert.equal(pageTitle({ name: 'profile' }, false), 'Sign in · PhishHawk');
});

test('a forgotten password: the page that asks for a link, and the two pages links in mail open', () => {
  const token = 'Ab3_-'.repeat(9);
  assert.deepEqual(parseRoute('/app/forgot'), { name: 'forgot' });
  assert.deepEqual(parseRoute(`/app/reset/${token}`), { name: 'reset', token });
  assert.deepEqual(parseRoute(`/app/verify-email/${token}/`), { name: 'verify-email', token });
  for (const path of ['/app/reset', '/app/reset/short', `/app/reset/${token}/x`, '/app/verify-email/a%20b', `/app/verify-email/${'a'.repeat(129)}`]) {
    assert.deepEqual(parseRoute(path), { name: 'not-found' }, path);
  }
  for (const path of ['/app/forgot', `/app/reset/${token}`, `/app/verify-email/${token}`]) {
    assert.equal(signedOutView(parseRoute(path)), 'account', path);
  }
  assert.equal(pageTitle({ name: 'forgot' }, false), 'Forgot your password · PhishHawk');
  assert.equal(pageTitle({ name: 'reset', token }, false), 'Choose a new password · PhishHawk');
  assert.equal(pageTitle({ name: 'verify-email', token }, false), 'Confirm your email · PhishHawk');
  assert.equal(pageTitle({ name: 'verify-email', token }, true), 'Confirm your email · PhishHawk');
});

test('the setup after sign-up has a page of its own, signed in', () => {
  assert.deepEqual(parseRoute('/app/welcome'), { name: 'welcome' });
  assert.equal(signedOutView(parseRoute('/app/welcome')), 'login');
  assert.equal(pageTitle({ name: 'welcome' }, true), 'Welcome · PhishHawk');
});

test('feedback has a page of its own, signed in', () => {
  assert.deepEqual(parseRoute('/app/feedback'), { name: 'feedback' });
  assert.equal(signedOutView(parseRoute('/app/feedback')), 'login');
  assert.equal(pageTitle({ name: 'feedback' }, true), 'Feedback · PhishHawk');
});
