import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normaliseDomain, parseLimit } from '../lib/validate';

/* The same rules as the server (PATCH /api/v1/settings answers 422 otherwise),
   so a mistake is shown next to the field instead of after saving. */

test('a domain is kept as the server keeps it: lower case, IDNA, no final dot', () => {
  assert.equal(normaliseDomain(' Example.COM. '), 'example.com');
  assert.equal(normaliseDomain('bücher.example'), 'xn--bcher-kva.example');
  assert.equal(normaliseDomain('mail.example.co.uk'), 'mail.example.co.uk');
});

test('anything that is not a domain is refused', () => {
  for (const bad of ['', '   ', 'not a domain', 'https://example.com/', 'example', '-bad.example', 'a..example', 'user@example.com', '192.0.2.1', 'example.com/path']) {
    assert.equal(normaliseDomain(bad), null, bad);
  }
});

test('a limit is a whole number from 1 to 100000', () => {
  assert.equal(parseLimit('30'), 30);
  assert.equal(parseLimit(' 100000 '), 100000);
  for (const bad of ['', '0', '100001', '-5', '2.5', '1e3', 'ten']) {
    assert.equal(parseLimit(bad), null, bad);
  }
});

test('a refusal that names its field is shown next to that field', async () => {
  const { fieldOf } = await import('../api/errors');
  assert.deepEqual(fieldOf('last_name: required'), { field: 'last_name', message: 'Required.' });
  assert.deepEqual(fieldOf('username: that username is taken'), { field: 'username', message: 'That username is taken.' });
  assert.deepEqual(fieldOf('password: at least 12 characters'), { field: 'password', message: 'At least 12 characters.' });
  // a colon alone does not make a field: only the account form's own names do
  assert.deepEqual(fieldOf('too many attempts: wait 3 s'), { field: null, message: 'too many attempts: wait 3 s' });
  assert.deepEqual(fieldOf('that setup code is not right'), { field: null, message: 'that setup code is not right' });
});
