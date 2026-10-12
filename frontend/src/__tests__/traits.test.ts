import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sharedTrait } from '../lib/traits';

/* What links a campaign's messages, as the pages show it: defanged like every indicator, and a subject or display
   name the server no longer reveals as "Same subject". */

test('web addresses and senders are defanged; hashes and phones are shown as they are', () => {
  assert.deepEqual(sharedTrait({ kind: 'domain', value: 'evil-portal.example', messages: 3 }), { label: 'Domain', value: 'evil-portal[.]example' });
  assert.deepEqual(sharedTrait({ kind: 'link', value: 'https://login.evil.example/a', messages: 2 }).value, 'hxxps://login[.]evil[.]example/a');
  assert.equal(sharedTrait({ kind: 'sender', value: 'boss@evil.example', messages: 2 }).value, 'boss[@]evil[.]example');
  assert.equal(sharedTrait({ kind: 'originating IP', value: '45.148.10.77', messages: 2 }).value, '45[.]148[.]10[.]77');
  assert.equal(sharedTrait({ kind: 'attachment', value: 'ab'.repeat(32), messages: 2 }).value, 'ab'.repeat(32));
});

test('a hidden subject or display name reads "Same ..."', () => {
  assert.deepEqual(sharedTrait({ kind: 'subject', value: null, messages: 2 }), { label: 'Subject', value: null, hidden: 'Same subject' });
  assert.equal(sharedTrait({ kind: 'display name', value: null, messages: 2 }).hidden, 'Same display name');
  assert.equal(sharedTrait({ kind: 'subject', value: 'payroll update', messages: 2 }).value, 'payroll update');
});

test('a kind the app does not know is shown as plain text under its own name', () => {
  assert.deepEqual(sharedTrait({ kind: 'something new', value: 'x.example', messages: 2 }), { label: 'something new', value: 'x.example' });
});
