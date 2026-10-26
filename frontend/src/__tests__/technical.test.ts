import assert from 'node:assert/strict';
import { test } from 'node:test';
import { rememberForTab, switchable, tabChoice, technicalView } from '../app/technical';

const organization = { workspace: { id: 1, name: 'Ana Labs', kind: 'organization' as const } };
const individual = { workspace: { id: 2, name: 'noor', kind: 'individual' as const } };
const older = { workspace: null };

test('an organization always sees the technical pages, with no switch', () => {
  assert.equal(switchable(organization), false);
  assert.equal(technicalView(organization, false), true);
  assert.equal(technicalView(organization, true), true);
});

test('a session without a workspace (an older server) sees the technical pages', () => {
  assert.equal(switchable(older), false);
  assert.equal(technicalView(older, false), true);
});

test('someone on their own sees the simple pages until they turn the switch on', () => {
  assert.equal(switchable(individual), true);
  assert.equal(technicalView(individual, false), false);
  assert.equal(technicalView(individual, true), true);
});

test("the tab's choice starts off and keeps what was last remembered", () => {
  assert.equal(tabChoice(), false);
  rememberForTab(true);
  assert.equal(tabChoice(), true);
  rememberForTab(false);
  assert.equal(tabChoice(), false);
});
