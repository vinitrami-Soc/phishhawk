import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analysisActions } from '../app/permissions';

const admin = { role: 'admin' as const, user_id: 1 };
const alice = { role: 'analyst' as const, user_id: 2 };
const bob = { role: 'analyst' as const, user_id: 3 };
const open = { submitted_by: 2, hold: false, tier1_deleted_at: null };

test('an analyst on their own message', () => {
  assert.deepEqual(analysisActions(alice, open), {
    reanalyze: true, downloads: true, reportFrame: true, rawMessage: true,
    deleteNow: true, deleteCompletely: false, hold: false, release: false,
  });
});

test("an analyst on someone else's message: no raw message, no delete", () => {
  const actions = analysisActions(bob, open);
  assert.equal(actions.rawMessage, false);
  assert.equal(actions.deleteNow, false);
  assert.equal(actions.reanalyze, true);
  assert.equal(actions.downloads, true);
});

test('an admin can do everything on an open message except release it', () => {
  assert.deepEqual(analysisActions(admin, open), {
    reanalyze: true, downloads: true, reportFrame: true, rawMessage: true,
    deleteNow: true, deleteCompletely: true, hold: true, release: false,
  });
});

test('a held message shows no delete controls, and only an admin can release it', () => {
  const held = { ...open, hold: true };
  const forAdmin = analysisActions(admin, held);
  assert.equal(forAdmin.deleteNow, false);
  assert.equal(forAdmin.deleteCompletely, false);
  assert.equal(forAdmin.hold, false);
  assert.equal(forAdmin.release, true);
  assert.equal(analysisActions(alice, held).deleteNow, false);
  assert.equal(analysisActions(alice, held).release, false);
});

test('after "Delete now" only the verdict and record remain', () => {
  const deleted = { ...open, tier1_deleted_at: '2026-10-08T10:00:00+00:00' };
  for (const session of [admin, alice]) {
    assert.deepEqual(analysisActions(session, deleted), {
      reanalyze: false, downloads: false, reportFrame: false, rawMessage: false,
      deleteNow: false, deleteCompletely: false, hold: false, release: false,
    });
  }
});

test('a message with no submitter (token or system) is nobody\'s own', () => {
  const noOwner = { ...open, submitted_by: null };
  assert.equal(analysisActions({ role: 'analyst', user_id: null }, noOwner).rawMessage, false);
  assert.equal(analysisActions({ role: 'analyst', user_id: null }, noOwner).deleteNow, false);
});
