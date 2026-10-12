import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatBytes, formatDateTime, formatRelative } from '../lib/format';

test('a server timestamp reads as a date and time, not ISO', () => {
  assert.equal(formatDateTime('2026-10-06T17:04:15+00:00', 'UTC'), '6 Oct 2026, 17:04');
  assert.equal(formatDateTime('2026-10-06T17:04:15Z', 'Asia/Kolkata'), '6 Oct 2026, 22:34');
});

test('a missing or unreadable timestamp never shows "Invalid Date"', () => {
  assert.equal(formatDateTime(null), '');
  assert.equal(formatDateTime(''), '');
  assert.equal(formatDateTime('not a date'), 'not a date');
});

test('recent times read relative to now', () => {
  const now = Date.parse('2026-10-09T12:00:00Z');
  assert.equal(formatRelative('2026-10-09T11:59:40Z', now), 'just now');
  assert.equal(formatRelative('2026-10-09T11:56:00Z', now), '4 minutes ago');
  assert.equal(formatRelative('2026-10-09T09:00:00Z', now), '3 hours ago');
  assert.equal(formatRelative('2026-10-08T09:00:00Z', now), 'yesterday');
  assert.equal(formatRelative('2026-10-06T12:00:00Z', now), '3 days ago');
});

test('older times fall back to the date', () => {
  const now = Date.parse('2026-10-09T12:00:00Z');
  assert.equal(formatRelative('2026-09-01T08:30:00Z', now, 'UTC'), '1 Sept 2026, 08:30');
});

test('sizes use B, KB and MB', () => {
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(19270), '18.8 KB');
  assert.equal(formatBytes(25 * 1024 * 1024), '25.0 MB');
});
