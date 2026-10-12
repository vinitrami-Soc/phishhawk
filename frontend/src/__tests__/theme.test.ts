import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pickTheme, revealRadius } from '../app/theme';

test('a saved choice wins over the system setting', () => {
  assert.equal(pickTheme('light', true), 'light');
  assert.equal(pickTheme('dark', false), 'dark');
});

test('with no saved choice, follow the system setting', () => {
  assert.equal(pickTheme(null, true), 'dark');
  assert.equal(pickTheme(null, false), 'light');
});

test('anything else saved is ignored', () => {
  assert.equal(pickTheme('purple', true), 'dark');
  assert.equal(pickTheme('', false), 'light');
});

test('the reveal circle reaches the farthest corner of the screen', () => {
  // from the bottom-left corner of a 1000 x 600 screen, the farthest corner is the top right
  assert.equal(Math.round(revealRadius(0, 600, 1000, 600)), Math.round(Math.hypot(1000, 600)));
  // from the centre, every corner is equally far
  assert.equal(Math.round(revealRadius(500, 300, 1000, 600)), Math.round(Math.hypot(500, 300)));
});
