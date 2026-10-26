import assert from 'node:assert/strict';
import { test } from 'node:test';
import { FALLBACK_REASON, REASONS, plainReasons, plainSteps, plainVerdict } from '../app/plain';

const VERDICTS = ['MALICIOUS', 'LIKELY PHISHING', 'SUSPICIOUS', 'NO STRONG INDICATORS'] as const;
// The engine's FAMILIES (src/phishhawk/models.py); tests/test_plain_words.py checks the engine's side.
const FAMILIES = ['auth', 'sender', 'link', 'attachment', 'content', 'evasion', 'intel', 'policy'];

const signal = (severity: 'high' | 'medium' | 'low', family?: string) => ({ severity, label: 'a finding', techniques: [], family });

test('every verdict has a headline, a line under it and at least one step', () => {
  for (const verdict of VERDICTS) {
    const plain = plainVerdict(verdict);
    assert.ok(plain.headline && plain.detail, verdict);
    assert.ok(plainSteps(verdict).length > 0, verdict);
  }
});

test('no verdict calls a message safe', () => {
  for (const verdict of VERDICTS) {
    const { headline, detail } = plainVerdict(verdict);
    const words = [headline, detail.replace("doesn't prove it's safe", ''), ...plainSteps(verdict).map((s) => `${s.lead ?? ''} ${s.text}`)].join(' ');
    assert.doesNotMatch(words, /\bsafe\b/i, verdict);
  }
});

test('every family of finding has a reason of its own', () => {
  assert.deepEqual(Object.keys(REASONS).sort(), [...FAMILIES].sort());
  for (const family of FAMILIES) assert.deepEqual(plainReasons('SUSPICIOUS', [signal('high', family)]), [REASONS[family]]);
  assert.equal(new Set(Object.values(REASONS)).size, FAMILIES.length);
});

test('one reason per family, the most serious first, at most three', () => {
  const reasons = plainReasons('LIKELY PHISHING', [
    signal('low', 'content'), signal('medium', 'link'), signal('high', 'sender'),
    signal('high', 'sender'), signal('medium', 'attachment'), signal('high', 'auth'),
  ]);
  assert.deepEqual(reasons, [REASONS.sender, REASONS.auth, REASONS.link]);
});

test('findings without a known family are skipped; the fallback shows only when nothing is left', () => {
  assert.deepEqual(plainReasons('SUSPICIOUS', [signal('high', ''), signal('medium', 'constructor'), signal('low')]), [FALLBACK_REASON]);
  assert.deepEqual(plainReasons('SUSPICIOUS', [signal('high', ''), signal('low', 'link')]), [REASONS.link]);
  assert.deepEqual(plainReasons('MALICIOUS', []), [FALLBACK_REASON]);
});

test('a message with no warning signs gets no reasons', () => {
  assert.deepEqual(plainReasons('NO STRONG INDICATORS', [signal('low', 'content')]), []);
});

test('a scam gets the steps for someone who already clicked or paid, and the UK reporting address', () => {
  for (const verdict of ['MALICIOUS', 'LIKELY PHISHING'] as const) {
    const steps = plainSteps(verdict);
    assert.deepEqual(steps.map((s) => s.lead).filter(Boolean), ['Already clicked a link or typed a password?', 'Shared bank or card details?']);
    assert.match(steps.map((s) => s.text).join(' '), /report@phishing\.gov\.uk/);
  }
});

test('an unknown verdict is treated with caution', () => {
  assert.deepEqual(plainVerdict('SOMETHING NEW'), plainVerdict('SUSPICIOUS'));
  assert.deepEqual(plainSteps('toString'), plainSteps('SUSPICIOUS'));
});
