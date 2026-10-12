import assert from 'node:assert/strict';
import { test } from 'node:test';
import fixtures from '../mocks/fixtures.json';
import type { Analysis } from '../api/types';

/* The preview data are real server responses. Keep them that way: do not edit
   them by hand or add invented analyses. */
const analyses = fixtures as unknown as Analysis[];
const VERDICTS = ['NO STRONG INDICATORS', 'SUSPICIOUS', 'LIKELY PHISHING', 'MALICIOUS'];
const KINDS = ['json', 'stix', 'misp', 'md', 'csv', 'html', 'manifest'];

test('the preview has the five real analyses, hostile message included', () => {
  assert.deepEqual(analyses.map((a) => a.id), [1, 2, 3, 4, 6]);
  const hostile = analyses.find((a) => a.id === 6)!;
  assert.equal(hostile.verdict, 'LIKELY PHISHING');
  assert.equal(hostile.score, 7);
  assert.ok(hostile.report!.urls.some((u) => u.defanged === 'hxxps://evil-login[.]top/login?next='));
});

test('every analysis has the server shape', () => {
  for (const a of analyses) {
    assert.ok(VERDICTS.includes(a.verdict), `${a.id} verdict`);
    assert.ok(a.offline === false || a.verdict !== 'MALICIOUS', `${a.id}: an offline analysis is never MALICIOUS`);
    assert.deepEqual(a.files.map((f) => f.kind), KINDS, `${a.id} files`);
    assert.match(a.report_id, /^PH-[0-9A-F]{16}$/);
    assert.ok(a.report, `${a.id} report`);
  }
});
