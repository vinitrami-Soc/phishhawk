import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

/* The product page quotes the held-out evaluation. Its numbers must be the ones
   in eval/results.json, so a new evaluation cannot leave the page behind. */

const root = fileURLToPath(new URL('../../../', import.meta.url));
const results = JSON.parse(readFileSync(root + 'eval/results.json', 'utf8'));
const landing = readFileSync(root + 'frontend/src/screens/LandingScreen.tsx', 'utf8');
const pct = (part: number, whole: number) => (Math.round((1000 * part) / whole) / 10).toFixed(1);

test('the product page quotes the evaluation in eval/results.json', () => {
  const phish = results.sets.pot_holdout.result;
  const legit = ['ham_holdout', 'enron', 'fixtures', 'msg'].map((key) => results.sets[key].result);
  const fp = legit.reduce((sum, r) => sum + r.flagged.fp, 0);
  const total = legit.reduce((sum, r) => sum + r.emails, 0).toLocaleString('en-GB');
  const flagged = pct(phish.flagged.tp, phish.emails);
  const engine = results.tool_version.split('.').slice(0, 2).join('.');
  for (const quote of [
    `value: ${flagged},`,
    `${pct(phish.strict.tp, phish.emails)}% of them were called likely phishing`,
    `${fp} of ${total} real legitimate emails were flagged by mistake`,
    `value: ${Math.round(phish.timing_ms.median)}, decimals: 0, unit: 'ms'`,
    `PhishHawk ${engine} engine`,
    `it flagged ${flagged}%, and it flagged ${fp} of ${total} legitimate emails`,
  ]) {
    assert.ok(landing.includes(quote), `the product page should say: ${quote}`);
  }
});
