import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { fingerprint } from './fingerprint';
import manifest from './locked-files.json';

/* The UI kit and the fix kit must stay as delivered: the kit is tested under
   PhishHawk's CSP with React 18 and motion 11, and the API layer against the
   real PhishHawk server. Comments, whitespace, quote style, semicolons and
   trailing commas are ignored (and JSON formatting); any change to the code
   itself fails. */

const root = fileURLToPath(new URL('../../', import.meta.url));

test('the fingerprint ignores formatting and comments, not code', () => {
  const original = "// note\nconst a = 'x';\nexport function f(b: number) {\n  return a + b; /* sum */\n}\n";
  const reformatted = 'const a = "x"\nexport function f(b: number) { return a + b }';
  const changed = "const a = 'y';\nexport function f(b: number) {\n  return a + b;\n}\n";
  assert.equal(fingerprint('x.ts', reformatted), fingerprint('x.ts', original));
  assert.notEqual(fingerprint('x.ts', changed), fingerprint('x.ts', original));
  assert.equal(fingerprint('x.json', '{"b": 1, "a": [1, 2]}'), fingerprint('x.json', '{\n  "a": [1,2],\n  "b": 1\n}'));
  assert.notEqual(fingerprint('x.json', '{"a": [2, 1]}'), fingerprint('x.json', '{"a": [1, 2]}'));
  assert.equal(fingerprint('x.ts', "const u = 'https://example.org/a';"), 'constu="https://example.org/a"');
  assert.equal(fingerprint('x.md', '<!<!-- a -->-- b -->text'), 'text');
});

test('every locked file is present and unchanged', () => {
  const changed: string[] = [];
  for (const [path, expected] of Object.entries(manifest as Record<string, string>)) {
    const file = root + path;
    if (!existsSync(file)) {
      changed.push(`${path} (missing)`);
    } else if (createHash('sha256').update(fingerprint(path, readFileSync(file, 'utf8'))).digest('hex') !== expected) {
      changed.push(path);
    }
  }
  assert.deepEqual(changed, [], `Write these again exactly as in PhishHawk-frontend-v2.txt:\n${changed.join('\n')}`);
});
