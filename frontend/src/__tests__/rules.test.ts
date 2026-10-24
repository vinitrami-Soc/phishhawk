import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import locked from './locked-files.json';

/* The frontend build brief's hard rules, checked in the source. Every rule
   names what to do instead. src/mocks/ and src/__tests__/ are not scanned, and
   neither are the locked files (they are checked by locked.test.ts). */

const root = fileURLToPath(new URL('../../', import.meta.url));
const lockedPaths = new Set(Object.keys(locked));

function sourceFiles(dir = 'src'): string[] {
  const out: string[] = [];
  for (const name of readdirSync(root + dir)) {
    const path = `${dir}/${name}`;
    if (statSync(root + path).isDirectory()) {
      if (path !== 'src/mocks' && path !== 'src/__tests__') out.push(...sourceFiles(path));
    } else if (/\.(tsx?|jsx?|css)$/.test(name) && !lockedPaths.has(path)) {
      out.push(path);
    }
  }
  return out;
}

const files = sourceFiles().map((path) => ({ path, text: readFileSync(root + path, 'utf8') }));
// the positive checks ("this must exist somewhere") read every file, locked ones included
const allText = [...files.map((f) => f.text), ...[...lockedPaths].filter((p) => p.startsWith('src/') && !p.startsWith('src/__tests__/') && existsSync(root + p)).map((p) => readFileSync(root + p, 'utf8'))].join('\n');

function hits(pattern: RegExp, except: string[] = []) {
  const found: string[] = [];
  for (const { path, text } of files) {
    if (except.includes(path)) continue;
    text.split('\n').forEach((line, i) => {
      if (pattern.test(line)) found.push(`${path}:${i + 1}: ${line.trim().slice(0, 120)}`);
    });
  }
  return found;
}

const FORBIDDEN: [string, RegExp, string[]?][] = [
  ['the report is the server file in <ReportFrame>; never srcDoc', /srcdoc/i],
  ['no allow-same-origin in any sandbox', /allow-same-origin/],
  ['iframes only in ReportFrame', /<iframe/],
  ['AnimatePresence mode="wait" or "sync"; popLayout injects a <style> the CSP blocks', /popLayout/],
  ['render text as text; no HTML injection', /dangerouslySetInnerHTML|\.innerHTML|outerHTML|insertAdjacentHTML|document\.write/],
  ['downloads are links to the server (<FileDownloads>); never build files in the browser', /createObjectURL|new Blob\(/],
  ['no eval', /\beval\(|new Function\(/],
  ['only src/api/client.ts talks to the network', /\bfetch\(|XMLHttpRequest|axios/, ['src/api/client.ts']],
  ['only src/api/client.ts may load the mock', /mockTransport|mockData/, ['src/api/client.ts']],
  ['only src/api/ handles the CSRF token', /csrf/i, ['src/api/client.ts', 'src/api/errors.ts', 'src/api/types.ts']],
  ['use <a target="_blank" rel="noopener noreferrer">, not window.open', /window\.open\(/],
  ['public files: `${import.meta.env.BASE_URL}brand/...`, never "/brand/..."', /["'`]\/brand\//],
  ['the logo is brand/phishhawk-mark.svg; there are no PNG logos or favicons', /phishhawk-mark\.png|favicon-\d+\.png|apple-touch-icon/],
  ['no Gemini API in this app', /@google\/genai|GEMINI_API_KEY/],
  ['no demo accounts or passwords in the UI', /\balice\b|\bboss\b|preview-only-password|PREVIEW_PASSWORD/i],
  ['links and sources never come from report values: use attackUrl() or fileUrl()', /(href|src)=\{[^}]*\.url\b/],
  ['copy the defanged text shown on screen, never .url', /(copy\w*|writeText)\([^)]*\.url\b/i],
  ['attackUrl lives in src/security/safe.ts only', /function attackUrl/, ['src/security/safe.ts']],
  ['no browser storage except the theme choice: the session is the server cookie', /localStorage|sessionStorage|indexedDB/, ['src/app/theme.ts']],
  ['no <style> elements: styles go in .css files', /<style[\s>]/],
  // validate.ts parses a typed domain with new URL("http://..."): nothing is fetched
  ['no external URLs: everything is bundled (ATT&CK links come from attackUrl)', /https?:\/\/(?!attack\.mitre\.org\/|www\.w3\.org\/)/, ['src/security/safe.ts', 'src/lib/validate.ts']],
  ['invented copy or fields: use the build brief and the API', /sandboxed and auditable|Cryptographically|ledger|jobs_waiting|free_disk_mb|["']ingest["']|Nominal|SERVER_SIDE_GEMINI|OAuth|Single Sign-On|\bSSO\b|tempPassword/i],
];

for (const [rule, pattern, except] of FORBIDDEN) {
  test(rule, () => {
    assert.deepEqual(hits(pattern, except), []);
  });
}

test('the only <iframe> is ReportFrame, with exactly this sandbox', () => {
  const frame = readFileSync(root + 'src/components/phishhawk/ReportFrame.tsx', 'utf8');
  assert.match(frame, /sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"/);
});

test('the Offline analysis switch uses the brief\'s exact words', () => {
  assert.match(allText, /Do not send this message(?:'|&apos;|\\'|’)s indicators to reputation providers\./);
  assert.match(allText, /Offline analysis enabled (?:—|&mdash;|\\u2014) reputation lookups will not be performed\./);
  assert.match(allText, /role=["']switch["']/);
  assert.match(allText, /aria-checked=/);
});

test('screens are lazy-loaded', () => {
  const app = readFileSync(root + 'src/App.tsx', 'utf8');
  assert.match(app, /\blazy\(/);
  assert.doesNotMatch(app, /from ['"]@\/screens\/(?!StateScreens)/, 'import screens with lazy(() => import(...)), not statically');
});

test('the app gets the user from useAuth, never from the login form', () => {
  assert.match(allText, /useAuth\(/);
  assert.doesNotMatch(allText, /Simulate authentication|toLowerCase\(\) === ['"]admin['"]/);
});

test('package.json pins the tested versions and adds nothing the app does not use', () => {
  const pkg = JSON.parse(readFileSync(root + 'package.json', 'utf8'));
  const deps: Record<string, string> = { ...pkg.dependencies, ...pkg.devDependencies };
  assert.equal(deps.react, '18.3.1');
  assert.equal(deps['react-dom'], '18.3.1');
  assert.equal(deps.motion, '11.18.2');
  for (const name of ['@google/genai', 'express', 'dotenv', 'esbuild', '@designcodeio/threeui', 'framer-motion', 'gsap', 'three', 'axios', 'styled-components', '@emotion/react']) {
    assert.equal(deps[name], undefined, `remove ${name}`);
  }
});

test('the template and generated leftovers are gone', () => {
  for (const path of [
    '.env.example', 'docker-compose.yml', 'docs/API_DOCUMENTATION.md', 'scripts/generate-assets.cjs',
    'src/mocks/mockData.ts', 'src/__tests__/core.test.js', 'bun.lock',
    // generated pictures: a redrawn logo and its favicons
    'public/brand/placeholder-mark.png', 'public/brand/phishhawk-mark.png', 'public/brand/favicon-32.png',
    'public/brand/favicon-192.png', 'public/brand/apple-touch-icon-180.png',
    // the report pictures are WebP now (lossless, half the size)
    'public/brand/report-dark.png', 'public/brand/report-light.png',
  ]) {
    assert.equal(existsSync(root + path), false, `delete ${path}`);
  }
  if (existsSync(root + 'metadata.json')) {
    assert.doesNotMatch(readFileSync(root + 'metadata.json', 'utf8'), /GEMINI/);
  }
});

test('index.html links the logo as the favicon, so the browser does not ask for /favicon.ico', () => {
  const html = readFileSync(root + 'index.html', 'utf8');
  assert.match(html, /<link rel="icon"[^>]*href="\/brand\/phishhawk-mark\.svg"/);
});

test('report pictures are either absent or the real ones from the PhishHawk repository', () => {
  // The owner adds report-dark.webp and report-light.webp (docs/images/report-*.png from the
  // PhishHawk repository, as lossless WebP) after export. Until then the login showcase shows its
  // fallback; generated pictures are not allowed.
  const real: Record<string, string> = {
    'public/brand/report-dark.webp': 'ee9773c261b3b785135e77a9d5ed90c8d9d305da4ad0d54f8ebf8709774cd79c',
    'public/brand/report-light.webp': 'cb757d4863b705e12a020f390999b382081f49a7533e0f608977b831e5ca6b25',
  };
  for (const [path, sha256] of Object.entries(real)) {
    if (!existsSync(root + path)) continue;
    assert.equal(createHash('sha256').update(readFileSync(root + path)).digest('hex'), sha256, `delete ${path}: it is not the real report picture`);
  }
});

test('there is a light/dark switch, and colours come from the theme tokens', () => {
  assert.match(allText, /aria-label="Dark theme"/);
  assert.match(readFileSync(root + 'src/styles/tokens.css', 'utf8'), /\[data-theme='light'\]/);
  assert.deepEqual(hits(/#[0-9a-fA-F]{6}\b/, ['src/styles/tokens.css']), [], 'use the tokens (bg-canvas, text-ink, ...), not raw hex colours');
});

test('search engines are told not to index the app', () => {
  assert.match(readFileSync(root + 'index.html', 'utf8'), /<meta name="robots" content="noindex, nofollow" \/>/);
});

test('a skip link leads past the top bar to the main content', () => {
  assert.match(allText, /href="#main"/);
  assert.match(allText, />\s*Skip to content\s*</);
  assert.match(allText, /id="main"/);
});

test('the privacy page says what is kept and when it was last updated', () => {
  const page = readFileSync(root + 'src/screens/PrivacyScreen.tsx', 'utf8');
  assert.match(page, /Last updated <time dateTime="\d{4}-\d{2}-\d{2}">/);
  for (const topic of ['What PhishHawk keeps', 'What leaves this server', 'Deleting your account', 'Cookies and storage on your device', 'Terms of use']) {
    assert.match(page, new RegExp(topic), topic);
  }
});

test('the privacy page names who runs this server as the server says, never as the app guesses', () => {
  const page = readFileSync(root + 'src/screens/PrivacyScreen.tsx', 'utf8');
  assert.match(page, /getOperator\(/);
  assert.match(page, /href=\{`mailto:\$\{operator\.email\}`\}/);
});

test('printing uses the light colours, whatever the theme on screen', () => {
  const css = readFileSync(root + 'src/styles/tokens.css', 'utf8');
  const block = (selector: RegExp) => {
    const body = css.match(selector)?.[1] ?? '';
    return Object.fromEntries([...body.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  };
  const light = block(/\[data-theme='light'\] \{([^}]*)\}/);
  const print = block(/@media print \{\s*:root,\s*\[data-theme\] \{([^}]*)\}/);
  assert.ok(Object.keys(print).length >= 20, 'the print block sets the colour tokens');
  const effects = ['--shell-highlight', '--float-shadow', '--glow-strength']; // shadows and glows are off on paper
  for (const [name, value] of Object.entries(print)) if (!effects.includes(name)) assert.equal(value, light[name], name);
});
