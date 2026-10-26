# Simple view for individual accounts: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Someone with an individual account sees the analysis and upload pages in plain words, with a "Show technical details" switch back to today's pages; organization accounts are unchanged.

**Architecture:** Frontend only. Pure modules hold the plain text (`src/app/plain.ts`) and the per-tab switch state (`src/app/technical.ts`); small components draw the switch, the simple analysis and the upload guide; `AnalysisScreen` and `TriageScreen` choose between the simple and the technical page. The server, API, JSON report, CLI and HTML report do not change.

**Tech Stack:** React 18 + TypeScript (Vite), unit tests with `tsx --test` (node:test), browser tests with pytest + Playwright against a real PhishHawk server.

Spec: `docs/superpowers/specs/2026-10-26-simple-view-design.md`.

## Global Constraints

- Work on branch `claude/simple-view-spec` in `/home/user/phishhawk`; one PR at the end.
- Commit as the user, with no co-author lines: `git -c "user.name=Vinit Rami" -c "user.email=274839285+vinitrami-Soc@users.noreply.github.com" commit ...`
- Never edit a file listed in `frontend/src/__tests__/locked-files.json` (among them `src/api/types.ts`, `src/api/client.ts`, `src/app/vocabulary.ts`, `src/app/permissions.ts`, `src/app/theme.ts`, `src/components/ui/ui.tsx`, every file in `src/components/core/`, `src/__tests__/rules.test.ts`). Import from them freely.
- No browser storage (`localStorage`, `sessionStorage`, `indexedDB`): the switch's choice lives in memory for the tab (`rules.test.ts`).
- No external URLs in `frontend/src` (`rules.test.ts`); `report@phishing.gov.uk` is an address, not a URL.
- The app's text is English and is copied exactly from the spec.
- Every value from the message is shown as text; the sender address goes through `showIndicator('email', ...)`.
- Organization sessions, and sessions with `workspace: null`, always get today's pages and never see the switch.
- Frontend checks: `cd frontend && npm test && npx tsc --noEmit && npm run build`. Python checks: `python -m pytest` from the repo root, `ruff check src tests samples eval tools phishhawk`.
- Browser tests need the build and a Chromium: `PHISHHAWK_FRONTEND_BUILD=frontend/dist PHISHHAWK_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python -m pytest tests/server/test_frontend_browser.py -p no:cacheprovider -rs` (in CI the job "The server and a browser" runs them; locally, drop `PHISHHAWK_CHROMIUM` if Playwright installed its own Chromium).

## File map

| File | Responsibility |
|---|---|
| `frontend/src/app/plain.ts` (new) | Plain text: verdict headline and detail, one reason per finding family, steps per verdict. |
| `frontend/src/__tests__/plain.test.ts` (new) | Unit tests for `plain.ts`. |
| `tests/test_plain_words.py` (new) | The engine's `FAMILIES` and `plain.ts`'s `REASONS` keys are the same set. |
| `frontend/src/app/technical.ts` (new) | Who has the switch, which pages a session sees, the tab's choice in memory. |
| `frontend/src/__tests__/technical.test.ts` (new) | Unit tests for `technical.ts`. |
| `frontend/src/components/phishhawk/TechnicalSwitch.tsx` (new) | `useTechnicalView` hook and the `TechnicalSwitch` card. |
| `frontend/src/components/phishhawk/SimpleAnalysis.tsx` (new) | The simple verdict, the email, the reasons and the steps. |
| `frontend/src/components/phishhawk/GetTheEmail.tsx` (new) | The "How do I get the email?" guide. |
| `frontend/src/screens/AnalysisScreen.tsx` | Chooses the simple or technical analysis page; shows the switch. |
| `frontend/src/screens/TriageScreen.tsx` | Takes the session; plain words and the guide on the simple page; shows the switch. |
| `frontend/src/App.tsx` | Passes the session to `TriageScreen`. |
| `tests/server/test_frontend_browser.py` | The individual and organization journeys in a real browser. |
| `docs/FRONTEND.md`, `CHANGELOG.md` | The simple view, for readers and the release notes. |

---

### Task 1: The plain words

**Files:**
- Create: `frontend/src/app/plain.ts`
- Test: `frontend/src/__tests__/plain.test.ts`
- Test: `tests/test_plain_words.py`

**Interfaces:**
- Consumes: `Signal`, `Verdict` types from `@/api/types`; `SEVERITY_ORDER` from `@/app/vocabulary`.
- Produces:
  - `type PlainVerdict = { headline: string; detail: string }`
  - `type PlainStep = { lead?: string; text: string }`
  - `plainVerdict(verdict: string): PlainVerdict`
  - `plainSteps(verdict: string): PlainStep[]`
  - `plainReasons(verdict: string, signals: Pick<Signal, 'severity' | 'family'>[]): string[]`
  - `REASONS: Readonly<Record<string, string>>`, `FALLBACK_REASON: string`

- [ ] **Step 1: Write the failing unit tests**

Create `frontend/src/__tests__/plain.test.ts`:

```ts
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
```

Create `tests/test_plain_words.py`:

```python
"""Every family of finding has plain words for someone checking their own mail
(frontend/src/app/plain.ts), so a new family cannot be left without a reason."""

import re
from pathlib import Path

from phishhawk.models import FAMILIES

PLAIN = Path(__file__).resolve().parents[1] / "frontend" / "src" / "app" / "plain.ts"


def test_every_family_of_finding_has_a_plain_reason():
    block = PLAIN.read_text("utf-8").split("export const REASONS", 1)[1].split("};", 1)[0]
    assert set(re.findall(r"^\s*(\w+): '", block, re.M)) == set(FAMILIES)
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cd frontend && npx tsx --test src/__tests__/plain.test.ts`
Expected: FAIL, `Cannot find module '../app/plain'`.

Run: `python -m pytest tests/test_plain_words.py -q`
Expected: FAIL, `FileNotFoundError` for `frontend/src/app/plain.ts`.

- [ ] **Step 3: Write `plain.ts`**

Create `frontend/src/app/plain.ts`:

```ts
/* Plain words for someone checking their own mail: the verdict, why, and what
   to do (docs/superpowers/specs/2026-10-26-simple-view-design.md). Fixed text:
   nothing here comes from the message. */

import type { Signal, Verdict } from '@/api/types';
import { SEVERITY_ORDER } from '@/app/vocabulary';

export type PlainVerdict = { headline: string; detail: string };
export type PlainStep = { lead?: string; text: string };

const VERDICTS: Record<Verdict, PlainVerdict> = {
  MALICIOUS: { headline: 'This email is dangerous.', detail: 'Security services already know a link or file in it as harmful.' },
  'LIKELY PHISHING': { headline: 'This email is very likely a scam.', detail: 'It shows several signs that scammers use.' },
  SUSPICIOUS: { headline: 'Be careful with this email.', detail: "Some things look wrong, but we can't be sure." },
  'NO STRONG INDICATORS': {
    headline: 'No warning signs found.',
    detail: "This doesn't prove it's safe: if it asks for money or your password, check with the sender another way.",
  },
};

/** One reason per family of finding: the engine's FAMILIES (src/phishhawk/models.py), kept in step by tests/test_plain_words.py. */
export const REASONS: Readonly<Record<string, string>> = {
  sender: 'The sender pretends to be someone you trust.',
  link: 'A link leads somewhere other than it shows, or to a kind of website often used for scams.',
  attachment: 'An attachment could harm your device or ask for your password.',
  content: 'The wording pushes you to act fast, pay, or sign in.',
  auth: 'The email could not be confirmed as coming from the address it shows.',
  evasion: 'The email hides parts of itself to get past spam filters.',
  intel: 'Security services already report a link or file in this email as harmful.',
  policy: 'It matches a block list or rule set on your account.',
};

export const FALLBACK_REASON = 'Several smaller warning signs add up.';

const SCAM: PlainStep[] = [
  { text: "Don't click any link, open any attachment, or reply." },
  { text: 'Report it as phishing in your email app, then delete it. In the UK you can also forward it to report@phishing.gov.uk.' },
  { lead: 'Already clicked a link or typed a password?', text: 'Change that password now, and anywhere else you use it, and turn on 2-step verification.' },
  { lead: 'Shared bank or card details?', text: 'Call your bank on the number on the back of your card.' },
];

const STEPS: Record<Verdict, PlainStep[]> = {
  MALICIOUS: SCAM,
  'LIKELY PHISHING': SCAM,
  SUSPICIOUS: [
    { text: "Don't click links or open attachments yet." },
    { text: 'Check with the sender another way: call them, or type their website address yourself.' },
    { text: 'If it turns out to be fake, report it as phishing and delete it.' },
  ],
  'NO STRONG INDICATORS': [{ text: 'If it asks for money, a password or urgent action, check with the sender another way first.' }],
};

/** A verdict this version does not know is treated like SUSPICIOUS. */
function known(verdict: string): Verdict {
  return Object.hasOwn(VERDICTS, verdict) ? (verdict as Verdict) : 'SUSPICIOUS';
}

export function plainVerdict(verdict: string): PlainVerdict {
  return VERDICTS[known(verdict)];
}

export function plainSteps(verdict: string): PlainStep[] {
  return STEPS[known(verdict)];
}

/** Up to three reasons, the most serious finding of each family first; none for a message with no warning signs. */
export function plainReasons(verdict: string, signals: Pick<Signal, 'severity' | 'family'>[]): string[] {
  if (verdict === 'NO STRONG INDICATORS') return [];
  const reasons: string[] = [];
  const bySeverity = [...signals].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  for (const { family } of bySeverity) {
    const reason = family && Object.hasOwn(REASONS, family) ? REASONS[family] : undefined;
    if (reason && !reasons.includes(reason)) reasons.push(reason);
    if (reasons.length === 3) break;
  }
  return reasons.length ? reasons : [FALLBACK_REASON];
}
```

- [ ] **Step 4: Run them and watch them pass**

Run: `cd frontend && npx tsx --test src/__tests__/plain.test.ts`
Expected: 8 tests pass.

Run: `python -m pytest tests/test_plain_words.py -q`
Expected: 1 passed.

Run: `cd frontend && npm test && npx tsc --noEmit`
Expected: all pass (the rules test scans the new file: no storage, no URLs).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/plain.ts frontend/src/__tests__/plain.test.ts tests/test_plain_words.py
git -c "user.name=Vinit Rami" -c "user.email=274839285+vinitrami-Soc@users.noreply.github.com" commit -m "Plain words for a verdict, its reasons and what to do"
```

---

### Task 2: The switch and its state

**Files:**
- Create: `frontend/src/app/technical.ts`
- Create: `frontend/src/components/phishhawk/TechnicalSwitch.tsx`
- Test: `frontend/src/__tests__/technical.test.ts`

**Interfaces:**
- Consumes: `Session` type from `@/api/types`; `Card`, `Switch` from `@/components/ui/ui`.
- Produces:
  - `switchable(session: Pick<Session, 'workspace'>): boolean`
  - `technicalView(session: Pick<Session, 'workspace'>, choice: boolean): boolean`
  - `tabChoice(): boolean`, `rememberForTab(next: boolean): void`
  - `type TechnicalView = { technical: boolean; switchable: boolean; setTechnical: (next: boolean) => void }`
  - `useTechnicalView(session: Session): TechnicalView`
  - `TechnicalSwitch({ view }: { view: TechnicalView })`: the switch in a card, or `null` when not switchable.

- [ ] **Step 1: Write the failing unit tests**

Create `frontend/src/__tests__/technical.test.ts`:

```ts
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cd frontend && npx tsx --test src/__tests__/technical.test.ts`
Expected: FAIL, `Cannot find module '../app/technical'`.

- [ ] **Step 3: Write `technical.ts` and the switch**

Create `frontend/src/app/technical.ts`:

```ts
/* Technical pages or simple ones (docs/superpowers/specs/2026-10-26-simple-view-design.md).
   An organization always sees the technical pages. Someone on their own sees the
   simple ones until they turn on "Show technical details". The choice lasts while
   this tab is open: browser storage is kept for the theme alone
   (src/__tests__/rules.test.ts), so a reload starts simple again. */

import type { Session } from '@/api/types';

type WithWorkspace = Pick<Session, 'workspace'>;

let chosen = false;

/** Only someone on their own has the switch. */
export function switchable(session: WithWorkspace): boolean {
  return session.workspace?.kind === 'individual';
}

export function technicalView(session: WithWorkspace, choice: boolean): boolean {
  return !switchable(session) || choice;
}

/** This tab's choice: off until the switch is turned on. */
export function tabChoice(): boolean {
  return chosen;
}

export function rememberForTab(next: boolean): void {
  chosen = next;
}
```

Create `frontend/src/components/phishhawk/TechnicalSwitch.tsx`:

```tsx
/* "Show technical details", for someone on their own (app/technical.ts). */

import { useState } from 'react';
import type { Session } from '@/api/types';
import { rememberForTab, switchable, tabChoice, technicalView } from '@/app/technical';
import { Card, Switch } from '@/components/ui/ui';

export type TechnicalView = { technical: boolean; switchable: boolean; setTechnical: (next: boolean) => void };

export function useTechnicalView(session: Session): TechnicalView {
  const [choice, setChoice] = useState(tabChoice);
  return {
    technical: technicalView(session, choice),
    switchable: switchable(session),
    setTechnical: (next) => {
      rememberForTab(next);
      setChoice(next);
    },
  };
}

export function TechnicalSwitch({ view }: { view: TechnicalView }) {
  if (!view.switchable) return null;
  return (
    <Card className="px-5 py-4 sm:px-6">
      <Switch
        checked={view.technical}
        onChange={view.setTechnical}
        label="Show technical details"
        description="Indicators, authentication checks, ATT&CK, the full report and downloads."
      />
    </Card>
  );
}
```

- [ ] **Step 4: Run them and watch them pass**

Run: `cd frontend && npx tsx --test src/__tests__/technical.test.ts`
Expected: 4 tests pass.

Run: `cd frontend && npm test && npx tsc --noEmit`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/technical.ts frontend/src/components/phishhawk/TechnicalSwitch.tsx frontend/src/__tests__/technical.test.ts
git -c "user.name=Vinit Rami" -c "user.email=274839285+vinitrami-Soc@users.noreply.github.com" commit -m "A Show technical details switch, remembered while the tab is open"
```

---

### Task 3: The simple analysis page

**Files:**
- Create: `frontend/src/components/phishhawk/SimpleAnalysis.tsx`
- Modify: `frontend/src/screens/AnalysisScreen.tsx` (imports at lines 6-31; hooks at 432-447; the page from 577 to the end)
- Test: `tests/server/test_frontend_browser.py` (`test_someone_who_signs_up_alone_is_set_up_shown_around_and_analyses_a_first_message`, `test_an_analyst_works_a_message_in_the_frontend_at_every_width`)

**Interfaces:**
- Consumes: `plainVerdict`, `plainReasons`, `plainSteps` (Task 1); `useTechnicalView`, `TechnicalSwitch` (Task 2); `Analysis` type; `VERDICT_GLOW`, `verdictTone` from `@/app/vocabulary`; `showIndicator` from `@/security/safe`; `GlowEffect`; `Card`, `Panel`, `SectionTitle`, `Time` from `@/components/ui/ui`.
- Produces: `SimpleAnalysis({ analysis }: { analysis: Analysis })`.

- [ ] **Step 1: Write the failing browser checks**

In `tests/server/test_frontend_browser.py`, in `test_someone_who_signs_up_alone_is_set_up_shown_around_and_analyses_a_first_message`, replace

```python
        page.wait_for_url("**/app/analyses/*", timeout=60000)
        page.get_by_text("LIKELY PHISHING").first.wait_for(timeout=30000)
```

with

```python
        page.wait_for_url("**/app/analyses/*", timeout=60000)

        # someone on their own gets the verdict in plain words and what to do, not the tabs
        headline = page.get_by_role("heading", level=1, name="This email is very likely a scam.")
        headline.wait_for(timeout=30000)
        sync_api.expect(page.get_by_role("heading", name="Why we think so")).to_be_visible()
        sync_api.expect(page.get_by_role("heading", name="What to do now")).to_be_visible()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_have_count(0)
        simple = page.url

        # the switch brings back the technical page while the tab is open; a reload starts simple again
        page.get_by_role("switch", name="Show technical details").click()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_be_visible()
        page.locator("main a[href='/app/analyses']").first.click()
        page.locator("main table a[href^='/app/analyses/']").first.click()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_be_visible()
        page.reload()
        headline.wait_for()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_have_count(0)
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(simple)
            headline.wait_for()
            page.wait_for_timeout(400)
            assert page.evaluate(PAST_EDGE, "body") == [], (width, "the simple analysis")
        page.set_viewport_size({"width": 1280, "height": 900})
```

In `test_an_analyst_works_a_message_in_the_frontend_at_every_width` (root, the default organization), after `analysis = page.url` add:

```python
        sync_api.expect(page.get_by_role("switch", name="Show technical details")).to_have_count(0)
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cd frontend && npm run build && cd .. && PHISHHAWK_FRONTEND_BUILD=frontend/dist PHISHHAWK_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python -m pytest tests/server/test_frontend_browser.py -k "alone or works_a_message" -p no:cacheprovider -rs`
Expected: the "alone" test FAILS waiting for the heading "This email is very likely a scam."; the "works_a_message" test passes.

- [ ] **Step 3: Write `SimpleAnalysis.tsx`**

Create `frontend/src/components/phishhawk/SimpleAnalysis.tsx`:

```tsx
/* The analysis page for someone checking their own mail (docs/superpowers/specs/
   2026-10-26-simple-view-design.md, section 3): the verdict, which email, why,
   and what to do, in plain words. Values from the message are shown as text. */

import type { Analysis } from '@/api/types';
import { plainReasons, plainSteps, plainVerdict } from '@/app/plain';
import { VERDICT_GLOW, verdictTone } from '@/app/vocabulary';
import { GlowEffect } from '@/components/core/glow-effect';
import { Card, Panel, SectionTitle, Time } from '@/components/ui/ui';
import { cn } from '@/lib/utils';
import { showIndicator } from '@/security/safe';

export function SimpleAnalysis({ analysis }: { analysis: Analysis }) {
  const report = analysis.report;
  const verdict = plainVerdict(analysis.verdict);
  const tone = verdictTone(analysis.verdict);
  const steps = plainSteps(analysis.verdict);
  return (
    <div className="grid grid-cols-1 gap-6">
      <div className="relative">
        <GlowEffect
          className="opacity-[var(--glow-strength)]"
          colors={[VERDICT_GLOW[analysis.verdict] ?? 'var(--verdict-neutral)', 'transparent']}
          mode="static"
          blur="strong"
          scale={0.92}
        />
        <Panel className="relative">
          <div className="grid gap-6 p-6 sm:p-8">
            <div>
              <h1 className={cn('text-[28px] font-semibold leading-tight tracking-[-0.02em] sm:text-4xl', tone.text)}>{verdict.headline}</h1>
              <p className="mt-3 max-w-[60ch] text-base leading-relaxed text-ink-dim">{verdict.detail}</p>
            </div>
            <dl className="grid gap-x-8 gap-y-4 border-t border-line pt-5 sm:grid-cols-3">
              <div className="min-w-0">
                <dt className="text-xs text-ink-muted">Subject</dt>
                <dd className={cn('mt-1 break-words text-sm', analysis.subject === null ? 'text-ink-muted' : 'text-ink')}>{analysis.subject ?? 'Message deleted'}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs text-ink-muted">From</dt>
                <dd className="mt-1 break-all text-sm text-ink">{showIndicator('email', report?.from_address || analysis.sender)}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs text-ink-muted">Checked</dt>
                <dd className="mt-1 text-sm text-ink">
                  <Time iso={analysis.created_at} />
                </dd>
              </div>
            </dl>
          </div>
        </Panel>
      </div>

      {analysis.verdict !== 'NO STRONG INDICATORS' && (
        <Card className="p-6">
          <SectionTitle>Why we think so</SectionTitle>
          {report ? (
            <ul className="mt-4 grid gap-2.5">
              {plainReasons(analysis.verdict, report.signals).map((reason) => (
                <li key={reason} className="flex gap-3 text-sm leading-relaxed text-ink-dim">
                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                  {reason}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-4 text-sm text-ink-muted">The details were deleted with the message.</p>
          )}
        </Card>
      )}

      <Card className="p-6">
        <SectionTitle>What to do now</SectionTitle>
        <ol className="mt-4 grid gap-3">
          {steps.map((step, i) => (
            <li key={step.text} className="flex gap-3 text-sm leading-relaxed text-ink-dim">
              <span aria-hidden="true" className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-line text-xs text-ink-muted">
                {i + 1}
              </span>
              <span>
                {step.lead && <strong className="font-medium text-ink">{step.lead} </strong>}
                {step.text}
              </span>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
```

- [ ] **Step 4: Choose the page in `AnalysisScreen.tsx`**

1. Add to the imports (after the `ReportFrame` import):

```tsx
import { SimpleAnalysis } from '@/components/phishhawk/SimpleAnalysis';
import { TechnicalSwitch, useTechnicalView } from '@/components/phishhawk/TechnicalSwitch';
```

2. In `AnalysisScreen`, right after `const toast = useToast();`, add:

```tsx
  const view = useTechnicalView(session);
```

3. Move the first `ConfirmDialog` (the one with `open={confirm === 'tier1'}`) out of the returned JSX into a constant, declared right after `dockItems`:

```tsx
  const deleteNowDialog = (
    <ConfirmDialog
      open={confirm === 'tier1'}
      onOpenChange={(open) => !open && setConfirm(null)}
      title="Delete this message now?"
      body="This removes the message and its reports. The verdict and this record are kept."
      confirmLabel="Delete now"
      danger
      busy={busy}
      error={confirm === 'tier1' ? actionError : null}
      onConfirm={() => run(() => deleteMessage(analysis.message_id, 'tier1'), 'Message deleted. The verdict and record are kept.')}
    />
  );
```

and put `{deleteNowDialog}` where that `ConfirmDialog` was.

4. Right after `deleteNowDialog`, before the existing `return (`, add the simple page:

```tsx
  if (!view.technical) {
    return (
      <div className="grid grid-cols-1 gap-8 pb-20 lg:pb-24">
        <Link href="/app/analyses" className="inline-flex min-h-8 w-max items-center gap-2 text-sm text-ink-muted hover:text-ink">
          <ArrowLeft className="h-4 w-4" strokeWidth={1.5} /> Queue
        </Link>
        <TechnicalSwitch view={view} />
        <SimpleAnalysis analysis={analysis} />
        <VerdictQuestion analysisId={analysis.id} session={session} />
        {can.deleteNow && (
          <div>
            <Button size="sm" variant="danger" onClick={() => setConfirm('tier1')} disabled={busy}>
              Delete this message
            </Button>
          </div>
        )}
        {deleteNowDialog}
      </div>
    );
  }
```

5. In the technical page, right after the `Queue` `<Link>` block, add:

```tsx
      <TechnicalSwitch view={view} />
```

- [ ] **Step 5: Run the checks and watch them pass**

Run: `cd frontend && npm test && npx tsc --noEmit && npm run build`
Expected: all pass.

Run: `PHISHHAWK_FRONTEND_BUILD=frontend/dist PHISHHAWK_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python -m pytest tests/server/test_frontend_browser.py -k "alone or works_a_message or verdict_was_right" -p no:cacheprovider -rs`
Expected: 3 passed (root is in the default organization, so its pages are unchanged).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/phishhawk/SimpleAnalysis.tsx frontend/src/screens/AnalysisScreen.tsx tests/server/test_frontend_browser.py
git -c "user.name=Vinit Rami" -c "user.email=274839285+vinitrami-Soc@users.noreply.github.com" commit -m "A simple analysis page for someone checking their own mail"
```

---

### Task 4: The simple upload page

**Files:**
- Create: `frontend/src/components/phishhawk/GetTheEmail.tsx`
- Modify: `frontend/src/screens/TriageScreen.tsx` (imports at 5-21; `TriageScreen` at 106; the header at 158; the drop zone at 227-233; the textarea placeholder at 245; the end of the returned JSX)
- Modify: `frontend/src/App.tsx:248`
- Test: `tests/server/test_frontend_browser.py` (the same two tests as Task 3)

**Interfaces:**
- Consumes: `useTechnicalView`, `TechnicalSwitch` (Task 2); `Session` type; `Card`, `SectionTitle` from `@/components/ui/ui`.
- Produces: `GetTheEmail()`; `TriageScreen({ session }: { session: Session })`.

- [ ] **Step 1: Write the failing browser checks**

In `test_someone_who_signs_up_alone_is_set_up_shown_around_and_analyses_a_first_message`, replace the first block after `onboarded` is checked:

```python
        # the first analysis
        page.get_by_role("button", name="Paste the message").click()
```

with

```python
        # the upload page speaks plainly and shows how to get the email out of a mail app
        page.get_by_role("heading", level=1, name="Check an email").wait_for()
        sync_api.expect(page.get_by_text("Drop the email file here, or choose it")).to_be_visible()
        page.get_by_text("Gmail (on a computer)").click()
        sync_api.expect(page.get_by_text("Choose Download message.")).to_be_visible()
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(server.base + "/app/")
            page.get_by_role("heading", level=1, name="Check an email").wait_for()
            page.wait_for_timeout(400)
            assert page.evaluate(PAST_EDGE, "body") == [], (width, "the simple upload page")
        page.set_viewport_size({"width": 1280, "height": 900})

        # the first analysis
        page.get_by_role("button", name="Paste the message").click()
```

In `test_an_analyst_works_a_message_in_the_frontend_at_every_width`, right after `page, errors = _signed_in(browser, server)` add:

```python
        page.get_by_role("heading", level=1, name="Analyze a reported message").wait_for()
        sync_api.expect(page.get_by_text("How do I get the email?")).to_have_count(0)
        sync_api.expect(page.get_by_role("switch", name="Show technical details")).to_have_count(0)
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cd frontend && npm run build && cd .. && PHISHHAWK_FRONTEND_BUILD=frontend/dist PHISHHAWK_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python -m pytest tests/server/test_frontend_browser.py -k "alone or works_a_message" -p no:cacheprovider -rs`
Expected: the "alone" test FAILS waiting for the heading "Check an email"; the other passes.

- [ ] **Step 3: Write `GetTheEmail.tsx`**

Create `frontend/src/components/phishhawk/GetTheEmail.tsx`:

```tsx
/* How someone on their own gets an email out of their mail app, for the simple
   upload page (docs/superpowers/specs/2026-10-26-simple-view-design.md, section 4).
   The menu names are each provider's; check them again when a provider changes
   its menus. */

import { Card, SectionTitle } from '@/components/ui/ui';

const APPS: { name: string; steps: string[]; after: string }[] = [
  {
    name: 'Gmail (on a computer)',
    steps: ['Open the email.', 'Click ⋮ (More), next to Reply.', 'Choose Download message.', 'Drop the downloaded file here.'],
    after: 'Or choose Show original instead, click Copy to clipboard, and paste it with Paste the message, above.',
  },
  {
    name: 'Outlook (Outlook.com or Outlook on the web)',
    steps: [
      'Open the email.',
      'Click … (More actions).',
      'Choose Download, then Download as EML. (Some versions say Save as, then Save as EML.)',
      'Drop the downloaded file here.',
    ],
    after:
      'A file saved from Outlook can leave out the hidden lines that show who really sent the email. PhishHawk still checks its links, attachments and wording.',
  },
  {
    name: 'Apple Mail (Mac)',
    steps: ['Select the email.', 'Choose File, then Save As.', 'Set Format to Raw Message Source, and save.', 'Drop the saved file here.'],
    after: 'Or drag the email from the list to your desktop, and drop that file here.',
  },
];

export function GetTheEmail() {
  return (
    <Card className="p-6">
      <SectionTitle>How do I get the email?</SectionTitle>
      <p className="mt-2 text-sm leading-relaxed text-ink-dim">Check emails you received. Don&apos;t upload confidential work email.</p>
      <div className="mt-4 grid gap-2">
        {APPS.map((app) => (
          <details key={app.name} className="rounded-2xl border border-line px-4 py-3">
            <summary className="cursor-pointer text-sm font-medium text-ink">{app.name}</summary>
            <ol className="mt-3 grid list-decimal gap-1.5 pl-5 text-sm leading-relaxed text-ink-dim">
              {app.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <p className="mt-3 text-[13px] leading-relaxed text-ink-muted">{app.after}</p>
          </details>
        ))}
      </div>
      <p className="mt-4 text-[13px] leading-relaxed text-ink-muted">
        On a phone? Phone email apps can&apos;t save the email file. Open your email on a computer instead.
      </p>
    </Card>
  );
}
```

- [ ] **Step 4: Use it in `TriageScreen.tsx` and pass the session from `App.tsx`**

1. In `TriageScreen.tsx`, change the types import to `import type { AnalysisSummary, Session } from '@/api/types';` and add:

```tsx
import { GetTheEmail } from '@/components/phishhawk/GetTheEmail';
import { TechnicalSwitch, useTechnicalView } from '@/components/phishhawk/TechnicalSwitch';
```

2. Change `export default function TriageScreen() {` to:

```tsx
export default function TriageScreen({ session }: { session: Session }) {
  const view = useTechnicalView(session);
  const simple = !view.technical;
```

(the existing `useState` lines follow unchanged).

3. Replace the `PageHeader` line with:

```tsx
      <PageHeader
        eyebrow={simple ? 'PhishHawk' : 'Triage'}
        title={simple ? 'Check an email' : 'Analyze a reported message'}
        description={
          simple
            ? 'Save the email from your email app and drop it here, or copy and paste it.'
            : 'Upload one or more .eml or .msg files, an .mbox or a .zip, or paste the full message with its headers.'
        }
      />
      <TechnicalSwitch view={view} />
```

4. Replace the two drop-zone lines

```tsx
                    <span className="text-sm font-medium text-ink">Drop .eml, .msg, .mbox or .zip files, or choose them</span>
                    <span className="text-xs text-ink-muted">Several messages are analysed as a batch</span>
```

with

```tsx
                    <span className="text-sm font-medium text-ink">{simple ? 'Drop the email file here, or choose it' : 'Drop .eml, .msg, .mbox or .zip files, or choose them'}</span>
                    <span className="text-xs text-ink-muted">{simple ? 'Not sure how? See How do I get the email? below.' : 'Several messages are analysed as a batch'}</span>
```

5. Replace `placeholder="Paste the full message, headers first."` with:

```tsx
                placeholder={simple ? 'Paste the whole email here.' : 'Paste the full message, headers first.'}
```

6. Between `</Panel>` and `<RecentAnalyses />`, add:

```tsx
      {simple && <GetTheEmail />}
```

7. In `frontend/src/App.tsx` line 248, change `screen = <TriageScreen />;` to `screen = <TriageScreen session={session} />;`.

- [ ] **Step 5: Run the checks and watch them pass**

Run: `cd frontend && npm test && npx tsc --noEmit && npm run build`
Expected: all pass.

Run: `PHISHHAWK_FRONTEND_BUILD=frontend/dist PHISHHAWK_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python -m pytest tests/server/test_frontend_browser.py -p no:cacheprovider -rs`
Expected: every test passes (none skipped).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/phishhawk/GetTheEmail.tsx frontend/src/screens/TriageScreen.tsx frontend/src/App.tsx tests/server/test_frontend_browser.py
git -c "user.name=Vinit Rami" -c "user.email=274839285+vinitrami-Soc@users.noreply.github.com" commit -m "A simple upload page that shows how to get the email out of a mail app"
```

---

### Task 5: Docs, changelog, full check and the PR

**Files:**
- Modify: `docs/FRONTEND.md` (the browser-test paragraph at lines 27-35; a new section before `## The rules`)
- Modify: `CHANGELOG.md` (`## [Unreleased]`)

- [ ] **Step 1: Describe the simple view in `docs/FRONTEND.md`**

In the paragraph that lists what the browser tests cover, replace "someone who signs up alone, goes through the setup and analyses a first message;" with "someone who signs up alone, goes through the setup, gets the simple pages and the switch back to the technical ones, and analyses a first message;".

Add before `## The rules`:

```markdown
## The simple view, for someone on their own

An individual account sees two pages in plain words: the upload page, with a
"How do I get the email?" guide for Gmail, Outlook and Apple Mail, and the
analysis page, with the verdict, up to three reasons and what to do now. The
words are in `src/app/plain.ts`. A "Show technical details" switch
(`src/components/phishhawk/TechnicalSwitch.tsx`) brings back the technical
pages; the choice lasts while the tab is open, because browser storage is kept
for the theme (`src/app/technical.ts`). Organization accounts always see the
technical pages, with no switch. Design:
`docs/superpowers/specs/2026-10-26-simple-view-design.md`.
```

- [ ] **Step 2: Add the changelog entry**

Under `## [Unreleased]`, above `### Security`, add:

```markdown
### Added

- **A simple view for someone checking their own mail.** An individual
  account's analysis page shows the verdict in plain words, up to three
  reasons and what to do now, including what to do after clicking a link or
  sharing card details. Its upload page explains how to get the email out of
  Gmail, Outlook or Apple Mail. "Show technical details" brings back the full
  pages while the tab is open. Organization accounts are unchanged.
```

- [ ] **Step 3: Run every check**

Run from the repo root:

```bash
ruff check src tests samples eval tools phishhawk
mypy
python -m pytest -p no:cacheprovider
cd frontend && npm test && npx tsc --noEmit && npm run build && cd ..
PHISHHAWK_FRONTEND_BUILD=frontend/dist PHISHHAWK_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python -m pytest tests/server/test_frontend_browser.py -p no:cacheprovider -rs
git status --short
```

Expected: ruff and mypy clean; pytest ends with "passed" and no failures; the frontend checks pass; every browser test passes with none skipped; `git status` shows only the two doc files (the build output is ignored).

- [ ] **Step 4: Commit, push and open the PR**

```bash
git add docs/FRONTEND.md CHANGELOG.md
git -c "user.name=Vinit Rami" -c "user.email=274839285+vinitrami-Soc@users.noreply.github.com" commit -m "Document the simple view"
git push -u origin claude/simple-view-spec
```

Open the PR to `main` with the repository's template (`.github/pull_request_template.md`), ending with:

```
🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_015tJLsgYc3M9hFkgMTR6a7T
```

Merge it with `expectedHeadSha` once every check is green.

- [ ] **Step 5: Before the next release**

Check the Outlook steps in a real Outlook.com mailbox (spec, section 4). If the menu names differ, correct `GetTheEmail.tsx` and the spec in one small PR.
