# Simple view for individual accounts: design

Status: approved in conversation on 2026-10-26. Builds on workspaces and
sign-up (2026-10-13-workspaces-signup-feedback-design.md).

## 1. What the user asked for, and the decisions

A friend who tried the live app said: "I don't know what the .eml format is,
or what the downloaded formats are." Someone checking their own mail is often
not technical, but the app speaks to a SOC analyst everywhere. The analysis
page even tells an individual to "Escalate to L2" and to "Hunt the attachment
SHA-256 values in EDR".

Decisions confirmed by the user:

- **Individual accounts see a simple view by default.** A switch, "Show
  technical details", brings back today's full page. The choice is remembered.
- **Organization accounts keep the full view.** They see no switch.
- **The upload page gets the simple view too**, with a short guide to getting
  the email out of Gmail, Outlook or Apple Mail.
- **Approach A: the web app only.** The engine, the command line, the JSON
  report and its schema, the REST API and the HTML report do not change.

The app's text stays in English.

## 2. Who sees what

| Account | Default | Switch shown | Analysis page | Upload page |
|---|---|---|---|---|
| Organization (admin or analyst) | Technical | No | Today's page | Today's page |
| Individual, switch off | Simple | Yes | Simple page (section 3) | Simple page (section 4) |
| Individual, switch on | Technical | Yes | Today's page, plus the switch | Today's page, plus the switch |

One choice drives both pages, and it lasts while the tab is open: moving
between pages keeps it, and a reload or a new visit starts simple again. It is
held in memory only. The frontend's locked rules (`src/__tests__/rules.test.ts`)
keep browser storage for the theme alone, and the user chose this over changing
them (2026-10-26). Nothing is stored on the server.

**The top bar follows the same choice** (added on 2026-10-26, at the user's
request). With the switch off, an individual's bar has "Check an email"
(Triage) and "My emails" (Queue), and More holds Settings, Profile and
Feedback. Campaigns, Audit, Health, Users, Tokens and Mailboxes are left out:
the pages still answer at their addresses, and turning the switch on brings
them back to the bar at once. The Queue page is then called "My emails",
Triage's "Recent analyses" becomes "Your recent checks" with "See all", and
the simple analysis page's back link reads "My emails". The browser tab's
title stays as it is, because `src/app/routes.ts` is locked. Every page and the
bar read one shared choice (`onTabChoice` in `src/app/technical.ts`), so the
switch changes them together.

## 3. The simple analysis page

Top to bottom:

1. **The switch**, "Show technical details". Its description reads:
   "Indicators, authentication checks, ATT&CK, the full report and downloads."
2. **The verdict** in plain words (3.1), in the verdict's colour, with the
   words always written out, so colour is never the only signal.
3. **Which email this is:** the subject, the sender and when it was checked,
   shown as text (the address through `showIndicator`, as today).
4. **Why we think so** (3.2), for every verdict except NO STRONG INDICATORS.
5. **What to do now** (3.3).
6. **"Was this verdict right?"**: the existing `VerdictQuestion`, unchanged.
7. **Delete this message**, when today's page offers it (`deleteNow` in
   `analysisActions`), with the same confirmation.

Hidden in the simple view: the score, the tabs (Indicators, Authentication,
ATT&CK, Report, Files), technique IDs, SHA-256 values, the Analysis status and
Limitations cards, the command bar's copy actions and the quick-actions dock.

A message that is still being analysed, or whose analysis failed, shows the
same states as today. Once a message is deleted its findings are gone, so "Why
we think so" says "The details were deleted with the message." instead of
guessing; the verdict and the steps still show.

### 3.1 The verdict

| Verdict | Headline | Line under it |
|---|---|---|
| MALICIOUS | This email is dangerous. | Security services already know a link or file in it as harmful. |
| LIKELY PHISHING | This email is very likely a scam. | It shows several signs that scammers use. |
| SUSPICIOUS | Be careful with this email. | Some things look wrong, but we can't be sure. |
| NO STRONG INDICATORS | No warning signs found. | This doesn't prove it's safe: if it asks for money or your password, check with the sender another way. |

The word "safe" is never used as a verdict.

### 3.2 Why we think so

Each finding (`Signal`) carries a `family`, one of the engine's `FAMILIES`. The
simple view turns families, not individual findings, into reasons:

| Family | Reason |
|---|---|
| `sender` | The sender pretends to be someone you trust. |
| `link` | A link leads somewhere other than it shows, or to a kind of website often used for scams. |
| `attachment` | An attachment could harm your device or ask for your password. |
| `content` | The wording pushes you to act fast, pay, or sign in. |
| `auth` | The email could not be confirmed as coming from the address it shows. |
| `evasion` | The email hides parts of itself to get past spam filters. |
| `intel` | Security services already report a link or file in this email as harmful. |
| `policy` | It matches a block list or rule set on your account. |

Rules:

- Sort the findings by severity (high, then medium, then low), keeping the
  engine's order within a severity.
- Take the first finding of each family and show its family's reason.
- Show at most 3 reasons.
- Skip findings whose family is empty or unknown.
- If no reason is left and the verdict is not NO STRONG INDICATORS, show one
  reason: "Several smaller warning signs add up."

### 3.3 What to do now

MALICIOUS and LIKELY PHISHING:

1. Don't click any link, open any attachment, or reply.
2. Report it as phishing in your email app, then delete it. In the UK you can
   also forward it to report@phishing.gov.uk.
3. **Already clicked a link or typed a password?** Change that password now,
   and anywhere else you use it, and turn on 2-step verification.
4. **Shared bank or card details?** Call your bank on the number on the back of
   your card.

SUSPICIOUS:

1. Don't click links or open attachments yet.
2. Check with the sender another way: call them, or type their website address
   yourself.
3. If it turns out to be fake, report it as phishing and delete it.

NO STRONG INDICATORS:

1. If it asks for money, a password or urgent action, check with the sender
   another way first.

The steps are fixed text. None of them contains a value from the message.

## 4. The simple upload page

- **Title:** "Check an email".
- **Description:** "Save the email from your email app and drop it here, or
  copy and paste it."
- **Drop zone:** "Drop the email file here, or choose it", and under it "Not
  sure how? See How do I get the email? below." It accepts the same files as
  today (`.eml`, `.msg`, `.mbox`, `.zip`), so nothing a person already does
  stops working; only the words change.
- **Paste:** the Upload files / Paste the message toggle stays as it is. The
  paste box's placeholder becomes "Paste the whole email here."
- **The switch**, as on the analysis page.
- **A note:** "Check emails you received. Don't upload confidential work email."
- **"How do I get the email?"**: three collapsible sections.

**Gmail (on a computer)**

1. Open the email.
2. Click ⋮ (More), next to Reply.
3. Choose **Download message**.
4. Drop the downloaded file here.

Or choose **Show original** instead, click **Copy to clipboard**, and paste it
below.

**Outlook (Outlook.com or Outlook on the web)**

1. Open the email.
2. Click … (More actions).
3. Choose **Download**, then **Download as EML**. (Some versions say **Save
   as**, then **Save as EML**.)
4. Drop the downloaded file here.

A file saved from Outlook can leave out the hidden lines that show who really
sent the email. PhishHawk still checks its links, attachments and wording; the
sender checks are then left out, as they are today for any message without
them.

**Apple Mail (Mac)**

1. Select the email.
2. Choose **File**, then **Save As**.
3. Set **Format** to **Raw Message Source**, and save.
4. Drop the saved file here.

Or drag the email from the list to your desktop, and drop that file here.

**On a phone:** "Phone email apps can't save the email file. Open your email on
a computer instead."

The Gmail and Apple Mail labels match Google's and Apple's own help pages as
of 2026-10-26. No Microsoft page was found for Outlook, so its labels come from
third-party guides (section 8); the build checks them in a real Outlook.com
mailbox before release and corrects the text if they differ.

## 5. How it is built

All changes are in `frontend/`.

| File | Change |
|---|---|
| `src/app/plain.ts` (new) | `plainVerdict(verdict)` returns `{ headline, detail }`. `plainReasons(verdict, signals)` returns up to 3 strings (section 3.2). `plainSteps(verdict)` returns `{ lead?: string; text: string }[]` (section 3.3). Pure functions, no React. |
| `src/app/technical.ts` (new) | `switchable(session)`: true for an individual workspace. `technicalView(session, choice)`: true unless the workspace is an individual one whose choice is off. `tabChoice()` and `rememberForTab(next)` hold this tab's choice in memory. |
| `src/components/phishhawk/TechnicalSwitch.tsx` (new) | `useTechnicalView(session)` returns `{ technical, switchable, setTechnical }`; `TechnicalSwitch` draws the switch, or nothing when the session is not switchable. |
| `src/components/phishhawk/SimpleAnalysis.tsx` (new) | The verdict, the email, the reasons and the steps (section 3), from the `Analysis` the screen already loads. |
| `src/components/phishhawk/GetTheEmail.tsx` (new) | The guide in section 4. |
| `src/screens/AnalysisScreen.tsx` | When `technical` is false, render the switch, `SimpleAnalysis`, `VerdictQuestion` and the delete button in place of today's page. Otherwise today's page, with the switch under the Queue link. |
| `src/screens/TriageScreen.tsx` | Takes the session. When `technical` is false, use section 4's words and show `GetTheEmail`. Shows the switch when `switchable` is true. |
| `src/App.tsx` | Passes the session to `TriageScreen`. |
| `tests/test_plain_words.py` (new) | Every family in the engine's `FAMILIES` has a reason in `plain.ts`, so a new family cannot be forgotten. |
| `docs/FRONTEND.md`, `CHANGELOG.md` | Describe the simple view; CHANGELOG under Unreleased, Added. |

The switch is the existing `Switch` component from `components/ui/ui.tsx`.

Nothing changes on the server: the session already carries
`workspace.kind`, and each finding already carries its `family`. The server
still checks every request, so the simple view is presentation only, like
`app/permissions.ts`.

## 6. Testing

- **Unit tests** (`npm test`, which runs `tsx --test`):
  - `plain.test.ts`: every verdict has a headline, a detail line and at least
    one step; every family in `FAMILIES` has a reason; reasons are at most 3, one
    per family, highest severity first; unknown and empty families are
    skipped; the fallback reason appears only when nothing else does; no
    verdict text contains the word "safe" except in "doesn't prove it's safe".
  - `technical.test.ts`: organization sessions, and sessions without a
    workspace, are always technical and not switchable; individual sessions are
    simple until their choice is on; the tab's choice starts off and keeps what
    was last remembered.
- **Browser test** (`tests/server/test_frontend_browser.py`, run by the CI job
  "The server and a browser"):
  - An individual account sees the guide on the upload page and submits a
    sample. The analysis page shows the plain headline and the steps, and no
    ATT&CK tab. Turning the switch on shows the tabs; going to the Queue and
    back keeps them; a reload shows the simple page again.
  - An organization account sees the tabs and no switch, on both pages.
- `npx tsc --noEmit`, `npm run build` and the existing Python tests stay
  green. The existing test for someone who signs up alone waits for the plain
  headline instead of "LIKELY PHISHING".
## 7. Out of scope

- Languages other than English.
- A simple HTML report, simple downloads, or a simple command line.
- Remembering the choice after a reload, or on another device.
- Simpler words inside the Queue's filters and on the Batch and Campaign
  pages, and in the tour after sign-up.
- An interactive "Did you click?" flow. The fixed steps cover both cases.

## 8. Sources for the upload guide

- Gmail, Show original and Copy to clipboard: [Trace an email with its full
  header](https://support.google.com/mail/answer/29436).
- Gmail, Download message: [How-To Geek](https://www.howtogeek.com/791699/download-emails-from-gmail/),
  [Atlassian KB](https://support.atlassian.com/jira/kb/how-to-create-an-eml-file-for-a-email/).
- Outlook, Download as EML and Save as EML, and the missing original headers:
  [CodeTwo KB](https://www.codetwo.com/kb/export-email-to-file/).
- Apple Mail, Raw Message Source: [Save emails as files or PDFs in Mail on
  Mac](https://support.apple.com/guide/mail/mlhlp1044/mac).
- The UK reporting address: the NCSC's Suspicious Email Reporting Service,
  report@phishing.gov.uk.
