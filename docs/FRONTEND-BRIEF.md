# PhishHawk v3: frontend build brief (for Google AI Studio)

**How to use this file**

1. In Google AI Studio (Build), start a new app and paste this whole file as the
   first message.
2. Attach two files from the PhishHawk repository:
   - `docs/api/openapi.json`, the API;
   - `docs/report.schema.json`, the full analysis report.

   `openapi.json` describes the M1 API. Until M1 is merged, it comes from
   the tested M1 prototype and there is no server to call yet: build against
   the mock API from section 3. Examples in this brief that show `<...>` or
   `"...": "..."` are abbreviated (rule 10 in section 2.2).
3. Then ask for one screen at a time, in the order of section 7.
4. Sections 2, 4, 5 and 6 are rules. Section 1 is yours to play with. Section
   12 is the order of work.

---

## 0. What you are building

PhishHawk is a self-hosted phishing triage service for a small SOC team. An
analyst gives it a reported email; PhishHawk analyses it and returns:
- a verdict and a risk score;
- the evidence, defanged indicators and MITRE ATT&CK techniques;
- a full HTML report;
- six export formats (JSON, STIX 2.1, MISP, Markdown, CSV, HTML) and a manifest.

**The backend is finished and fixed.** You are building only the frontend: a
single-page app that talks to the PhishHawk API on the same server.

- The app is served at `https://<phishhawk-server>/app/`.
- The API lives at `/api/v1/...` on the same origin.
- PhishHawk also has simple built-in pages at `/`. They stay as the backup and
  admin interface; your app is the main one.

v3 arrives in three milestones. Section 7 covers M1, which your app needs
first. Sections 8 and 9 cover M2 and M3: design those screens now, and wire
them when their endpoints exist.

| Milestone | What the backend adds |
|---|---|
| **M1** | Log in, submit one message (upload or paste), the verdict and full report, six downloads, re-analyze, delete, hold, settings, users and API tokens, audit log, health. |
| **M2** (planned) | Batch upload (several files, `.mbox`, `.zip`) with combined downloads, campaigns across messages, queue filters by source, date and user, and a "Test connection" button for providers. |
| **M3** (planned) | Importing reported mail from IMAP, Microsoft Graph and Gmail mailboxes (read-only), managed by admins. |

---

## 1. Your creative freedom

The look and feel are entirely yours, including:
- layout and navigation;
- colours, typography, light and dark themes;
- icons and illustrations;
- motion, animations, transitions and micro-interactions;
- glassmorphism, gradients, 3D, particles and charts;
- loading skeletons and empty states;
- how the verdict "feels".

Nothing in this brief prescribes a style. Make it beautiful.

Three things to keep while you create:

- **Motion respects `prefers-reduced-motion`.** Give it a calm version.
- **Text stays readable**: WCAG AA contrast (4.5:1 for normal text) in every
  theme, a visible keyboard focus, and everything usable by keyboard.
- **Meaning never rests on colour alone.** A verdict always shows its words
  (for example "LIKELY PHISHING") next to whatever colour or icon you give it.

Everything else (sections 2 to 6) is about safety and the contract with the
backend. It limits *how* you build things, not *what they look like*.

---

## 2. Non-negotiable rules

### 2.1 Do

1. **Render every value that comes from an email as plain text**: React
   `{value}` or `textContent`. Section 5 lists those values.
2. **Show indicators defanged**, for example `hxxps://evil-login[.]top/...`.
   Use `urls[].defanged` where the report gives it. For other indicators, use
   the `showIndicator()` helper in section 5.2.
3. **Show the full HTML report only inside this exact sandboxed iframe:**

   ```html
   <iframe
     sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
     src="/api/v1/analyses/{id}/files/{html-file-name}"
     title="Full report"
     loading="lazy">
   </iframe>
   ```

   `{id}` is the analysis ID and `{html-file-name}` is the `name` of the
   `files[]` entry whose `kind` is `html`, passed through `encodeURIComponent`.
   The server serves that file with its own sandboxing policy.

   The parent application must never read, query, modify or inject content into
   the iframe DOM. Never fetch the HTML report and insert it into the parent
   page.

   Do not add `allow-scripts` or `allow-same-origin`. Do not loosen or remove
   any existing sandbox permission.
4. **Use relative URLs** for every request (`/api/v1/...`), so the browser
   sends the session cookie.
5. **Keep the CSRF token in memory only** (a variable or React state). Send it
   as the `X-CSRF-Token` header on every POST, PATCH and DELETE, except the
   login request itself.
6. **Bundle everything with npm and Vite**: libraries, fonts (for example
   `@fontsource/*` packages), icons and images.
7. **Ask before destructive actions.** "Delete now" and "Delete completely"
   need a confirmation that says what will be lost.
8. **Handle every error status** in section 4.5 with a clear, human message.
9. **Start downloads only when the user clicks.** The server records every
   download in the audit log.
10. **Treat the role as a display hint.** The server enforces permissions;
    you only hide buttons a user cannot use (section 6).
11. **Use an explicit route allowlist.** The frontend may navigate only to
    routes defined in the frontend route section (section 7.1) and to
    same-origin API/file URLs defined in the backend contract.
12. **Use an explicit vocabulary allowlist.** Values such as verdict, severity,
    role, status, source, kind and action must be mapped through fixed lookup
    tables. Never use API values directly as CSS classes, inline styles, HTML
    attributes or component names.
13. **Keep API data in memory only.** In-memory query/cache state is allowed
    during the current page session, but it must be cleared on logout,
    session expiry and a 401 response.
14. **Use AbortController** for polling, search, route changes and any request
    that can become irrelevant when the user leaves a screen.

### 2.2 Don't

1. **Never** pass email data to `dangerouslySetInnerHTML`, `innerHTML`,
   `outerHTML`, `insertAdjacentHTML`, `document.write` or a Markdown, HTML or
   rich-text renderer.
2. **Never** build an `href`, `src`, `action`, CSS value or class name from
   attacker-controlled email data. Never make an indicator clickable.

   An indicator is display-only data. Never pass an indicator value to:

   - `href`;
   - `src`;
   - `action`;
   - `fetch`;
   - `XMLHttpRequest`;
   - `window.open`;
   - `location`;
   - CSS;
   - an iframe URL;
   - a download URL.

   Copying the displayed defanged value to the clipboard is allowed.
3. **Never** fetch the HTML report and insert it into the page. Never remove
   or loosen the iframe's `sandbox`; never add `allow-scripts` or
   `allow-same-origin`.
4. **Never make a network request to another site from the browser.**

   This means:

   - no CDN;
   - no Google Fonts;
   - no Gemini or other AI API;
   - no analytics;
   - no error tracker;
   - no maps;
   - no remote images;
   - no reputation-provider request;
   - no `fetch()` or XHR to an external origin.

   Reported mail must not leave the PhishHawk server, and the server's security
   policy blocks these requests anyway.

   The only permitted external navigation is a normal user-clicked link to an
   approved MITRE ATT&CK technique URL generated by the strict `attackUrl()`
   allowlist. The frontend must never fetch that URL, embed it, prefetch it or
   send data to it.
5. **Never** store API data, passwords, API keys or the CSRF token in
   `localStorage`, `sessionStorage`, IndexedDB, cookies or a service-worker
   cache. Never log API data to the console. A theme preference in
   `localStorage` is fine.
6. **Never** use `eval`, `new Function`, inline `<script>` blocks, an import
   map, or `javascript:` URLs.
7. **Never refang or open an indicator.**

   This includes:

   - building a VirusTotal link;
   - building a urlscan.io link;
   - building a reputation-provider URL;
   - calling `window.open()` with an indicator;
   - placing an indicator in an iframe;
   - using an indicator as an image source;
   - using an indicator as a download target.

   The only exception is the fixed, validated MITRE ATT&CK URL returned by
   `attackUrl()` for a valid technique ID.
8. **Never** add a backend, a proxy, server-side rendering or API routes of
   your own. The app is static files only.
9. **Never** invent API fields or endpoints. If something is missing, show
   what exists, mark the gap with a visible `NEEDS BACKEND` label, and leave a
   `// NEEDS BACKEND:` comment in the code.
10. **Do not trust abbreviated examples as API contracts.** The attached
    `openapi.json` and `report.schema.json` are the source of truth. Any
    example containing `<...>` or omitted fields is illustrative only and
    must not be implemented as a literal field.

### 2.3 What the server's Content-Security-Policy allows

Every response for `/app/` carries this policy:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; frame-src 'self'; form-action 'self';
frame-ancestors 'none'; base-uri 'none'
```

What that means for your choice of libraries:

| Works | Blocked |
|---|---|
| Plain CSS, CSS Modules, Tailwind compiled by Vite (`@tailwindcss/vite`) | The Tailwind Play CDN, any `<link>` to another site |
| React `style={{...}}` props, Framer Motion, GSAP, the Web Animations API, CSS animations | Libraries that inject `<style>` tags at run time (styled-components, Emotion, and so MUI by default) |
| SVG icons as components (for example `lucide-react`), inline SVG, `data:` images | Icon fonts or images from a CDN |
| Canvas and WebGL (for example three.js, bundled), chart libraries that draw SVG or canvas | WebAssembly runtimes (for example Rive, `dotlottie` players) and Lottie expressions (they use `eval`) |
| Self-hosted fonts from npm | Google Fonts |

**How to check:** run the built app from PhishHawk (section 10). Any console
message that starts with "Refused to ..." names the thing the policy blocked.
Replace it, or bundle it.

---

## 3. Project setup

- React and TypeScript with Vite. The router is your choice; it must work
  under the base path `/app/`.
- In `vite.config.ts`, set `base: '/app/'`.
- `npm run build` produces `dist/`. That folder is all the server needs.
- For development without a server, write a small mock API layer that returns
  the example responses from section 7. Turn it on only when
  `import.meta.env.DEV` is true, so it never ships in the build.
- Put all API calls in one typed API client (the `src/api/` folder in section
  3.1). It adds the CSRF header, parses errors (section 4.5) and sends the user
  to login on a 401.

### 3.1 Required frontend structure

Use a clear feature-based structure similar to:

```text
src/
  app/
    App.tsx
    routes.tsx
    providers.tsx

  api/
    client.ts
    errors.ts
    session.ts
    submissions.ts
    analyses.ts
    settings.ts
    users.ts
    tokens.ts
    audit.ts

  auth/
    AuthContext.tsx
    ProtectedRoute.tsx
    roleGuards.ts

  components/
    VerdictBadge.tsx
    ScoreCard.tsx
    IndicatorValue.tsx
    FileDownloadList.tsx
    ConfirmDialog.tsx
    LoadingState.tsx
    EmptyState.tsx
    ErrorState.tsx

  features/
    login/
    submit/
    queue/
    analysis/
    settings/
    users/
    tokens/
    audit/

  security/
    defang.ts
    vocabulary.ts
    safeLinks.ts

  styles/
    tokens.css
    globals.css
```

This is a guide, not a requirement to use exactly these filenames. Do not add
a backend, proxy, server-side renderer or custom API route.

---

## 4. Talking to the backend

### 4.1 Session and login

```
App start      GET /api/v1/session
               200 -> {"user_id": 2, "username": "alice", "role": "analyst",
                       "via": "session", "scope": "full", "csrf": "<token>"}
                      keep csrf and the user in memory, show the app
               401 -> show the login screen

Log in         POST /api/v1/session   JSON {"username": "...", "password": "..."}
               200 -> {"csrf": "<token>"} and an HttpOnly cookie (you cannot read it; that is fine)
                      then GET /api/v1/session for the user and role
               401 -> "Wrong username or password"
               429 -> too many tries: the Retry-After header gives the seconds to wait; show a countdown

Log out        DELETE /api/v1/session  with X-CSRF-Token  -> 204; clear everything in memory
```

A session ends after 8 hours of inactivity. Any 401 means: clear state and
show login.

### 4.2 Session refresh rules

- On every full page load, call `GET /api/v1/session`.
- If it returns 200, replace the in-memory user and CSRF token with the new
  values.
- If it returns 401, clear all in-memory state and show login.
- Never restore a session from localStorage, sessionStorage, IndexedDB or a
  service-worker cache.
- If a state-changing request returns 403 and the error indicates a CSRF
  problem, call `GET /api/v1/session` once, replace the in-memory CSRF token,
  and retry the original request once.

  The server marks a CSRF problem with a 403 whose `detail` is exactly
  `the form is out of date: reload the page and try again`. Every other 403 is
  a permission refusal (for example `only an admin can do that`): show it and
  do not retry.
- Never retry a failing request indefinitely.
- If the retry also fails, show a clear error and leave the current page state
  unchanged.

### 4.3 Requests that change something

Every POST, PATCH and DELETE except `POST /api/v1/session` requires:

```http
X-CSRF-Token: <csrf-token>
```

Without it the server answers 403. The token must exist in memory before the
request is sent.

The API client must:

1. add the header automatically;
2. never expose the token in the URL;
3. never log the token;
4. never persist the token;
5. refresh and retry once after a CSRF-specific 403 (section 4.2);
6. clear it on logout, 401 or session expiry.

### 4.4 Waiting for a verdict

After a submit returns 202, poll:

```text
GET /api/v1/submissions/{id}
```

Poll approximately every 1.5 seconds. An analysis usually takes about a second.

- `queued`: waiting to start.
- `running`: analysis is in progress.
- `done`: `analysis_id` is available; navigate to the analysis page.
- `failed`: show the server-provided `error` as text, for example "this
  message exceeded the analysis limits".

Polling requirements:

- Use `AbortController`.
- Stop polling when a terminal state is reached.
- Stop polling when the user leaves the screen.
- Stop polling after five minutes.
- Do not create more than one active polling loop for the same submission.
- If a temporary network error occurs, show a retry option.
- Do not silently continue polling forever.

After five minutes, say that the analysis is taking longer than expected and
offer a "Check again" button. The server keeps working; the result will also
appear in the queue.

### 4.5 Errors

Every API error is JSON: `{"error": "<code>", "detail": "<human text>"}`.
`detail` is safe to show as text.

| Status | `error` | Meaning; what to show |
|---|---|---|
| 400 | `bad_request` | Bad input, for example an empty message. |
| 401 | `unauthorized` | Not logged in or session expired: go to login. |
| 403 | `forbidden` | Not allowed for this role, or the CSRF token is missing or stale (section 4.2 tells them apart). |
| 404 | `not_found` | No such item. |
| 409 | `conflict` | The message is on hold; an admin must release it before deleting. |
| 410 | `gone` | The message and its reports were deleted after the retention period; the verdict and the record stay. |
| 413 | `too_large` | The file is over the upload limit (25 MB by default). |
| 415 | `unsupported` | Not an `.eml` or `.msg` message. |
| 422 | `invalid` | A form value is wrong; `detail` says which. |
| 429 | `throttled` | Too many login tries; wait `Retry-After` seconds. |

### 4.6 Network and unexpected errors

Handle these cases even when the server does not return the standard JSON
error shape:

- network disconnected;
- request timeout;
- invalid JSON response;
- unexpected 5xx response;
- aborted request;
- browser blocked request;
- download failure.

Do not show raw stack traces, response bodies or tokens.

Use a short human message, for example:

```text
The PhishHawk server could not be reached. Check the connection and try again.
```

For a request that was intentionally aborted because the user changed screens,
do not show an error toast.

---

## 5. Data that comes from an attacker

### 5.1 What counts

Everything that comes from a reported email is attacker-controlled. Render it
as text, defanged where it is an indicator. In the API that is:

- in analysis objects: `subject`, `sender`, `sender_domain`, and the file
  `name`s (these are safe names, but treat them as text anyway);
- everything inside `report`, the full JSON report described by
  `report.schema.json`. That includes `subject`, `from_display`,
  `from_address`, `to`, `reply_to`, `summary`, every `signals[].label`,
  `urls[]`, `attachments[].filename`, `lookalikes[]`, `iocs[]`,
  `recommendations`, `hops` and `qr_codes`;
- in the audit log: `actor`, which a failed login fills with whatever was typed
  as a username, and every value in `details`.

Values that are fixed vocabulary are safe to map to your own styles: `verdict`,
`signals[].severity`, `status`, `role`, `scope`, `source`, `kind` and `action`.
Even so, map them through a lookup table; never put them into a class name or
style directly.

### 5.2 Helpers to use

```typescript
// iocs[].type is one of these.
const INDICATOR_TYPES = new Set([
  "url",
  "domain",
  "ipv4",
  "ipv6",
  "email",
  "sha256",
  "crypto-wallet",
  "phone",
]);

const ALLOWED_ATTACK_ID = /^T\d{4}(?:\.\d{3})?$/;

// The engine's rule: hxxp(s):// for the scheme, [.] for every dot in the host.
export function defangUrl(value: string): string {
  const text = String(value);
  const match = text.match(/^(https?|hxxps?|ftp):\/\/([^/?#]+)(.*)$/i);

  if (!match) {
    return defangDomain(text);
  }

  const scheme = match[1].toLowerCase();
  const safeScheme =
    scheme === "ftp" ? "ftp" : scheme.endsWith("s") ? "hxxps" : "hxxp";
  const host = defangDomain(match[2]);

  return `${safeScheme}://${host}${match[3]}`;
}

export function defangDomain(value: string): string {
  return String(value).split(".").join("[.]");
}

export function defangEmail(value: string): string {
  return String(value).split("@").join("[@]").split(".").join("[.]");
}

export function showIndicator(type: string, value: string): string {
  const indicatorType = String(type);
  const text = String(value);

  if (!INDICATOR_TYPES.has(indicatorType)) {
    return text;
  }

  if (indicatorType === "url") {
    return defangUrl(text);
  }

  if (indicatorType === "domain" || indicatorType === "ipv4") {
    return defangDomain(text);
  }

  if (indicatorType === "email") {
    return defangEmail(text);
  }

  return text;
}

export function attackUrl(id: string): string | null {
  const techniqueId = String(id);

  if (!ALLOWED_ATTACK_ID.test(techniqueId)) {
    return null;
  }

  const path = techniqueId.replace(".", "/");
  return `https://attack.mitre.org/techniques/${path}/`;
}
```

For example, `showIndicator("url", "https://evil-login.top/login?next=")`
gives `hxxps://evil-login[.]top/login?next=`, `showIndicator("ipv4",
"203.0.113.7")` gives `203[.]0[.]113[.]7`, and `showIndicator("email",
"pay@evil-login.top")` gives `pay[@]evil-login[.]top`. A URL without a scheme
gets every dot defanged. `ipv6`, `sha256`, `crypto-wallet` and `phone` values
are shown unchanged, as text.

Use `showIndicator()` only for values whose type is known to be an indicator.
Never run it on:

- subjects;
- display names;
- filenames;
- report prose;
- recommendations;
- audit details;
- API error messages.

`attackUrl()` is navigation-only. Never fetch, prefetch, iframe, proxy or
embed its result. Open it only after a deliberate user click with:

```tsx
<a
  href={attackUrl(technique.id) ?? undefined}
  target="_blank"
  rel="noopener noreferrer"
>
  {technique.id}
</a>
```

If the technique ID is invalid, render it as plain text and do not create a
link.

Links to `attack.mitre.org` are the only external links the app has.
Navigation away is not a request the CSP blocks.

### 5.3 Safe rendering rules

- Use React text interpolation for attacker-controlled values.
- Never use `dangerouslySetInnerHTML`.
- Never use a Markdown renderer for email-derived content.
- Never use a rich-text renderer for report values.
- Never use attacker-controlled values as CSS classes.
- Never use attacker-controlled values as inline style property names or URLs.
- Never use attacker-controlled values as React component names.
- Never use attacker-controlled values as DOM event-handler attributes.
- Fixed vocabulary must be mapped through a constant lookup table.
- Unknown vocabulary values must render as neutral text, not as a guessed style.

---

## 6. Roles: what to show to whom

`GET /api/v1/session` returns `role`: `analyst` or `admin`.

| Action | Analyst | Admin |
|---|---|---|
| Submit, see every analysis, download exports, re-analyze | yes | yes |
| Download the raw message, "Delete now" | only for messages they submitted: show it when `analysis.submitted_by == session.user_id` (the server decides; if the same message was also submitted by someone else, it may allow more) | yes |
| Hold and release, "Delete completely" | no | yes |
| Settings, users, API tokens | no | yes |
| Audit log | own actions | everyone's |

Further conditions:
- While `hold` is true, show no delete buttons; deleting returns 409.
- When `tier1_deleted_at` is set, the message and reports are gone. Show the
  verdict and the record, with no downloads, no report frame, no
  re-analyze and no "Delete now".

### 6.1 Role enforcement reminder

Role checks are only presentation logic.

The frontend must hide or disable controls that the role cannot use, but the
server remains the authority. Do not assume that a hidden button makes an
operation safe.

For every destructive action:

1. Check the current role.
2. Check the current object state.
3. Ask for confirmation.
4. Send the request with the CSRF header.
5. Refresh the object from the server.
6. Show the server's final state.

---

## 7. Milestone 1 screens and their API

The API is fully defined in `openapi.json`. The shapes below are real
responses, abbreviated where they show `<...>` or `"...": "..."`.

### 7.1 Required M1 routes

Use routes equivalent to:

```text
/app/
/app/login
/app/analyses
/app/analyses/:id
/app/settings
/app/users
/app/tokens
/app/audit
/app/health
```

Requirements:

- `/app/login` is public.
- `/app/`, `/app/analyses` and `/app/analyses/:id` require a valid session.
- `/app/settings`, `/app/users`, `/app/tokens` require the admin role.
- `/app/audit` requires a valid session; the server determines which entries
  are visible.
- `/app/health` may be admin-only even though `/healthz` itself is public.
- Unknown frontend routes show a safe not-found screen.
- Reloading a deep link must work under the `/app/` base path.
- Do not place API data, credentials or tokens in route parameters. The
  numeric analysis ID in `/app/analyses/:id` is fine; accept only digits
  there, and show the not-found screen for anything else.

### 7.2 Login

`POST /api/v1/session` as in section 4.1. Show the error states: wrong
password, throttled with a countdown, and server unreachable.

### 7.3 Submit (home)

There are two ways in: drag and drop or pick a file (`.eml`, `.msg`), or paste
the raw message (headers and body).

Add an **Offline analysis** switch with this exact meaning:

> Do not send this message's indicators to reputation providers.

This does not mean that the browser is disconnected from the PhishHawk server.
The message still goes to the same-origin PhishHawk API for analysis.

Show the selected state clearly:

```text
Offline analysis enabled — reputation lookups will not be performed.
```

Send:

```text
offline=true
```

with the multipart submission.

```
POST /api/v1/submissions      multipart/form-data, X-CSRF-Token
  file=<the file>              or   raw=<pasted text>
  offline=true|false
202 -> {"id": 41, "status": "queued", "error": "", "analysis_id": null,
        "submitted_at": "2026-10-07T09:12:03+00:00"}
```

Then poll as in section 4.4. The same message twice is fine; the server
recognises it by its SHA-256. Show the last 10 analyses below the form, using
the first 10 of `GET /api/v1/analyses`.

### 7.4 Queue

```
GET /api/v1/analyses?q=<search>&verdict=<exact verdict>&offset=<n>
200 -> [ analysis summary, ... ]     (50 per page, newest first; empty list = no more)
```

- `q` matches a SHA-256 prefix, a report ID (`PH-...`) or any indicator value.
- `verdict` is one of `NO STRONG INDICATORS`, `SUSPICIOUS`, `LIKELY PHISHING`,
  `MALICIOUS`.

An analysis summary looks like this:

```json
{
  "id": 12, "message_id": 9, "submission_id": 41,
  "submitted_by": 2, "submitted_by_name": "alice",
  "source": "upload", "offline": true,
  "sha256": "372d0d6e533b23fd558a9eba1539feac4a752d335a362841427f7e568432c0f2",
  "report_id": "PH-372D0D6E533B23FD",
  "verdict": "LIKELY PHISHING", "score": 32,
  "sender": "it-servicedesk@examp1e-corp.co.uk", "sender_domain": "examp1e-corp.co.uk",
  "subject": "Urgent: password expires today - payroll review shared with you",
  "created_at": "2026-10-07T09:12:04+00:00",
  "providers": [], "lookups": [],
  "techniques": ["T1027", "T1027.006", "T1036", "T1036.007", "T1036.008", "T1204.002", "T1566",
                 "T1566.001", "T1583.001", "T1598.002", "T1598.003", "T1656"],
  "hold": false, "tier1_deleted_at": null,
  "files": [
    {"name": "phishhawk-report-372d0d6e533b-20261007.json", "kind": "json", "type": "JSON report",
     "size": 19270, "sha256": "<64 hex characters>", "available": true},
    {"name": "phishhawk-report-372d0d6e533b-20261007.stix.json", "kind": "stix", "type": "STIX 2.1 bundle", "...": "..."},
    {"name": "phishhawk-report-372d0d6e533b-20261007.misp.json", "kind": "misp", "type": "MISP event", "...": "..."},
    {"name": "phishhawk-report-372d0d6e533b-20261007.md", "kind": "md", "type": "Markdown note", "...": "..."},
    {"name": "phishhawk-report-372d0d6e533b-20261007.csv", "kind": "csv", "type": "CSV indicators", "...": "..."},
    {"name": "phishhawk-report-372d0d6e533b-20261007.html", "kind": "html", "type": "HTML report", "...": "..."},
    {"name": "phishhawk-report-372d0d6e533b-20261007.manifest.json", "kind": "manifest", "type": "Manifest", "...": "..."}
  ]
}
```

`subject` is `null` once the message has been deleted.

#### Queue states

The queue must support:

- initial loading;
- loading the next page;
- no analyses yet;
- no search results;
- no more results;
- invalid search;
- server error;
- expired session;
- retry;
- keyboard navigation;
- narrow mobile layout.

Do not load all analyses at once. Use the server's pagination.

### 7.5 Analysis

```
GET /api/v1/analyses/{id}
200 -> the summary above, plus "report": the full JSON report (null after deletion)
```

What this screen holds; the presentation is yours:

- **Verdict and score**, the report ID, the SHA-256, who submitted it and
  when, and whether it was analysed offline.
- **Why**, from the report:
  - `summary`, a list of sentences;
  - `signals`, each with `severity` (`high`, `medium` or `low`), `label` and
    `techniques`;
  - `analysis_status` (`status`, `reasons`, `reputation`);
  - `authentication` (`status`, `checks`, `explanation`).
- **Indicators**:
  - `urls`: use `defanged`, and show `flagged` and `notes`;
  - `attachments`: `filename`, `true_type`, `sha256`, `flagged`, `notes`;
  - `lookalikes`: `domain`, `target`, `method`;
  - `iocs`: `type`, `value` via `showIndicator`, and `context`.
- **ATT&CK**: `report.techniques` has `id`, `name` and `evidence` for each
  technique; link with `attackUrl()`.
- **What to do**: `recommendations`, a list of sentences; a checklist works
  well. `limitations` lists what the analysis could not check.
- **Outbound lookups**: `lookups`, each `{provider, method, url}`, which says
  what was sent to which reputation service.
- **Downloads**: one link per item in `files` with `available` true, to
  `/api/v1/analyses/{id}/files/{name}?download=1`. Add a link to the raw
  message, `/api/v1/messages/{message_id}/raw`, only for the owner or an admin.
- **The full report** in the sandboxed iframe from section 2.1. Optionally add
  a link to open it in a new tab: the same URL, which the server serves
  sandboxed.
- **Actions**:

```
Re-analyze           POST   /api/v1/analyses/{id}/reanalyze      -> 202 submission (then poll)
Delete now           DELETE /api/v1/messages/{message_id}?scope=tier1   -> {"deleted": "tier1"}
Delete completely    DELETE /api/v1/messages/{message_id}?scope=all     -> {"deleted": "all"}   (admin)
Hold / Release       POST / DELETE /api/v1/messages/{message_id}/hold   -> {"hold": true|false} (admin)
```

"Delete now" removes the message and its reports and keeps the verdict and
record. "Delete completely" removes everything; the audit log keeps the hash.
Explain this in the confirmation.

#### Download rules

- Do not automatically download or prefetch any file.
- Start a download only after a deliberate user click.
- Prefer a normal same-origin download link.
- Do not construct a download URL from an attacker-controlled filename.
- Use only the exact file URL returned or defined by the API contract. For an
  export that is `/api/v1/analyses/{id}/files/{name}?download=1`, built from
  the analysis `id` and the server-generated `files[].name` (passed through
  `encodeURIComponent`). Never use `attachments[].filename` or any other
  report value in a URL.
- Do not pass indicators into download URLs.
- If a file is unavailable, render it as unavailable text.
- If a download fails, show the error as text and do not expose the raw server
  response.
- The server records downloads in the audit log. Showing the report in the
  frame also counts as a `download` of the HTML file; that is expected.

#### Analysis state handling

If `hold` is true:

- show a visible hold banner;
- hide delete controls;
- explain that deletion returns a conflict until an admin releases the hold.

If `tier1_deleted_at` is set:

- show the retained verdict and record;
- show that the message content has been deleted;
- hide downloads;
- hide the report iframe;
- hide re-analyze;
- hide raw-message access;
- hide delete controls.

If `report` is null for any other reason:

- show a clear unavailable state;
- do not invent report content;
- do not crash the page.

After "Delete completely" the analysis no longer exists: `GET
/api/v1/analyses/{id}` returns 404, so show the not-found state.

### 7.6 Settings (admin)

```
GET   /api/v1/settings
PATCH /api/v1/settings     JSON with any subset of the fields below; returns the new view
```

```json
{
  "providers": ["virustotal", "rdap"],
  "protected_domains": ["example-corp.co.uk"], "allow_domains": [], "block_domains": [],
  "trusted_authserv": [],
  "retention_days": 30, "max_upload_mb": 25, "max_batch_messages": 500, "campaign_window_days": 90,
  "keys": {"virustotal": "...a1b2", "urlscan": "", "abuseipdb": ""}
}
```

- Providers: `virustotal`, `urlscan`, `rdap` (needs no key) and `abuseipdb`.
  All are off on a new install. Explain that turning one on sends indicators
  (never the email itself) to that service.
- Keys are only ever shown as their last four characters. To set one, send
  `{"keys": {"virustotal": "<new key>"}}`; to remove one, send `""`. Use a
  password field, and never echo a key back.
- Limits accept 1 to 100000.

### 7.7 Users and API tokens (admin)

```
GET   /api/v1/users            -> [{"id", "username", "role", "disabled", "last_login_at"}]
POST  /api/v1/users            {"username", "password", "role"}  -> 201 user
PATCH /api/v1/users/{id}       {"role"?, "disabled"?, "password"?}  -> user
GET   /api/v1/tokens           -> [{"id", "name", "scope", "user_id", "created_at", "revoked"}]
POST  /api/v1/tokens           {"name", "scope": "read"|"submit", "user_id"}  -> 201 {"token": "phk_...", "note"}
DELETE /api/v1/tokens/{id}     -> {"revoked": true}
```

- Usernames: 3 to 64 characters of lowercase letters, digits, `.`, `-` and
  `_`, starting with a letter or digit.
- Passwords: at least 12 characters.
- An admin cannot disable themselves or remove their own admin role (422).
- **A new token is shown once.** Display it with a copy button and a clear "you
  won't see this again" note; don't keep it after the dialog closes.

### 7.8 Audit log

```
GET /api/v1/audit?offset=<n>   -> [{"id", "at", "actor", "action", "object_type", "object_id", "details"}]
```

The log comes 100 entries per page, newest first. Analysts see their own
entries.

Actions you will see: `login`, `login_failed`, `logout`, `submit`, `analyze`,
`analyze_failed`, `download`, `download_raw`, `reanalyze`, `delete_tier1`,
`delete_completely`, `hold`, `release`, `settings`, `user_create`,
`user_change`, `token_create`, `token_revoke`, `rotate_key`,
`retention_sweep`. Render `actor` and `details` as text (section 5.1).

### 7.9 Status (optional, for admins)

```
GET /healthz   (no login needed)
-> {"status": "ok", "version": "...", "queue": 0, "last_heartbeat": "...", "disk_free_mb": 23517}
```

### 7.10 Required UI states

Every screen must define these states:

- loading;
- loaded;
- empty;
- permission denied;
- not found;
- session expired;
- network error;
- server error;
- retrying;
- retry available;
- destructive action pending;
- destructive action completed;
- object deleted;
- object held;
- reduced-motion mode;
- keyboard-only mode;
- narrow mobile layout.

Use accessible text for all states. Do not communicate state only through colour,
animation or iconography.

---

## 8. Milestone 2 screens (planned)

The backend adds these in M2. Build the screens with mock data; connect them
once `openapi.json` lists the endpoints. The fields below come from the
design; confirm them against `openapi.json` then, and don't invent others.

- **Batch upload**: several files at once, or one `.mbox` or `.zip`, up to 500
  messages. `POST /api/v1/submissions` then answers with the submission IDs and
  a batch ID.
- **Batch page**: `GET /api/v1/batches/{id}` shows progress and each message's
  verdict as it finishes. `GET /api/v1/batches/{id}/files/{name}` gives the
  combined downloads: a batch HTML report, JSON, CSV, STIX and MISP, plus a
  manifest.
- **Campaigns**:
  - `GET /api/v1/campaigns` lists them: number of messages, first and last
    seen, the indicators they share, and the mix of verdicts.
  - `GET /api/v1/campaigns/{id}` gives the detail.
  - A shared subject or sender name appears in clear only while one of the
    messages is still kept; after that, the API says only "same subject" or
    "same display name". Recipient addresses become counts the same way.
  - Campaigns cover the last 90 days by default.
- **Queue filters**: source (`upload`, `paste`, `batch`, `mailbox`), a date
  range and a user, beside the existing search and verdict filter.
- **Settings, "Test connection"**: `POST /api/v1/settings/providers/{name}/test`
  checks a provider's key and shows the result.

## 9. Milestone 3 screens (planned)

The same applies as for M2: design now, wire later, confirm the fields.

- **Mailboxes (admin)**: `GET/POST/PATCH/DELETE /api/v1/mailboxes`, and
  `POST /api/v1/mailboxes/{id}/poll` for "Poll now".
  - Three kinds:
    - **IMAP**: host, port, user, password or app password, folder;
    - **Microsoft Graph**: tenant ID, client ID, client secret, and the
      mailbox address;
    - **Gmail**: a Google Workspace service account, and the mailbox address.
  - Show each mailbox's status, last poll and last error. The error is already
    sanitised; show it as text.
  - Credentials are write-only. Never show them back; offer "replace" only.
  - Imported messages show up as submissions with source `mailbox`.
  - Say plainly that PhishHawk only reads mail; it never deletes or moves it.

---

## 10. Deploy

1. Run `npm run build`.
2. Confirm `vite.config.ts` contains `base: "/app/"`, for example:

   ```ts
   export default defineConfig({
     plugins: [react()],
     base: "/app/",
   });
   ```

3. Confirm the generated `dist/` folder contains only static frontend assets.
4. Confirm no mock API code is enabled in production.
5. Copy `dist/` to the PhishHawk server.
6. Set `PHISHHAWK_FRONTEND_DIR` to that folder.
7. Mount the folder read-only when using Docker Compose: `compose.yaml` has
   the two lines, commented out.
8. Restart the PhishHawk server.
9. Open:

   ```text
   https://<server>/app/
   ```

10. Test a deep link such as:

    ```text
    https://<server>/app/analyses/12
    ```

11. Confirm the server returns the frontend entry point for valid `/app/`
    routes.
12. Confirm every API request remains same-origin.
13. Confirm there are no CSP violations.
14. Confirm no external fonts, images, scripts, analytics or API requests are
    present.

---

## 11. Acceptance checklist

Run these against the real server before you call the frontend done.

1. **No console errors.** In DevTools, nothing starting with "Refused to" and
   no failed requests.
2. **No outside requests.** In the Network tab, every request goes to the
   PhishHawk server itself.
3. **The hostile email.** Log in, choose "paste", paste the message below,
   turn on Offline analysis and submit. Check:
   - no alert box appears, on any screen;
   - the subject, the sender name and the attachment's file name show the
     literal characters `"><img ...` and `"><svg ...` as text;
   - the URL shows as `hxxps://evil-login[.]top/login?next=` and is not
     clickable;
   - the queue, the analysis screen, the audit log and a search for
     `evil-login` all behave the same way.

   ```
   From: "\"><svg onload=alert(1)>" <ceo@evil-login.top>
   To: "<img src=x onerror=alert(2)>" <victim@example-corp.co.uk>
   Subject: "><img src=x onerror=alert(document.domain)> Urgent invoice
   Message-ID: <"><svg onload=alert(3)>@evil-login.top>
   Reply-To: "<script>alert(4)</script>" <pay@evil-login.top>
   Authentication-Results: "><svg onload=alert(8)>; spf=fail smtp.mailfrom=evil-login.top
   MIME-Version: 1.0
   Content-Type: multipart/mixed; boundary="b1"

   --b1
   Content-Type: text/html; charset=utf-8

   <p>Pay now: <a href="javascript:alert(5)">"><svg onload=alert(6)></a></p>
   <p>https://evil-login.top/login?next="><script>alert(7)</script></p>
   --b1
   Content-Type: text/plain; name="\"><img src=x onerror=alert(9)>.txt"
   Content-Disposition: attachment; filename="\"><img src=x onerror=alert(9)>.txt"

   invoice
   --b1--
   ```

4. **The report frame** has exactly
   `sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"`.
5. **Roles.**
   - Logged in as an analyst: no Settings, Users or Tokens, and no "Delete
     now" or raw-message link on someone else's analysis.
   - Logged in as an admin: everything is there.
   - On a held message: no delete buttons.
6. **Sessions.** Log out, then press Back: you get the login screen, and no
   data shows from memory or storage.
7. **Keyboard only.** You can log in, submit, open the analysis and download a
   file without a mouse, with focus always visible.
8. **Reduced motion.** With reduced motion turned on in the operating system,
   animations stop or become simple fades.
9. **Phone width.** At 320 px wide nothing scrolls sideways, and the verdict
   is readable without zooming.
10. **Storage.** `localStorage` holds nothing but the theme preference, and
    `sessionStorage` holds nothing (test 17 has the full check).
11. **MITRE links.**
    - Valid ATT&CK IDs create only the approved MITRE navigation link.
    - The frontend never fetches or embeds the MITRE page.
    - Invalid technique IDs render as plain text.
    - No indicator creates an external link.
12. **CSRF recovery.**
    - Expire the in-memory CSRF token.
    - Trigger a state-changing request.
    - Confirm one session refresh and one retry happen.
    - Confirm there is no infinite retry loop.
13. **Polling.**
    - Submit a message.
    - Confirm only one polling loop exists.
    - Navigate away.
    - Confirm polling stops and the request is aborted.
    - Confirm polling stops after a terminal state.
    - Confirm polling times out after five minutes.
14. **Deletion states.**
    - Test held message.
    - Test tier-1 deletion.
    - Test complete deletion.
    - Confirm the correct controls disappear in each state.
    - Confirm the audit log remains available according to the role.
15. **Download behaviour.**
    - No file downloads on page load.
    - Downloads start only after a click.
    - Unavailable files are not clickable.
    - Download errors do not expose raw server content.
16. **Rendering safety.**
    - Test hostile content in subject, sender, filename, URL, reply-to,
      authentication header, audit detail and API error detail.
    - The message in test 3 covers the subject, sender, attachment file name,
      URL, reply-to and authentication header. For the audit log, try to log
      in with the username `"><svg onload=alert(10)>` (it becomes the `actor`
      of a `login_failed` entry), and as an admin create an API token named
      `"><img src=x onerror=alert(11)>` (it appears in the `details` of
      `token_create`).
    - Confirm every value appears as literal text.
    - Confirm no attacker-controlled value becomes an HTML attribute, CSS
      value, link, image source or request URL.
17. **Storage.**
    - Confirm `localStorage` contains only the theme preference.
    - Confirm `sessionStorage` contains no API data.
    - Confirm IndexedDB is unused.
    - Confirm service-worker caching is unused.
    - Confirm the CSRF token disappears after logout.
18. **Accessibility.**
    - Dialog focus moves into the dialog.
    - Escape closes the dialog.
    - Focus returns to the triggering control.
    - Errors use accessible announcements.
    - Buttons and links have accessible names.
    - Tables have headers and captions.
    - The UI works without colour, mouse or animation.
19. **Production build.**
    - `npm run build` succeeds.
    - Mock API code is not enabled.
    - No `eval`, `new Function`, inline script, import map or JavaScript URL
      exists in the production bundle.
    - No `dangerouslySetInnerHTML` is used for email-derived data.

---

## 12. Final implementation instruction

Build Milestone 1 first.

Before writing UI code:

1. Read `docs/api/openapi.json`.
2. Read `docs/report.schema.json`.
3. Treat those files as the source of truth.
4. Do not invent missing endpoints or fields.
5. Resolve any conflict in favour of the backend contract and the security rules
   in this prompt.
6. If the backend does not support a requested feature, show the available
   data and add a visible:

   ```text
   NEEDS BACKEND
   ```

7. Keep all API calls in one typed API client.
8. Keep attacker-controlled values as text.
9. Keep the CSRF token and API state in memory only.
10. Keep all requests same-origin.
11. Do not add a backend or proxy.
12. Do not add external dependencies that violate the CSP.
13. Run the complete acceptance checklist before declaring the frontend done.

Do not generate only a visual mockup. Generate a working, secure, typed,
accessible frontend that can be built with:

```bash
npm run build
```

The finished output must be deployable as static files under:

```text
/app/
```
