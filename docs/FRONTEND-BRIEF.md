# PhishHawk v3: frontend build brief (for Google AI Studio)

**How to use this file**

1. In Google AI Studio (Build), start a new app and paste this whole file as the
   first message.
2. Attach two files from the PhishHawk repository:
   - `docs/api/openapi.json`, the API;
   - `docs/report.schema.json`, the full analysis report.

   `openapi.json` is added by milestone M1 (task 15 of its plan). Until then,
   the examples in section 7 are the contract.
3. Then ask for one screen at a time, in the order of section 7.
4. Sections 2, 4, 5 and 6 are rules. Section 1 is yours to play with.

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
   Use `urls[].defanged` where the report gives it. For other values, use the
   `defang()` helper in section 5.2.
3. **Show the full HTML report only in this iframe**, exactly as written:
   ```html
   <iframe sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
           src="/analyses/{id}/files/{name of the file whose kind is html}"
           title="Full report"></iframe>
   ```
4. **Use relative URLs** for every request (`/api/v1/...`), so the browser
   sends the session cookie.
5. **Keep the CSRF token in memory only** (a variable or React state). Send it
   as the `X-CSRF-Token` header on every POST, PATCH and DELETE, except the
   login request itself.
6. **Bundle everything with npm and Vite**: libraries, fonts (for example
   `@fontsource/*` packages), icons and images.
7. **Ask before destructive actions.** "Delete now" and "Delete completely"
   need a confirmation that says what will be lost.
8. **Handle every error status** in section 4.4 with a clear, human message.
9. **Start downloads only when the user clicks.** The server records every
   download in the audit log.
10. **Treat the role as a display hint.** The server enforces permissions;
    you only hide buttons a user cannot use (section 6).

### 2.2 Don't

1. **Never** pass email data to `dangerouslySetInnerHTML`, `innerHTML`,
   `outerHTML`, `insertAdjacentHTML`, `document.write` or a Markdown, HTML or
   rich-text renderer.
2. **Never** build `href`, `src`, `action`, `style`, CSS or class names from
   email data, and never make an indicator clickable. Copy-to-clipboard of the
   defanged value is fine.
3. **Never** fetch the HTML report and insert it into the page. Never remove
   or loosen the iframe's `sandbox`; never add `allow-scripts` or
   `allow-same-origin`.
4. **Never** call any other site from the browser. That means no CDN, no Google
   Fonts, no Gemini or other AI APIs, no analytics, no error trackers, no maps
   and no remote images. Reported mail must not leave the server, and the
   server's security policy blocks these requests anyway.
5. **Never** store API data, passwords, API keys or the CSRF token in
   `localStorage`, `sessionStorage`, IndexedDB, cookies or a service-worker
   cache. Never log API data to the console. A theme preference in
   `localStorage` is fine.
6. **Never** use `eval`, `new Function`, inline `<script>` blocks, an import
   map, or `javascript:` URLs.
7. **Never** "refang" an indicator or open one. That includes building a
   VirusTotal link from it.
8. **Never** add a backend, a proxy, server-side rendering or API routes of
   your own. The app is static files only.
9. **Never** invent API fields or endpoints. If something is missing, show
   what exists and leave a clearly marked `// NEEDS BACKEND:` comment.

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
- Put all API calls in one module, for example `api.ts`. It adds the CSRF
  header, parses errors (section 4.4) and sends the user to login on a 401.

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

### 4.2 Requests that change something

Every POST, PATCH and DELETE (except `POST /api/v1/session`) needs the
`X-CSRF-Token: <csrf>` header. Without it the server answers 403.

### 4.3 Waiting for a verdict

After a submit (202), poll `GET /api/v1/submissions/{id}` every 1 to 2
seconds:
- `queued` and `running`: still working. Show progress your way; it usually
  takes about a second.
- `done`: `analysis_id` is set; open that analysis.
- `failed`: `error` gives a short reason, for example "this message exceeded
  the analysis limits".

Stop polling when the user leaves the screen.

### 4.4 Errors

Every API error is JSON: `{"error": "<code>", "detail": "<human text>"}`.
`detail` is safe to show as text.

| Status | `error` | Meaning; what to show |
|---|---|---|
| 400 | `bad_request` | Bad input, for example an empty message. |
| 401 | `unauthorized` | Not logged in or session expired: go to login. |
| 403 | `forbidden` | Not allowed for this role, or the CSRF token is missing. |
| 404 | `not_found` | No such item. |
| 409 | `conflict` | The message is on hold; an admin must release it before deleting. |
| 410 | `gone` | The message and its reports were deleted after the retention period; the verdict and the record stay. |
| 413 | `too_large` | The file is over the upload limit (25 MB by default). |
| 415 | `unsupported` | Not an `.eml` or `.msg` message. |
| 422 | `invalid` | A form value is wrong; `detail` says which. |
| 429 | `throttled` | Too many login tries; wait `Retry-After` seconds. |

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

```ts
// The same rule the engine uses: hxxp(s):// and [.] in the host.
export function defang(value: string): string {
  const out = value.replace(/^http(s?):\/\//i, (_m, s: string) => `hxxp${s}://`);
  const m = out.match(/^(hxxps?:\/\/|ftp:\/\/)([^/?#]+)(.*)$/i);
  return m ? m[1] + m[2].split('.').join('[.]') + m[3] : out.split('.').join('[.]');
}

// iocs[].type is one of: url, domain, ipv4, ipv6, email, sha256, crypto-wallet, phone
export function showIndicator(type: string, value: string): string {
  return ['url', 'domain', 'ipv4', 'email'].includes(type) ? defang(value) : value;
}

// The one link you may build from report data: a MITRE ATT&CK technique, from its ID.
export function attackUrl(id: string): string | null {
  return /^T\d{4}(\.\d{3})?$/.test(id) ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` : null;
}
```

Links to `attack.mitre.org` open a new tab with `rel="noopener noreferrer"`.
It is the only external link the app has. Navigation away is not a request
the CSP blocks.

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

---

## 7. Milestone 1 screens and their API

The API is fully defined in `openapi.json`. The shapes below are the real
responses.

### 7.1 Login

`POST /api/v1/session` as in section 4.1. Show the error states: wrong
password, throttled with a countdown, and server unreachable.

### 7.2 Submit (home)

There are two ways in: drag and drop or pick a file (`.eml`, `.msg`), or paste
the raw message (headers and body). Add an **Offline** switch, "no reputation
lookups for this message".

```
POST /api/v1/submissions      multipart/form-data, X-CSRF-Token
  file=<the file>              or   raw=<pasted text>
  offline=true|false
202 -> {"id": 41, "status": "queued", "error": "", "analysis_id": null,
        "submitted_at": "2026-10-07T09:12:03+00:00"}
```

Then poll as in section 4.3. The same message twice is fine; the server
recognises it by its SHA-256. Show the last 10 analyses below the form, using
the first 10 of `GET /api/v1/analyses`.

### 7.3 Queue

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

### 7.4 Analysis

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

### 7.5 Settings (admin)

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

### 7.6 Users and API tokens (admin)

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

### 7.7 Audit log

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

### 7.8 Status (optional, for admins)

```
GET /healthz   (no login needed)
-> {"status": "ok", "version": "...", "queue": 0, "last_heartbeat": "...", "disk_free_mb": 23517}
```

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

1. `npm run build`, with `base: '/app/'` set.
2. Copy `dist/` to the PhishHawk server.
3. Set `PHISHHAWK_FRONTEND_DIR` to that folder and restart. With Docker
   Compose, uncomment the two lines in `compose.yaml` and mount the folder
   read-only.
4. Open `https://<server>/app/`. Reloading any of your routes (for example
   `/app/analyses/12`) works.

---

## 11. Acceptance checklist

Run these against the real server before you call the frontend done.

1. **No console errors.** In DevTools, nothing starting with "Refused to" and
   no failed requests.
2. **No outside requests.** In the Network tab, every request goes to the
   PhishHawk server itself.
3. **The hostile email.** Log in, choose "paste", paste the message below,
   tick Offline and submit. Check:
   - no alert box appears, on any screen;
   - the subject and sender name show the literal characters `"><img ...`
     and `"><svg ...` as text;
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
   Content-Type: text/html; charset=utf-8

   <p>Pay now: <a href="javascript:alert(5)">"><svg onload=alert(6)></a></p>
   <p>https://evil-login.top/login?next="><script>alert(7)</script></p>
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
10. **Storage.** `localStorage` and `sessionStorage` hold nothing but UI
    preferences.
