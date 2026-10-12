# Your own frontend

The web app comes with its own pages, but you can build a frontend of your own,
for example in Google AI Studio, and let PhishHawk serve it at `/app/`. It runs
on the same origin as the API, so it needs no CORS and the session cookie
stays `SameSite=Strict`. The built-in pages keep working beside it, as the
backup and admin interface.

PhishHawk's own frontend is in [frontend/](../frontend/), built in Google AI
Studio to these rules. The Docker image builds it and serves it at `/app/`, and
the server's address (`/`) opens it; the built-in pages stay at `/login`,
`/queue` and the rest.

- [This repository's frontend](#this-repositorys-frontend)
- [The rules](#the-rules)
- [The API in five calls, and batches and campaigns](#the-api-in-five-calls-and-batches-and-campaigns)
- [Build and deploy](#build-and-deploy)
- [A starting prompt for Google AI Studio](#a-starting-prompt-for-google-ai-studio)

## This repository's frontend

```bash
cd frontend
npm ci --ignore-scripts && npm test && npx tsc --noEmit && npm run build
PHISHHAWK_FRONTEND_DIR="$PWD/dist" phishhawk server run    # then open http://127.0.0.1:8000
```

`npm run dev` previews it with a mock API, with no server. CI runs its tests,
builds it and drives the build in Chromium against a real server at seven
widths from 320 to 1440 px (`tests/server/test_frontend_browser.py`): the
product page a visitor sees first, signing in from it and signing out back to
it; one message from paste to report and files; a batch of two from upload to its
combined reports, its campaign and the queue's filters; and a mailbox added on
the Mailboxes screen, polled from a test IMAP server, its reports in the queue.

Signed out, `/app/` is the product page: what PhishHawk does and checks, the
measured results, the verdicts, the ways to use it and common questions, with
Sign in at the top. Signed in, `/app/` is Triage, and the product page stays at
`/app/about`. Every claim on it is what the code does; change it only with the
code (it is a locked file).

Several files, an .mbox or a .zip chosen on the triage page open the batch page
(`/app/batches/{id}`); Campaigns is in the top bar (`/app/campaigns`), and so
is Mailboxes for admins (`/app/mailboxes`).

To bring in a change made in Google AI Studio, export the project as a ZIP and
replace `frontend/` with it, keeping `public/brand/report-*.webp`, then run the
commands above. The files listed in `src/__tests__/locked-files.json`, the tests
among them, must come back unchanged; `npm test` fails otherwise.

## The rules

Everything in a reported email is written by the attacker: the subject, the
sender's name, every indicator, every value in the report. Your frontend shows
that text to your analysts, so it is part of the defence.

1. **Show message data as text, never as HTML.** In React, `{value}` is safe.
   Never pass message data to `dangerouslySetInnerHTML`, `innerHTML`, a
   Markdown-to-HTML renderer, or an `href`. That includes `subject`, `sender`,
   `sender_domain`, file names, indicators and anything inside `report`.
2. **Open the full report only in a sandboxed frame**, from the server:

   ```html
   <iframe sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
           src="/analyses/{id}/files/{html file name}"></iframe>
   ```

   Never fetch the report and insert it into your page.
3. **Load nothing from other sites.** The app's Content-Security-Policy allows
   scripts, styles, fonts, images and requests from this server only. No CDN,
   no import map that points at a CDN, no Google Fonts: install packages with
   npm and let the build bundle them.
4. **Send no message data anywhere else.** No Gemini or other AI calls, no
   analytics. PhishHawk is self-hosted so that reported mail stays on your
   server; the CSP blocks such requests anyway.
5. **Use relative URLs** (`/api/v1/...`), so the browser sends the session
   cookie, and send the CSRF token on every request that changes something.

## The API in five calls, and batches and campaigns

The full description is [docs/api/openapi.json](api/openapi.json). Errors are
JSON: `{"error": "<code>", "detail": "<text>"}`.

| Step | Call | Notes |
|---|---|---|
| On start | `GET /api/v1/session` | 401: show your login form. 200: `{"user_id", "username", "role", "via", "scope", "csrf"}`; keep `csrf` in memory. |
| Log in | `POST /api/v1/session` with JSON `{"username", "password"}` | 200: `{"csrf"}` and the session cookie. 401: wrong details. 429: wait (the `Retry-After` header says how long). |
| Submit | `POST /api/v1/submissions`, multipart: `files` (one or more .eml, .msg, .mbox or .zip files) or `raw` (pasted text), and `offline` (`true` for no reputation lookups) | Header `X-CSRF-Token: <csrf>`. 202. One message: `{"id", "status", "error", "analysis_id", "submitted_at", "batch_id": null}`. Several: a batch, `{"batch_id", "total", "submission_ids", "skipped"}` (`skipped`: files in a .zip that are not messages). 413: too large or too many messages, 415: not a message; `detail` says which. |
| Wait | `GET /api/v1/submissions/{id}` every second or two | Until `status` is `done` (then `analysis_id` is set) or `failed` (then `error` says why). |
| Show | `GET /api/v1/analyses/{id}` | `verdict`, `score`, `report_id`, `sha256`, `sender`, `subject`, `submitted_by` (a user ID) and `submitted_by_name`, `techniques`, `lookups`, `hold`, `files` (each with `name`, `kind`, `type`, `size`, `sha256`, `available`) and `report` (the full JSON report while the message is kept). |

Batches and campaigns:

| Call | Answer |
|---|---|
| `GET /api/v1/batches/{id}`, every few seconds | `status` (`running`, `finalizing`, `done` or `failed`), `total`, `counts` (`queued`, `running`, `done`, `failed`), `verdicts`, `messages` (in upload order: `position`, `status`, `error`, `analysis_id`, `verdict`, `score`, `sender`, `sender_domain`) and, once `done`, `files`: the combined reports, like an analysis's. `files_deleted_at` is set once they are gone. |
| `GET /api/v1/batches/{id}/files/{name}` | One combined report. The HTML one opens sandboxed, as an analysis's does; `?download=1` downloads any. |
| `GET /api/v1/campaigns` | Largest first: `id`, `size`, `first_seen`, `last_seen`, `verdicts`, `worst_verdict`, `senders`, `recipient_count`, and `shared` (`kind`, `value`, `messages`); a shared `subject` or `display name` has `value: null` here. |
| `GET /api/v1/campaigns/{id}` | The same, with `shared` values in clear where known (`null` means "same subject", the messages' content being gone), `messages` (`analysis_id`, `sha256`, `verdict`, `score`, `sender`, `subject` or `null`), `recipients` and `recipients_complete`. |

Also useful: `GET /api/v1/analyses?q=&verdict=&source=&user=&since=&until=&offset=`
(the queue, 50 at a time; `q` matches a SHA-256, a report ID or an indicator;
`source` is `upload`, `paste`, `batch` or `mailbox`; `user` a user ID; `since` and `until`
are days, `YYYY-MM-DD`, both included), downloads at
`/api/v1/analyses/{id}/files/{name}?download=1`, `DELETE /api/v1/session` to
log out, and `GET /api/v1/audit`. Settings, users and tokens are admin calls;
the built-in pages already cover them.

Mailboxes (admins): `GET /api/v1/mailboxes` lists them, each with `id`, `name`,
`kind` (`imap`, `graph` or `gmail`), `enabled`, `interval_minutes`, `config`
(where it is: `host`, `port`, `starttls`, `user`, `folder`; `tenant_id`,
`client_id`, `address`, `folder`; `address`, `label`, `service_account`),
`secret_set`, `status` (`never`, `ok` or `error`), `error`, `last_poll_at`,
`next_poll_at` and `last_counts` (`imported`, `duplicates`, `skipped`).
`POST /api/v1/mailboxes` with JSON `{"name", "kind", "config", "secret",
"interval_minutes", "enabled"}` adds one (201; 422 with the reason, 409 for a
name in use); `PATCH /api/v1/mailboxes/{id}` changes any of those (a missing
or empty `secret` keeps the old one); `DELETE /api/v1/mailboxes/{id}` removes
one; `POST /api/v1/mailboxes/{id}/poll` polls it now (202 `{"queued"}`; 409
when it is switched off). The secret is never in an answer. A message
imported from a mailbox has `source: "mailbox"`, `submitted_by: null` and the
mailbox's name in `submitted_by_name`.

Roles: analysts submit and read everything, and delete their own submissions;
admins also hold, release and delete completely. Show only the buttons the
user's `role` allows; the server refuses the rest (403) whatever the frontend
shows.

## Build and deploy

The Docker image does this for `frontend/`. For a frontend of your own:

1. Build static files with base path `/app/`. With Vite, set `base: '/app/'` in
   `vite.config.ts`, then run `npm run build`. The result is a `dist/` folder.
2. Copy `dist/` to the server, for example to `/srv/phishhawk-frontend`.
3. Set `PHISHHAWK_FRONTEND_DIR=/srv/phishhawk-frontend` and restart. With
   Compose, mount the folder read-only and set the variable; `compose.yaml`
   has the two lines, commented out.
4. Open `/app/`. Your frontend's own routes (`/app/queue`, `/app/analyses/12`)
   load `index.html`, so a reload works.

If the page stays blank, open the browser's console. A "Content Security
Policy" error names the script, style or font that came from another site;
bundle it instead.

## A starting prompt for Google AI Studio

Attach `docs/api/openapi.json` and paste:

```text
Build a web frontend for PhishHawk, a phishing triage service, in React and
TypeScript with Vite. The attached OpenAPI file describes its API.

- It is served by the PhishHawk server at /app/ on the same origin: set Vite's
  base to '/app/' and call the API with relative URLs such as /api/v1/session.
- Install every library with npm. Do not load scripts, styles or fonts from a
  CDN or Google Fonts, and do not use an import map. Do not call Gemini or any
  other external service.
- On start, GET /api/v1/session. On 401 show a login form that POSTs
  {"username", "password"} to /api/v1/session. Keep the returned "csrf" value
  in memory and send it as the X-CSRF-Token header on every POST, PATCH and
  DELETE.
- Pages: Submit (upload an .eml or .msg file, or paste raw text, with an
  "Offline" checkbox; then poll GET /api/v1/submissions/{id} until status is
  done or failed), Queue (GET /api/v1/analyses with search and a verdict
  filter), and Analysis (GET /api/v1/analyses/{id}: verdict, score, report ID,
  sender, the downloads, and the full report in
  <iframe sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
  src="/analyses/{id}/files/{name of the file whose kind is html}">).
- Every value that comes from an email is attacker-controlled. Render it as
  text only: never dangerouslySetInnerHTML, innerHTML, a Markdown renderer, or
  a link built from it.
- Accessible: one h1 per page, labels on every field, visible keyboard focus,
  WCAG AA contrast in light and dark.
```

Review what it produces against [the rules](#the-rules) before you deploy it.
