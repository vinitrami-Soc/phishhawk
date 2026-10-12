# PhishHawk v3 M3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An admin connects a report mailbox over IMAP, Microsoft Graph or the Gmail API, read-only, and every message that arrives in it is analysed like an upload, never twice (milestone M3 of the v3 design).

**Architecture:** A `mailboxes` table holds each connection, its credential sealed with the encryption key, and a cursor (IMAP: UIDVALIDITY and the last UID; Graph: the delta link; Gmail: the history ID). The worker's scheduler queues one `mailbox_poll` job per mailbox when it is due. The job fetches what is new through `imapfetch` (IMAP) or `mailapi`'s HTTP client (Graph, Gmail), skips what was seen, and hands each new message to `intake.accept()` as a `mailbox` submission. A failure leaves the mailbox in `error` with a sanitised reason and backs the polling off.

**Tech Stack:** As M2. Graph and Gmail tokens are fetched with `requests` (client credentials; a service-account JWT signed with `cryptography`, already in the server extra). No new dependency.

**Spec:** [docs/superpowers/specs/2026-10-06-phishhawk-v3-web-design.md](../specs/2026-10-06-phishhawk-v3-web-design.md), section 11, M3 ("IMAP, then Graph, then Gmail, each with its read-only test double"), with sections 6.3 (mailbox import), 7.5 (read-only guarantee), 7.2 (Mailboxes: admin), 8 (the Mailboxes page) and 9 (`/mailboxes` routes).

## Global Constraints

The M1 and M2 plans' constraints hold unchanged: Python 3.10 to 3.13; the base install needs only `requests`; the server reaches the engine only through `phishhawk.analysis`; "Plain message bytes are only ever in worker memory; they are never written to disk in clear"; the existing tests stay green at every step, with `ruff check src tests samples eval tools phishhawk` (line length 115) and `mypy` clean with and without the server extra; no secret literals in tests; one commit per task by Vinit Rami, without co-author lines. In addition:

- Read-only: PhishHawk "never deletes, moves or quarantines mail and never stores credentials that could" (D4). "Mailbox connectors request only read scopes. Tests run them against fake IMAP, Graph and Gmail servers that record every call and fail on anything but reads (`EXAMINE`/`SELECT ... READ-ONLY` and `BODY.PEEK` for IMAP; `GET` for Graph and Gmail)."
- "TLS certificates are always verified."
- "A `mailbox_poll` job runs every N minutes (N ≥ 5) ... Each new message becomes a submission (source `mailbox`); duplicates are skipped by SHA-256 and Message-ID."
- "On failure the mailbox shows `error` with a sanitised reason, polling backs off (up to one hour), and the failure is audited. Credentials never appear in the reason."
- "API keys and mailbox credentials in `settings` and `mailboxes` are encrypted the same way." Mailboxes are admin only.
- The CLI's `imap`, `graph` and `gmail` commands do not change.
- Done when: "each connector imports new messages from its fake server without a single non-read call, survives a credential failure with a sanitised error, and never imports the same message twice."

## How this plan was checked

The milestone was built task by task on a branch from `main`, test first. Each task below names the test that failed first and how; with its code it passed, and the whole suite, ruff and mypy stayed clean with and without the server extra. After task 6:

- With the server extra, on SQLite: 953 passed, 6 skipped (the Postgres-only workers test, the 500-message check run on its own, the two frontend browser tests and the built-in pages' browser test without their browser or build, and YARA, not installed here; CI runs each).
- Without it: 698 passed, 1 skipped.
- The web app's tests on Postgres 16, each on a database of its own: 255 passed, 5 skipped.
- Every connector test ends with its test double holding no violation: the IMAP server saw only CAPABILITY, STARTTLS, LOGIN, EXAMINE, UID SEARCH, UID FETCH of RFC822.SIZE and BODY.PEEK[], and LOGOUT; the Graph and Gmail sessions only GETs to their API and one POST to their token URL. Each double also has a test of its own that a write (SELECT, a FETCH that sets \Seen, PATCH, a POST to the API, a request to another host) is caught.
- End to end, `phishhawk server run` as a process imported two messages from the IMAP test server after Poll now and analysed them.

Found and fixed along the way, each with a test: a credential that no longer opens (copied from another row, or sealed under another key) crashed the poll, so the job failed and the scheduler queued the mailbox again every 30 seconds without backing off; it is now a failure like any other ("the stored credential cannot be opened"). The IMAP double answers `UID n:*` as servers do, with the newest message even when nothing is newer, and the poll filters it out. Hypothesis turned up the defect older than M3 again (report free text keeps a bare `www.` link live, example `WWW.0`); it is still left to a change of its own.

## Decisions the spec left open, settled here

1. **One poll at a time per mailbox.** The scheduler queues a `mailbox_poll` job for an enabled mailbox whose `next_poll_at` has passed and that has none queued or running. "Poll now" queues one at once (a no-op if one is waiting); on a disabled mailbox it answers 409.
2. **The interval** is per mailbox, 5 to 1,440 minutes, default 5.
3. **The first poll imports the newest 50 messages** and sets the cursor; later polls import everything after the cursor. So does a poll after the cursor is lost (IMAP's UIDVALIDITY changed, Graph's delta link expired, Gmail's history ID too old: a resync). Older mail is not imported on its own; upload it as an .mbox.
4. **A poll imports at most `max_batch_messages` (500) messages.** When more are waiting the cursor stays where the last one imported leaves it (IMAP) or where it was (Graph, Gmail), so the next poll picks up the rest; what was imported is skipped by its remote ID without being downloaded again.
5. **Duplicates**, in this order: the remote ID already seen in this mailbox (nothing downloaded); the SHA-256 of a message already stored, from any source; the Message-ID of a message any mailbox imported, kept as an HMAC under the trait key (`mailbox_items`). A duplicate is recorded as seen and counted, not submitted.
6. **What a poll leaves:** `last_poll_at`, `status` (`ok`, `error`, or `never`), `error`, and the counts of the last poll (imported, duplicates, skipped). A message larger than `max_upload_mb`, or that is not a message, is skipped for good and counted. A dropped connection stops the poll where it was: the cursor keeps the last message handled, and the mailbox shows the error.
7. **Backoff:** after the n-th failure in a row the next poll waits `min(interval × 2^n, 60 minutes)`; a success resets it. Every failure is audited (`mailbox_poll_failed`, with the reason). Successful polls are not audited; each message they import is (`submit`, actor `mailbox:<name>`).
8. **Sanitised reasons:** the reason is built by PhishHawk from what failed (connect, sign-in, folder, a provider's error code), passed through `printable()`, cut to 300 characters, and any occurrence of the mailbox's secret or of an access token in it is replaced with `***`. The provider's own error text (`error_description`) is never shown.
9. **Credentials:** IMAP a password (or app password); Graph a client secret; Gmail a service account's JSON key, of which only `client_email` and `private_key` are kept (its `token_uri` is ignored). Each is sealed in `mailboxes.secret`, bound to `mailbox:<id>`, re-encrypted by key rotation, never returned by the API (only `secret_set`), never audited.
10. **Tokens are fetched for each poll**, not cached: Graph with the client-credentials flow at `login.microsoftonline.com/<tenant>/oauth2/v2.0/token` (scope `https://graph.microsoft.com/.default`); Gmail with a JWT for `gmail.readonly` only, `sub` the report mailbox, at `oauth2.googleapis.com/token`. These two POSTs are the only requests that are not GETs. The token goes only to the API's host, in the Authorization header.
11. **Hosts:** an IMAP host is a host name or an IP address the admin enters (an on-premises server is a real case; admins are trusted); port 993 with TLS or 143 with STARTTLS, never plain. Graph and Gmail hosts are fixed; national clouds are not supported.
12. **Changing a connection** (host, port, STARTTLS, user, folder or label, tenant, client ID, mailbox address) resets the cursor; what was seen stays seen, so nothing is imported twice. Changing the name, interval, enabled or the secret keeps it. A mailbox keeps its kind: another kind is another mailbox.
13. **Deleting a mailbox** removes its settings, secret, cursor and seen items; messages it imported stay, with their analyses.
14. **Imports are submissions** with source `mailbox`, no user, and `mailbox_id`; the queue shows the mailbox's name as the submitter and filters by source `mailbox`. Raw download and Delete now on them are for admins (no one owns them).
15. **The read-only test doubles:** IMAP is a real IMAP server over TLS in a thread (a test CA through `SSL_CERT_FILE`), answering CAPABILITY, LOGIN, STARTTLS, EXAMINE, UID SEARCH, UID FETCH of `RFC822.SIZE` or `BODY.PEEK[]`, NOOP and LOGOUT; anything else (SELECT, STORE, COPY, MOVE, EXPUNGE, a FETCH of `BODY[]`) is recorded as a violation and refused. Graph and Gmail are a fake `requests` session recording every call: GET to the API's host and one POST to its token URL; anything else is a violation. Every connector test ends with no violations.

## Not in M3

Release v3.0.0 (its own step: the security review round, docs, screenshots, release notes); IMAP with OAuth (XOAUTH2) in the web app; national clouds; mailbox sweep and response actions (later specs).

## File map

| Path | Responsibility |
|---|---|
| `src/phishhawk/server/mailboxes.py` | A mailbox's settings: checks per kind, the sealed secret, the view without it, cursor resets. |
| `src/phishhawk/server/mailbox.py` | The poll: connectors for IMAP, Graph and Gmail (tokens, delta, history), duplicates, backoff, sanitised reasons. |
| `src/phishhawk/imapfetch.py` | `fetch(..., info=None)` reports the folder's UIDVALIDITY; nothing else changes. |
| `src/phishhawk/server/models.py`, `migrations/versions/0003_mailboxes.py` | `Mailbox`, `MailboxItem`, `Submission.mailbox_id`. |
| `src/phishhawk/server/jobs.py`, `worker.py`, `rotation.py`, `intake.py`, `views.py` | The job kind, scheduling, rotating mailbox secrets, the submission's mailbox, the submitter's name. |
| `src/phishhawk/server/routes/api.py`, `routes/pages.py`, `templates/mailboxes.html`, `base.html` | `GET/POST/PATCH/DELETE /api/v1/mailboxes`, `POST /api/v1/mailboxes/{id}/poll`; the Mailboxes page. |
| `tests/server/fakeimap.py`, `tests/server/fakehttp.py` | The read-only test doubles. |
| `tests/server/test_mailboxes.py`, `test_mailbox_imap.py`, `test_mailbox_graph.py`, `test_mailbox_gmail.py` | Settings, each connector, the milestone's "done when". |
| `frontend/` | The Mailboxes screen (admins), the queue's "Mailbox" source, the mock API. |
| `docs/SERVER.md`, `docs/FRONTEND.md`, README, CHANGELOG | Setting up each kind of mailbox with read-only access. |

## Pull requests

| PR | Tasks |
|---|---|
| 1 | Task 1: mailbox tables and sealed credentials |
| 2 | Task 2: the poll, with IMAP |
| 3 | Task 3: Microsoft Graph |
| 4 | Task 4: Gmail |
| 5 | Task 5: the API and the Mailboxes page |
| 6 | Task 6 and this plan: documentation |
| 7 | Task 7: the frontend's Mailboxes screen |

Each PR is based on the one before it and merged with a merge commit, so each task stays one commit.

## Tasks

### Task 1: Mailbox tables and sealed credentials

**Files:** create `src/phishhawk/server/mailboxes.py`, migration `0003_mailboxes.py`, `tests/server/test_mailboxes.py`; modify `models.py`, `jobs.py`, `rotation.py`, `tests/server/test_migrations.py`, `test_rotation.py`.

**Interfaces:** `Mailbox(id, name, kind, enabled, interval_minutes, config, secret, cursor, status, error, failures, last_poll_at, next_poll_at, last_counts, created_at)`; `MailboxItem(mailbox_id, remote_id, message_id, message_id_hmac, outcome, seen_at)`; `Submission.mailbox_id`; `mailboxes.create(db, box, data) -> Mailbox`, `update(db, box, mailbox, data) -> list[str]`, `view(mailbox) -> dict`, `secret_of(box, mailbox) -> str`, `MailboxError(status, message)`, `KINDS`, `CONNECTION`; job kind `mailbox_poll`.

- [x] Tests: each kind's settings and defaults (port 993, or 143 with STARTTLS; INBOX; inbox); what is refused (a host with a scheme or a path, a port out of range, a folder with a control character, a tenant that is not a GUID or domain, a client ID that is not a GUID, an address that is not one, an interval under 5 or over 1,440, a Gmail key that is not a service account's or whose private key does not load, an unknown kind, an empty or long name); names are unique (409); the view never holds the secret, only `secret_set`; the sealed secret does not open as another mailbox's; of a service account's key only its address and private key are kept, not its `token_uri`; changing the folder resets the cursor and changing the name, interval, enabled or secret does not; a mailbox keeps its kind; key rotation re-encrypts mailbox secrets and a second run moves nothing; an M2 database moves to M3 with its data; the migrations go down and up again and match the models.
- [x] They failed: `ImportError: cannot import name 'mailboxes'`, and `no such column: mailbox_id`.
- [x] The models, migration 0003 (written from Alembic's output, with named constraints), `mailboxes.py`, rotation. Run on Postgres 16 too. Commit.

### Task 2: The poll, with IMAP

**Files:** create `src/phishhawk/server/mailbox.py`, `tests/server/fakeimap.py`, `tests/server/test_mailbox_imap.py`; modify `imapfetch.py`, `intake.py`, `worker.py`, `views.py`, `tests/test_workflow.py` (UIDVALIDITY).

**Interfaces:** `poll(services, mailbox_id, heartbeat=None, session=None) -> dict` (the counts: `imported`, `duplicates`, `skipped`); `due(db, now=None) -> list[int]`; `queue_poll(db, mailbox_id) -> bool`; `gave_up(db, mailbox_id, error)`; `sanitise(reason, secrets) -> str`; `FIRST_POLL = 50`; `BACKOFF_CAP` (an hour); `imapfetch.connect`, `close`, `quote_folder`, `uidvalidity`, `fetch_uid` (public now; `fetch` uses them and behaves as before); `intake.accept(..., mailbox_id=None)`; `views.submitter_of(db, submission)`.

- [x] Tests, against the IMAP test server over TLS: the first poll imports the newest 50 of 60 messages and the next poll only the two that arrived since, as `mailbox` submissions analysed like uploads and audited as `mailbox:<name>`; a wrong password leaves `error` with "sign-in refused" and neither password in the reason, the audit log, the jobs or the view, and the polls wait 10, 20, 40, 60, 60 minutes; the right password resets it; nothing is imported twice: two polls in a row, a new UIDVALIDITY, the same message in two mailboxes, a message uploaded before, the same Message-ID with another header; a message over the limit is skipped and counted, and not fetched again; a connection dropped after two messages keeps the cursor at the second, and the next poll takes the other three; STARTTLS on port 143; a certificate from a CA no one trusts is refused; a missing folder is an error; the scheduler queues one poll when it is due, none while one waits, none for a disabled mailbox, and another once the interval has passed; a credential that does not open is an error, not a crash; the queue names the mailbox as the submitter and filters by `source=mailbox`, as do the API and the pages; and the double itself refuses SELECT and a FETCH of BODY[].
- [x] They failed: `ImportError: cannot import name 'mailbox'`; the submitter test on `None != 'Reports'`; the credential test on `DecryptError`.
- [x] The poll, the scheduler, the submitter's name; the CLI's IMAP tests pass unchanged. Commit.

### Task 3: Microsoft Graph

**Files:** create `tests/server/fakehttp.py`, `tests/server/test_mailbox_graph.py`; modify `mailbox.py`.

- [x] Tests, against the fake Graph: the token is asked for once per poll, by POST to the tenant's token URL with the client secret in the body, never in a URL; every GET goes to Graph with the token; the messages come through a delta query and the delta link is kept, and the next poll uses it; a folder the admin made is found by its name; next links are followed; a next link to another host stops the paging before anything is sent there; removed items are ignored; the first poll imports the newest 50 of 60; with a per-poll limit of 2, five new messages come in three polls without any downloaded twice; an expired delta link (410) starts again without duplicates; `invalid_client` gives "sign-in refused (invalid_client)" without the secret or Microsoft's own text; 403 names Mail.Read; 429 backs off; a reason never carries the secret, a bearer token or a control character; the double refuses a PATCH, a POST to the API and another host.
- [x] They failed: `KeyError: 'graph'`.
- [x] Commit.

### Task 4: Gmail

**Files:** create `tests/server/test_mailbox_gmail.py`; modify `mailbox.py`.

- [x] Tests, against the fake Gmail: the JWT's header and claims (`iss` the service account, `sub` the report mailbox, `scope` exactly `gmail.readonly`, `aud` Google's token URL, not the key file's, one hour) and its signature verifies with the key's public half; the first poll takes the profile's history ID before listing and imports the newest 50; later polls follow the history (`messageAdded`, under the label); a label is looked up by its name, and a missing one is an error; the history is followed page by page; a history ID too old (404) starts again without duplicates; more than one poll takes waits for the next; a message's size is checked before it is downloaded; another key gives "sign-in refused (invalid_grant)" naming domain-wide delegation, with no line of the key anywhere; the assertion is three base64url parts without padding; the double refuses a POST to the API and a DELETE.
- [x] They failed: `KeyError: 'gmail'`, and `module 'phishhawk.server.mailbox' has no attribute 'gmail_assertion'`.
- [x] Commit.

### Task 5: The API and the Mailboxes page

**Files:** create `templates/mailboxes.html`; modify `routes/api.py`, `routes/pages.py`, `templates/base.html`, `tests/server/test_rbac.py`, `test_hostile.py`, `test_pages.py`, `docs/api/openapi.json`; add API tests to `tests/server/test_mailboxes.py`.

- [x] Tests: create, list, read, change, poll now (queued, then not again while one waits) and delete through the API, each audited by name without the secret; 422 with the reason, 409 for a name in use, 404 for a mailbox that does not exist, 409 for Poll now when it is switched off; the role matrix's seven rows (admins only); a hostile mailbox name and error shown as text; the page adds, changes, polls and deletes without JavaScript, and shows a refusal's reason; the OpenAPI document is current; a real server and worker import after Poll now.
- [x] They failed: 404 for every mailbox route (the matrix's fixture could not create one).
- [x] Commit.

### Task 6: Documentation

`docs/SERVER.md` (setting up each kind with read-only access: an IMAP app password; a Graph app registration with the `Mail.Read` application permission, restricted to the report mailbox with RBAC for Applications or an application access policy; a Google Workspace service account with domain-wide delegation for `gmail.readonly` only; what is kept, the audit log, key rotation, troubleshooting), `docs/FRONTEND.md` (the mailbox calls), the README, the changelog; this plan.

### Task 7: The frontend's Mailboxes screen

The browser app gains a Mailboxes screen for admins (each mailbox's kind, status, last poll, sanitised error and counts; add, change, Poll now, delete; the secret written, never shown), "Mailbox" among the queue's sources, and the mock API's mailboxes. Its own tests, the lock test, `tsc`, the build, and the browser test against a real server with a fake IMAP server; the same files as a patch for Google AI Studio.
