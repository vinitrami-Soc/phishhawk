# PhishHawk v3: self-hosted web app (design)

Status: approved in brainstorming on 2026-10-06; written spec awaiting owner review
Owner: Vinit Rami
Source: "PhishHawk v3 Product Requirements Document" (draft of 2026-10-02)

## 1. Summary

PhishHawk v3 adds an optional, self-hosted web application on top of the existing
analysis engine. A small SOC team uploads or pastes reported emails (one at a time,
in batches, or from a report mailbox), sees a verdict with its evidence, downloads
the six report formats, and works through campaigns, with every action in an audit
log. The engine, the CLI and their 690 tests stay as they are; the web app is a new
package installed with `pip install "phishhawk[server]"` and shipped as one Docker
image.

Most of the PRD's functional requirements (FR-1 to FR-11) already exist in the v2
engine. The work in v3 is the platform around it: a web API and UI, local users and
roles, encrypted storage with retention, background jobs, an audit log and a stable
API that IntelPulse can use later.

## 2. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| D1 | Who runs it, where? | Self-hosted by one small team, one organisation, Docker. Local users with two roles, admin and analyst. | Lowest risk; matches IntelPulse's deployment model. |
| D2 | Raw email on the server | Encrypted at rest; deleted automatically after a retention period (default 30 days, admin can change); a smaller record stays. | Keeps evidence for the working window without collecting sensitive mail forever. |
| D3 | Enrichment default | Every provider off on a fresh install. Admin turns each on with its key. An analyst can choose "Offline" for any submission. No provider is required. | Outbound data is a deliberate choice, made per deployment and per message. |
| D4 | Response actions | PhishHawk stays read-only. It never deletes, moves or quarantines mail and never stores credentials that could. "Response" means a plan, a block list, a ticket or sweep results that the analyst runs in their own approved tool. | Keeps the public promise in the README and the Medium write-up; removes the most dangerous capability. |
| D5 | MVP scope | Core (upload or paste, verdict and evidence, audit, two roles, retention) plus all six exports, batch upload, the campaign view and mailbox import. IntelPulse handoff is a later spec. | The engine already produces all six formats and correlates campaigns. |
| D6 | Architecture | Approach A: a thin service in the same repository (`phishhawk.server`), SQLite by default with Postgres optional, a database-backed job queue and a separate worker process, one image. | Smallest operational footprint for a small team; reuses the engine untouched. Its API is the integration contract, so a separate shared service stays possible later. |

PRD open questions, answered:

- **Shared backend with IntelPulse?** Not in v3. PhishHawk runs its own service; IntelPulse
  integrates through PhishHawk's `/api/v1` (later spec).
- **Optional or mandatory providers?** All optional (D3).
- **Retention?** Tier 1 for `RETENTION_DAYS`, tier 2 until deleted by hand, admin hold for
  incidents (section 5).
- **What runs without approval?** Analysis, enabled enrichment, mailbox import, retention and
  campaign rebuilds. Nothing that changes a mailbox exists (D4).
- **Multi-tenant?** No. One organisation per deployment.

## 3. Scope

In the v3.0 release (built as milestones M1 to M3, section 11):

- Upload `.eml`, `.msg`, `.mbox` and `.zip`; paste a raw message.
- Analysis with the existing engine, offline or with the providers the admin enabled.
- Analysis page: verdict without scrolling, the existing HTML report, outbound lookups listed.
- Downloads: HTML, JSON, CSV, Markdown, STIX 2.1, MISP and the manifest.
- Batch submissions with combined exports.
- Campaigns across stored analyses.
- Mailbox import over IMAP, Microsoft Graph and the Gmail API, read-only.
- Local users, admin and analyst roles, API tokens.
- Encrypted storage, retention, hold, deletion.
- Hash-chained audit log.
- Docker image and a Compose file.

Out of scope for v3.0 (later specs): IntelPulse handoff; sandbox handoff and mailbox
sweep from the web; case notes and collaboration; SSO; multi-tenancy; any mailbox write
action (never, D4); detection changes (a separate track measured on new held-out data).

## 4. Architecture and components

The CLI and engine do not change, except one additive function in `campaign.py`
(section 6.4). The server depends on the engine only through `phishhawk.analysis`.

| Unit | Responsibility | Depends on |
|---|---|---|
| `phishhawk/analysis.py` | Facade. `analyze(raw: bytes, name: str, options: AnalysisOptions) -> AnalysisResult` returns the `Analysis`, its `to_dict()`, the six rendered exports, the manifest, the tier-2 summary and the campaign trait record, and the list of outbound lookups made. | `pipeline`, `report.*`, `campaign` |
| `server/config.py` | All settings from the environment: `DATA_DIR`, `DATABASE_URL`, `SECRET_KEY`, `ENCRYPTION_KEY`, `RETENTION_DAYS`, `MAX_UPLOAD_MB`, `MAX_BATCH_MESSAGES`, `CAMPAIGN_WINDOW_DAYS`, `BIND`, `TLS_CERT`/`TLS_KEY`. The four limits are defaults: an admin can change them in Settings, and the Settings value wins. Secrets never live in code or in the database in clear. | pydantic-settings |
| `server/db.py`, `server/models.py` | SQLAlchemy 2 models and Alembic migrations. SQLite (WAL) by default; Postgres through `DATABASE_URL`. | SQLAlchemy, Alembic |
| `server/store.py` | Encrypted blob store under `DATA_DIR/blobs`, retention sweeper, hold. | `cryptography` |
| `server/jobs.py`, `server/worker.py` | Job table, claiming, the worker loop, the child process that runs one analysis with resource limits, the scheduler for periodic jobs. | db, store, analysis |
| `server/auth.py` | Users, argon2id hashing, sessions, CSRF, roles, API tokens, login rate limiting. | db |
| `server/audit.py` | Append-only, hash-chained audit log and its verification. | db |
| `server/mailbox.py` | Read-only import from IMAP, Graph and Gmail, built on `imapfetch` and `mailapi`, with token acquisition for Graph and Gmail. | store, jobs, engine readers |
| `server/campaigns.py` | Rebuilds campaigns from tier-2 trait records. | `campaign.correlate_records` |
| `server/routes/` | JSON API under `/api/v1` and the HTML pages. | everything above |
| `server/templates/`, `server/static/` | Jinja2 templates, CSS and a little JavaScript, no build step. | none |
| `server/cli.py` | `phishhawk server run | worker | migrate | create-admin | rotate-key | audit verify`. | everything above |

`phishhawk server run` starts the web process and one worker process. Larger
deployments run `phishhawk server worker` separately and point `DATABASE_URL` at Postgres.

New dependencies, only in the `[server]` extra: fastapi, uvicorn, jinja2, sqlalchemy,
alembic, argon2-cffi, cryptography, python-multipart, pydantic-settings. The base install
keeps its single dependency (`requests`). Python 3.10 to 3.13, as now.

## 5. Data, encryption and retention

### 5.1 Two tiers

**Tier 1** (sensitive; deleted after `RETENTION_DAYS`, default 30), stored as encrypted
files, never in the database:

- the raw message as received;
- the full analysis JSON (`to_dict()`, which holds subject, recipients and body-derived text);
- the six exports and the manifest produced at analysis time.

**Tier 2** (kept until deleted by hand), in the database:

- message: SHA-256, size, source (upload, paste, batch, mailbox), submitted by and when,
  report ID, verdict, score, engine version, recipient count;
- sender address and sender domain;
- indicators (URLs, domains, IPs, file hashes, QR payloads, wallets, phone numbers) and
  ATT&CK technique IDs;
- the campaign trait record (section 6.4), in which the normalised subject and the sender
  display name are stored only as HMAC-SHA256 values under the installation's trait key
  (5.2), so they can be matched but not read.

Not in tier 2: recipient addresses, the subject in clear, body text, attachment names.

The same message submitted twice (same SHA-256) is one message with two submissions.

### 5.2 Encryption

- Each blob is encrypted with AES-256-GCM under `ENCRYPTION_KEY` (32 random bytes, base64,
  from the environment or a secret file). Each blob has a fresh 96-bit nonce; the blob ID is
  the associated data, so a blob moved to another record fails to decrypt.
- API keys and mailbox credentials in `settings` and `mailboxes` are encrypted the same way.
- The trait key for the HMAC values (5.1) is 32 random bytes generated at the first start and
  stored encrypted in `settings`. It never changes, because a new key would stop new records
  matching old ones whose tier 1 is gone; key rotation re-encrypts it but keeps its value.
  `SECRET_KEY` signs sessions and CSRF tokens only, and can be changed at any time.
- `phishhawk server rotate-key` re-encrypts every blob and secret under a new key, then
  records the rotation in the audit log.
- Plain message bytes are only ever in worker memory; they are never written to disk in clear.
- Without `ENCRYPTION_KEY` the server refuses to start. With the wrong key it refuses to
  decrypt and deletes nothing.
- In transit: TLS, either behind a reverse proxy (Caddy or nginx) or with uvicorn's own
  `TLS_CERT`/`TLS_KEY`. Cookies are `Secure`.

### 5.3 Retention, deletion and hold

- A `retention_sweep` job runs hourly. It deletes tier-1 blobs older than `RETENTION_DAYS`
  unless the message is on hold, marks the message `tier1_deleted_at`, and writes one audit
  record with the count.
- **Delete now** removes a message's tier 1 at once (an analyst for their own submissions, an
  admin for any).
- **Delete completely** (admin) also removes tier 2; the audit log keeps the SHA-256 and who
  deleted it.
- **Hold** (admin) exempts a message from the sweep, for incident evidence. Holding and
  releasing are audited.

## 6. Data flows and jobs

### 6.1 One message (upload or paste)

1. `POST /api/v1/submissions` with a file or raw text, plus `offline` (bool).
2. The server checks the size (`MAX_UPLOAD_MB`, default 25) and the type by magic bytes,
   computes the SHA-256, encrypts and stores the raw bytes, creates the submission and an
   `analyze` job, and answers `202` with the submission ID. Audited: `submit`.
3. The worker claims the job, decrypts in memory and runs `analysis.analyze()` in a child
   process limited to 2 GB of memory and 120 s of CPU. Options come from settings (enabled
   providers, protected domains, allowlist), with no providers if the analyst chose offline.
4. The worker stores tier 1 (JSON, exports, manifest), writes the tier-2 rows and the trait
   record, marks the job done and queues a `campaign_rebuild`. Audited: `analyze`, with the
   providers contacted.
5. The submit page polls `GET /api/v1/submissions/{id}` and opens the analysis page when
   the job is done.

The HTML report and the other exports are served side by side at
`/analyses/{id}/files/<safe name>`, so the report's "Report files" links (bare file names,
from v2's export work) resolve in the browser without change.

### 6.2 Batch

- Several files, or one `.mbox` or `.zip`, become one `batch` with one submission and one
  `analyze` job per message. Limits: `MAX_BATCH_MESSAGES` (default 500) and the total
  uncompressed size; names inside an archive are never used as paths.
- The batch page shows progress and each message's verdict.
- When every message is done, a `batch_finalize` job writes combined exports: the batch HTML
  report, JSON, CSV, STIX and MISP, plus a manifest (tier 1, same retention).

### 6.3 Mailbox import

- An admin adds a mailbox with read-only access only:
  - **IMAP:** host, port, user, password (or app password), folder. TLS certificates are
    always verified.
  - **Microsoft Graph:** tenant ID, client ID and client secret of an app registration with
    the `Mail.Read` application permission, and the report mailbox address. The setup guide
    recommends restricting the app to that mailbox with an Exchange application access
    policy. The server gets and renews tokens with the client-credentials flow.
  - **Gmail:** a Google Workspace service account with domain-wide delegation for the
    `gmail.readonly` scope only, impersonating the report mailbox. Personal Gmail accounts use
    IMAP with an app password instead.
- A `mailbox_poll` job runs every N minutes (N ≥ 5): IMAP by UID after the stored cursor,
  Graph by delta query, Gmail by history ID. Messages are fetched without being marked read,
  as the CLI does today. Each new message becomes a submission (source `mailbox`); duplicates
  are skipped by SHA-256 and Message-ID.
- On failure the mailbox shows `error` with a sanitised reason, polling backs off (up to one
  hour), and the failure is audited. Credentials never appear in the reason.

### 6.4 Campaigns

- `campaign.py` gains `correlate_records(records)`, where a record holds the trait sets, the
  host names under each domain trait, whether the message was flagged, and its summary.
  `correlate()` keeps its signature, builds those records from `(path, Analysis)` pairs and
  calls `correlate_records()`, so the CLI's output does not change.
- `analysis.analyze()` produces the record at analysis time; the server stores it in tier 2
  with the subject and display-name traits as HMAC values.
- A `campaign_rebuild` job (at most one queued at a time) correlates the records of the last
  `CAMPAIGN_WINDOW_DAYS` (default 90) and stores the campaigns.
- The campaign page shows shared indicators in clear. A shared subject or display name is
  shown in clear while tier 1 still exists for one of its messages, and as "same subject" or
  "same display name" after that. Recipient addresses are listed only while tier 1 exists;
  afterwards only counts.

### 6.5 Job mechanics

- Job kinds: `analyze`, `batch_finalize`, `campaign_rebuild`, `mailbox_poll`, `retention_sweep`.
- A worker claims a job in one transaction (SQLite: one worker; Postgres: `FOR UPDATE SKIP
  LOCKED`, several workers) and sends a heartbeat while it runs.
- An `analyze` job that fails because of its input (the engine raised, or a limit was hit)
  is not retried: the same input fails the same way. A job whose worker died is requeued, at
  most twice.
- A job running longer than its timeout plus a grace period is marked failed (`analyze`) or
  requeued (the others).
- A scheduler loop inside the worker process queues the periodic jobs.

## 7. Security

### 7.1 Threats

Attacker-controlled email content (stored XSS in lists and pages, parser and decompression
bombs, hostile archives); an authenticated user acting beyond their role; session theft and
CSRF; secrets leaking into logs or exports; a provider or mailbox host used to reach
somewhere else.

### 7.2 Authentication and roles

- Local users, argon2id hashes. Login is rate-limited per user and per address, with a
  growing delay after failures. The first admin is created with `phishhawk server create-admin`.
- Session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, eight hours idle timeout. Every
  state-changing request carries a CSRF token.
- API tokens for IntelPulse and scripts: created by an admin, shown once, stored as a hash,
  scope `read` or `submit`, revocable.

| Action | Analyst | Admin |
|---|---|---|
| Submit, view all analyses, batches and campaigns, download exports | yes | yes |
| Download a raw message | own submissions | any |
| Delete now (tier 1) | own submissions | any |
| Re-analyze | yes | yes |
| Hold and release, delete completely | no | yes |
| Users, API tokens, providers and keys, retention, protected domains | no | yes |
| Mailboxes | no | yes |
| Audit log | own actions | all |
| Rotate the encryption key | no | yes (CLI) |

### 7.3 Web hardening

- Every response has a header Content-Security-Policy: `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action
  'self'; frame-ancestors 'none'; base-uri 'none'`, plus `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` and HSTS when served over TLS.
- Templates auto-escape. Every attacker-written string shown outside the report also passes
  through the engine's `printable()`, so control and bidirectional characters are shown, not
  obeyed.
- The stored HTML report is served with `Content-Security-Policy: sandbox` (no
  `allow-scripts`, no `allow-same-origin`) on top of its own policy, so it runs in an opaque
  origin with no access to the session even if an escaping bug existed. Only the report
  endpoint allows framing, and only by the app's own pages (`frame-ancestors 'self'`).
- Downloads are `Content-Disposition: attachment` with the safe names from v2's export work.
  Raw messages are never served inline.

### 7.4 Uploads and the worker

- Size and count limits on uploads and archives. Archive member names are never used as
  file names.
- Each analysis runs in a child process with memory and CPU limits; the engine's own read
  budgets still apply.
- The worker only makes outbound requests to enabled providers and configured mailbox
  hosts. A deployment that needs to be offline runs the worker container with
  `--network none`.
- Each analysis records what was sent to which provider (a hash, a host name, a domain or an
  IP) and shows it on the analysis page.

### 7.5 Read-only guarantee

Mailbox connectors request only read scopes. Tests run them against fake IMAP, Graph and Gmail
servers that record every call and fail on anything but reads (`EXAMINE`/`SELECT ...
READ-ONLY` and `BODY.PEEK` for IMAP; `GET` for Graph and Gmail).

### 7.6 Secrets, logs and audit

- Secrets come only from the environment or secret files. Logs are JSON with credentials and
  tokens masked, and never contain message content.
- Audited: login success and failure, logout, submit, analysis done (with providers),
  re-analyze, every download, delete, hold and release, settings changes, user and token
  changes, mailbox changes and poll failures, key rotation, retention sweeps.
- Each audit record holds the hash of the previous one. `phishhawk server audit verify`
  reports any record that was changed, removed or reordered.

## 8. User interface

Server-rendered HTML (Jinja2) with a little vanilla JavaScript for drag-and-drop and progress
polling; every form also works without JavaScript. The design is the v2 report's: amber and
navy, the same fonts, light and dark, WCAG AA contrast. No framework, no build step.

| Page | Contents |
|---|---|
| Login | Username and password. |
| Submit (home) | Drop zone for `.eml .msg .mbox .zip`, a "paste raw email" field, an "Offline (no lookups)" switch; the last ten submissions with their verdicts. |
| Queue | Table of analyses: time, subject (escaped, shortened), sender domain, verdict badge, score, source, status. Filters: verdict, source, date, user. Search by SHA-256, report ID or indicator. Cards on phones. |
| Analysis | A bar with verdict, score, report ID, downloads (six formats and the manifest), "Outbound lookups", Delete, and Hold for admins; below, the HTML report in a sandboxed frame, and "Open full report" for printing. |
| Batch | Progress, one row per message, combined downloads. |
| Campaigns | List (messages, first and last seen, shared indicators, verdict mix) and a detail page. |
| Mailboxes (admin) | Add and edit, status, last poll, sanitised error, "Poll now". |
| Settings (admin) | Providers (on/off, masked key, "Test connection"), retention days, protected domains, allowlist, users and roles, API tokens. |
| Audit | Filterable table; analysts see their own actions. |

Accessibility as in the report: a skip link, one `h1`, named regions, a visible focus ring,
everything reachable by keyboard; tested the same way.

## 9. API (`/api/v1`, the integration contract)

All endpoints take a session cookie with a CSRF token, or an API token as
`Authorization: Bearer`. Errors are JSON `{"error": code, "detail": text}`.

| Method and path | Purpose | Role |
|---|---|---|
| `POST /submissions` | Upload files or raw text; `offline` flag. 202 with submission IDs and batch ID. | analyst |
| `GET /submissions/{id}` | Status and analysis ID. | analyst |
| `GET /analyses` | List with filters and search. | analyst |
| `GET /analyses/{id}` | Tier-2 summary, plus the full JSON while tier 1 exists. | analyst |
| `GET /analyses/{id}/files/{name}` | One export, the manifest or the HTML report. | analyst |
| `POST /analyses/{id}/reanalyze` | New analysis version from the stored raw message. | analyst |
| `GET /messages/{id}/raw` | The raw message as an attachment. | owner or admin |
| `DELETE /messages/{id}?scope=tier1` | Delete now. | owner or admin |
| `DELETE /messages/{id}?scope=all` | Delete completely. | admin |
| `POST /messages/{id}/hold`, `DELETE /messages/{id}/hold` | Hold and release. | admin |
| `GET /batches/{id}`, `GET /batches/{id}/files/{name}` | Batch status and combined exports. | analyst |
| `GET /campaigns`, `GET /campaigns/{id}` | Campaigns. | analyst |
| `GET/POST/PATCH/DELETE /mailboxes`, `POST /mailboxes/{id}/poll` | Mailbox import. | admin |
| `GET/PATCH /settings`, `POST /settings/providers/{name}/test` | Settings. | admin |
| `GET/POST/PATCH/DELETE /users`, `GET/POST/DELETE /tokens` | Users and API tokens. | admin |
| `GET /audit` | Audit log (own actions for analysts). | analyst |
| `GET /healthz` (outside `/api/v1`) | Database, worker heartbeat, disk space, queue depth. | none |

The OpenAPI document is generated by FastAPI and kept in `docs/api/openapi.json`; a test
fails when the routes change without it.

## 10. Errors and operations

- A message the engine cannot read: the job fails with a sanitised reason; the raw message
  stays in tier 1 for "Re-analyze" after an engine update.
- A limit hit: "this message exceeded the analysis limits", job failed, server unaffected.
- A provider failing: the analysis completes with "Reputation: partially checked", as in v2.
- SQLite busy: retried with backoff; the docs say to use Postgres for more than one worker.
- `/healthz` for monitors; JSON logs with a request ID on every line.
- Backups: `DATA_DIR` (blobs) and the database, documented together; a backup without
  `ENCRYPTION_KEY` cannot be read, by design.

## 11. Milestones

Each milestone is a series of small PRs; the CLI keeps working after every one.

**M1: one message end to end.** Facade, server skeleton and config, database and migrations,
encrypted store, jobs and worker with limits, auth with both roles and API tokens, submit
(upload and paste), analysis page with the report and the six downloads, provider settings,
audit log and verification, retention, hold and deletion, health, Docker image and Compose
file.
*Done when:* an analyst logs in, submits a bundled sample, sees the verdict and downloads all
six formats; the audit log verifies; a message past retention loses its tier 1 and keeps its
tier 2; the hostile-payload test passes on every page.

**M2: batch and campaigns.** Batch upload (`.mbox`, `.zip`, several files), batch page and
combined exports, `correlate_records()` and the campaign pages.
*Done when:* 500 bundled and synthetic messages run as one batch without blocking the UI,
and the campaigns match what the CLI's `phishhawk campaign` reports for the same messages.

**M3: mailbox import.** IMAP, then Graph, then Gmail, each with its read-only test double.
*Done when:* each connector imports new messages from its fake server without a single
non-read call, survives a credential failure with a sanitised error, and never imports the
same message twice.

**Release v3.0.0** after M3: a security review round recorded in `docs/SECURITY-REVIEW.md`,
user and admin docs, screenshots, changelog and release notes.

## 12. Testing

- The existing 690 tests stay green at every step.
- `tests/server/` (TDD, as in v2):
  - a role matrix test that calls every route as anonymous, analyst and admin and checks the
    status;
  - CSRF, session expiry, login rate limit, API token scopes;
  - store: round trip, nonce uniqueness, swapped blob detected, key rotation, retention with a
    fake clock, hold, both deletes;
  - jobs: claim, heartbeat, timeout, requeue, no retry on input failures, a decompression bomb
    that hits the limit and fails safely, duplicate submissions;
  - security: the v2 hostile fixture submitted through the API, then every page parsed
    against an allowlist of tags, attributes and links; the CSP header on every response;
    `sandbox` on the report; downloads as attachments; path traversal inside a batch archive;
  - the read-only test doubles for IMAP, Graph and Gmail;
  - audit: verification passes, and fails after a record is edited, removed or reordered;
  - campaigns: `correlate()` output unchanged for the existing campaign tests;
    `correlate_records()` on stored records matches it.
- Browser tests with Playwright (headless Chromium): log in, submit, see the verdict, download;
  keyboard only; widths 320 to 1440 px; the contrast test reused for the app's colours.
- Performance: a bundled sample from submit to verdict in under 5 s offline on the CI runner.
- CI: a job for the server extra on Python 3.10 to 3.13, and a Docker smoke test (Compose up,
  `/healthz`, submit a sample, fetch the report).

## 13. PRD traceability

| PRD item | Where |
|---|---|
| FR-1 intake (eml, msg, paste, IMAP) | 6.1, 6.2, 6.3 |
| FR-2 evidence preservation | 5.1 tier 1, 5.3 hold, SHA-256 and manifest |
| FR-3 to FR-8 headers, URLs, enrichment, RDAP, attachments, QR | existing engine through the facade (4) |
| FR-9 campaigns | 6.4 |
| FR-10 verdict with reasoning | existing engine and report (8) |
| FR-11 exports | 6.1, 6.2, 9 |
| FR-12 IntelPulse | API contract in 9; handoff in a later spec |
| FR-13 audit logging | 7.6 |
| Security, privacy, retention NFRs | 5, 7 |
| Performance and reliability NFRs | 6.5, 10, 12 |
| Usability NFRs, UX requirements | 8 |
| Operability | 4 (`server run`), 10 |

## 14. Risks

- **The server now holds sensitive mail.** Mitigated by tier 1 encryption and retention,
  tier 2 minimisation, the HMAC traits and the audit log; documented for admins.
- **A hostile message reaching the browser.** Mitigated by escaping, the strict CSP, the
  sandboxed report origin and the hostile-payload tests on every page.
- **Scope.** v3.0 now covers what the PRD split across 3.0 and 3.1. Mitigated by the three
  milestones, each shippable on its own.
- **Mailbox credentials.** Read-only scopes only, encrypted, admin-only, audited, and tested
  against write calls.
