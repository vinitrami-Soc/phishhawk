# PhishHawk v3 M2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Several files, an .mbox or a .zip submitted as one batch, with combined exports, and campaigns found across the stored messages exactly as the CLI's `phishhawk campaign` finds them (milestone M2 of the v3 design).

**Architecture:** The web process splits an upload into messages in memory, within limits, and queues one analysis per message, as M1 does for one. Each analysis also keeps the engine's `Analysis` as JSON (tier 1), so a `batch_finalize` job renders the combined exports without analysing again. A `campaign_rebuild` job runs `campaign.correlate_records()` over the records kept in tier 2. Analysis children fork from a process that already holds the engine. Postgres (psycopg 3) lets several workers share the queue.

**Tech Stack:** As M1; plus psycopg 3 in a new `postgres` extra, and multiprocessing's forkserver.

**Spec:** [docs/superpowers/specs/2026-10-06-phishhawk-v3-web-design.md](../specs/2026-10-06-phishhawk-v3-web-design.md), section 11, M2 ("Batch upload (`.mbox`, `.zip`, several files), batch page and combined exports, `correlate_records()` and the campaign pages"), with section 6.2 (batch) and 6.4 (campaigns). M1's plan moved two more things here: "Postgres and several workers are built and tested in M2", and the queue's source, date and user filters.

## Global Constraints

The M1 plan's constraints hold unchanged: Python 3.10 to 3.13; the base install needs only `requests`; the server reaches the engine only through `phishhawk.analysis`; "Plain message bytes are only ever in worker memory; they are never written to disk in clear"; the existing tests stay green at every step, with `ruff check src tests samples eval tools phishhawk` (line length 115) and `mypy` clean with and without the server extra; no secret literals in tests; one commit per task by Vinit Rami, without co-author lines. In addition:

- Engine: "`campaign.py` gains `correlate_records(records)` ... `correlate()` keeps its signature ... so the CLI's output does not change." Proven byte for byte on real mail, not only by the tests.
- Batch limits: `MAX_BATCH_MESSAGES` (500) and "the total uncompressed size; names inside an archive are never used as paths".
- Campaigns: "A shared subject or display name is shown in clear while tier 1 still exists for one of its messages, and as 'same subject' or 'same display name' after that. Recipient addresses are listed only while tier 1 exists; afterwards only counts."
- Done when: "500 bundled and synthetic messages run as one batch without blocking the UI, and the campaigns match what the CLI's `phishhawk campaign` reports for the same messages."

## How this plan was checked

The milestone was built task by task on a branch from `main`, test first. Each task below names the test that failed first and how; with its code it passed, and the whole suite, ruff and mypy stayed clean with and without the server extra. At the end:

- With the server extra, on SQLite: 872 passed, 4 skipped (the Postgres-only workers test, the 500-message check run on its own, the frontend browser test without a frontend build, and YARA, not installed here; CI runs each).
- Without it: 698 passed, 1 skipped.
- The web app's tests on Postgres 16, each on a database of its own: 174 passed, 3 skipped.
- The milestone check (task 8): 500 messages in 44 s, the slowest page 0.09 s meanwhile, campaigns equal to the CLI's.
- `phishhawk campaign` wrote byte-identical JSON, CSV and Markdown before and after task 2, on 167 synthetic and 1,896 real (SpamAssassin spam) messages.
- Saved and loaded (task 3), 2,063 messages rendered every format byte for byte as from the original analysis, and 300 of them together as one bundle.

Found and fixed along the way, each with a test: Starlette writes an uploaded file past 1 MB to a temporary file, so a large message reached the disk in clear in M1 (task 1); a job that crashed, or whose worker died three times, left its message "running" for good, which would have stalled a batch (task 6); two workers' first audit records could race to create the chain's head on Postgres (task 9). Hypothesis also turned up a defect older than M2: report free text keeps a bare `www.` link live (`tests/test_properties.py`, example `WWW.0`); it is left to a change of its own.

## Decisions the spec left open, settled here

1. **Splitting happens in the web process, in memory.** An upload is read whole; a request body over 4 x `MAX_UPLOAD_MB` is refused from its Content-Length before any of it is read (413), and one without a length is refused (411). Each message may be `MAX_UPLOAD_MB`, all of them together 4 x `MAX_UPLOAD_MB` ("the total uncompressed size"). A 500-message .mbox is accepted in about a second.
2. **Uploads are never spooled.** Starlette's spool limit is raised past the body limit, which bounds memory instead (decision 1).
3. **An .mbox is split as Python's `mailbox.mbox` reads it**, so the CLI and the web app see the same bytes and hashes. Every entry is a message by the mbox's framing, as the CLI treats it; plain files and .zip members are type-checked.
4. **A .zip gives each .eml, .msg or .mbox inside it**; other files and archives inside are skipped and counted (`skipped` in the answer); encrypted members are skipped. Its entries are counted from their signatures before it is opened, and each member is read only one byte past the limit, so a bomb is never inflated.
5. **One message is not a batch**: the answer has M1's shape plus `batch_id: null`. Several are a batch: `{batch_id, total, submission_ids, skipped}`.
6. **Combined exports come from saved analyses.** Each analysis keeps `analysis.save_state()` (the engine's `Analysis` as JSON, without the body text, which no report shows) as a sealed tier-1 blob; `batch_finalize` loads them and renders every format with the CLI's own renderer, in a limited child process. Analysing again would query providers again and could differ. They include Markdown, as a single message's exports do.
7. **A batch's combined exports are tier 1** and hold every message in them: they are deleted when any of those messages' tier 1 is (Delete now, Delete completely, retention), and after the retention period counted from the batch, hold or not. A message deleted before its analysis is left out of them.
8. **Batch rows show no subject**: that would mean opening every message's report on each refresh. The analysis page has it.
9. **A campaign's ID is its oldest message's ID**, so its link stays while it grows.
10. **Campaign rebuilds**: queued after each analysis when none is waiting; hourly, as messages leave the window; and after Delete completely. The window counts from each message's first submission.
11. **The campaign list shows a hidden trait as "same subject"**; the campaign page resolves it from the tier 1 of its messages.
12. **A job that crashes fails its submission** with "the analysis stopped: " and the exception's type, never its text, which may quote the message. So does one whose worker died three times.
13. **Children fork from a server process with the engine preloaded** (multiprocessing's forkserver): 0.07 s per message instead of 0.6, with the same memory and CPU limits.
14. **Postgres through psycopg 3**, in a new `postgres` extra (and the Docker image). `postgresql://` and `postgres://` URLs are given the driver. Migration 0002 creates the audit chain's head row.
15. **Queue days are UTC, both ends included.** On the built-in page an empty or malformed date filters nothing; the API answers 422.

## Not in M2

Mailbox import (M3); JSON logs with a request ID; the providers' "Test connection" button; the IntelPulse handoff (a later spec); the bare `www.` defanging above.

## File map

| Path | Responsibility |
|---|---|
| `src/phishhawk/campaign.py` | `correlate_records()`; `correlate()` builds records and calls it. `trait_record()` gains the date; `normalise_display_name()` names the rule `_traits()` used. |
| `src/phishhawk/analysis.py` | `AnalysisResult.state`, `save_state()`, `load_state()`, `render_saved()`, `hidden_traits()`. |
| `src/phishhawk/server/bodylimit.py` | The body limit middleware; uploads not spooled. |
| `src/phishhawk/server/batches.py` | Splitting (.mbox, .zip, several files) with limits; creating a batch; its view; finishing it; its combined exports. |
| `src/phishhawk/server/campaigns.py` | Rebuild from tier 2; list and detail views with hidden traits resolved while tier 1 exists. |
| `src/phishhawk/server/models.py`, `migrations/versions/0002_batches_and_campaigns.py` | `Batch`, `Campaign`, `CampaignMember`; a submission's batch and position; an analysis's `state_blob`; the audit head row. |
| `src/phishhawk/server/processing.py`, `worker.py`, `jobs.py`, `limits.py` | The saved analysis; `batch_finalize` and `campaign_rebuild` jobs; failed submissions after a crash; the forkserver. |
| `src/phishhawk/server/retention.py`, `rotation.py` | Deleting and re-encrypting the new tier-1 blobs. |
| `src/phishhawk/server/routes/api.py`, `routes/pages.py`, `routes/files.py`, `views.py`, `templates/` | Batch and campaign API and pages; the queue's filters. |
| `src/phishhawk/server/config.py` | Postgres URLs given the psycopg driver. |
| `tests/server/serverkit.py`, `conftest.py` | A database of its own for each test on Postgres (`PHISHHAWK_TEST_DATABASE_URL`). |
| `tests/server/test_milestone.py` | The milestone check. |
| `.github/workflows/ci.yml` | The milestone check on Python 3.12; the web app's tests on `postgres:16`. |

## Pull requests

| PR | Tasks |
|---|---|
| 1 | Task 1: uploads stay in memory |
| 2 | Tasks 2 and 3: the engine side (correlate_records, saved analyses) |
| 3 | Tasks 4 to 6: batches |
| 4 | Task 7: campaigns |
| 5 | Task 8: the milestone check, and faster children |
| 6 | Tasks 9 and 10: Postgres and several workers; the queue's filters |
| 7 | Task 11 and this plan: documentation |
| 8 | Task 12: the frontend's batch and campaign screens |

Each PR is based on the one before it and merged with a merge commit, so each task stays one commit.

## Tasks

### Task 1: Uploads stay in memory

**Files:** create `src/phishhawk/server/bodylimit.py`, `tests/server/test_uploads.py`; modify `src/phishhawk/server/app.py`.

**Interfaces:** `BodyLimit(app, limit: Callable[[], int])`, ASGI; `BATCH_FACTOR = 4`; `MB`.

- [x] Tests: `test_an_upload_larger_than_a_megabyte_stays_in_memory` (a 3 MB message through the API; `SpooledTemporaryFile.rollover` must not be called), `test_a_body_over_the_limit_is_refused_before_it_is_read` (101 MB declared: 413 "larger than 100 MB" and `receive` never called), `test_a_body_without_a_length_is_refused` (chunked: 411).
- [x] They failed: rollover was called once; both oversized and chunked bodies got 400 from the form parser.
- [x] `BodyLimit` refuses from the Content-Length, the limit read from the settings for each request; `MultiPartParser.spool_max_size` is raised. Added innermost, so its answers carry the security headers.
- [x] Whole suite, ruff, mypy; commit "M2 task 1: uploads stay in memory".

### Task 2: correlate_records(), campaigns from stored records

**Files:** modify `src/phishhawk/campaign.py`, `tests/test_campaign.py`.

**Interfaces:** `correlate_records(records: list[dict], min_size=2, weak_cap=200) -> dict`, the same result shape as `correlate()`. A record is `trait_record(a)` (`traits`, `under`, `flagged`, and now `date`, ISO UTC or "") plus `verdict`, `sender`, `recipients` and `summary` (passed through, ordered by its `"path"`).

- [x] Test: `test_stored_records_correlate_as_the_messages_do`: nine messages (a shared attachment, a shared phishing domain, two weak traits together, loners), their records through JSON with subject and display name replaced by SHA-256 values; clusters, members, dates, verdicts, senders, recipients and shared kinds equal `correlate()`'s.
- [x] It failed: `ImportError: cannot import name 'correlate_records'`.
- [x] `correlate()` builds the records and calls `correlate_records()`. Dates sort as times (a year before 1000 has fewer digits).
- [x] `phishhawk campaign` on main and on the branch, over 167 synthetic and 1,896 real messages: JSON, CSV and Markdown byte-identical. Commit.

### Task 3: Saved analyses, for a batch's combined exports

**Files:** modify `src/phishhawk/analysis.py`, `src/phishhawk/campaign.py`, `tests/test_analysis_facade.py`.

**Interfaces:** `AnalysisResult.state: bytes`; `save_state(a) -> bytes`; `load_state(data) -> Analysis` (ValueError for another format); `render_saved(states, tlp="amber", day=None) -> list[RenderedFile]`; `hidden_traits(report: dict) -> {"subject": str, "display name": str}`; `campaign.normalise_display_name()`.

- [x] Tests, with the clock and the STIX bundle's random ID fixed: every bundled sample renders every format byte for byte from the loaded state, which has no body text; five samples together render as `render_bundle()` of the analyses; a state of another version is refused; `hidden_traits()` gives the values `trait_record()` hides.
- [x] They failed: `AttributeError: module 'phishhawk.analysis' has no attribute 'load_state'` (and `render_saved`, `hidden_traits`).
- [x] A typed decoder rebuilds the dataclasses from `dataclasses.asdict()` after JSON: nested dataclasses and tuples come back as they were.
- [x] 2,063 messages saved and loaded rendered identically, and 300 together. Commit.

### Task 4: Tables for batches and campaigns, and the saved analysis

**Files:** modify `models.py`, `processing.py`, `retention.py`, `rotation.py`; create migration 0002; modify `tests/server/test_processing.py`, `test_rotation.py`, `test_migrations.py`.

- [x] Tests: the worker stores the saved analysis sealed and `load_state()` reads it back; the retention sweep removes it; rotation re-encrypts it (9 blobs become 10) and a batch's combined exports; an M1 database moves to M2 with its data; the migrations match the models.
- [x] They failed on `'Analysis' object has no attribute 'state_blob'`, and the rotation count (9, not 10); the batch rotation test failed with the code taken out (0 blobs moved, not 1).
- [x] `Batch`, `Campaign`, `CampaignMember`, `Submission.batch_id` and `position`, `Analysis.state_blob`. Migration 0002 written by hand from Alembic's output: a server default for `position` on M1's rows and a named foreign key. It was run up, down and up again. Commit.

### Task 5: Batch upload

**Files:** create `src/phishhawk/server/batches.py`, `templates/batch.html`, `tests/server/test_batches.py`; modify `intake.py`, `routes/api.py`, `routes/pages.py`, `templates/home.html`, the role matrix, the hostile-payload test, `docs/api/openapi.json`.

**Interfaces:** `split(files, *, max_messages, max_message_bytes, max_total) -> Split(messages, skipped)`; `BatchError(status, message)`; `mbox_messages(data)`; `accept(db, store, messages, ...) -> Batch`; `GET /api/v1/batches/{id}`; the page `/batches/{id}`.

- [x] Tests: six .mbox shapes (junk before the first message, no final newline, CRLF, consecutive From lines, a quoted `>From`) split exactly as `mailbox.mbox` reads them; a .zip gives its messages in order, skips a text file and an inner archive and never uses `../../etc/evil.eml`; a 64 MB bomb under 1 MB compressed is refused (413) before it inflates; 2,000 entries are refused before the archive is opened; each limit's message; non-messages refused (415); several files become one batch, analysed one by one, in order; an mbox keeps its order; one message is not a batch; the batch limit from Settings; the home page takes several files and opens the batch page, which refreshes while it runs.
- [x] They failed: `ImportError: cannot import name 'batches'`. One more, added when a real mailbox's entry failed the type check: every entry of an mbox is a message, as the CLI reads it.
- [x] The routes, the page and the role matrix rows. Commit.

### Task 6: A batch's combined exports

**Files:** modify `batches.py`, `worker.py`, `jobs.py`, `retention.py`, `routes/*`, `templates/batch.html`, `tests/server/test_batches.py`, the role matrix.

**Interfaces:** job `batch_finalize`; `after_submission(db, submission)`; `finalize(services, batch_id, heartbeat)`; `GET /api/v1/batches/{id}/files/{name}`; `jobs.requeue_stale(..., given_up)`.

- [x] Tests: when every message is done the batch has the seven files (the manifest lists three messages, the JSON three reports, the HTML report is sandboxed, the CSV downloads); a message deleted before its analysis does not stop the batch and is left out; deleting a message deletes the combined exports (410 afterwards); the retention period deletes them even when the messages are held; a crash fails that message ("the analysis stopped: RuntimeError") and the batch still finishes; so does a message whose worker died three times.
- [x] They failed: the batch stayed `running`, and `files_deleted_at` did not exist.
- [x] `finalize()` renders in a limited child and discards its files if a message in them was deleted meanwhile. Commit.

### Task 7: Campaigns

**Files:** create `src/phishhawk/server/campaigns.py`, `templates/campaigns.html`, `campaign.html`, `_shared.html`, `tests/server/test_campaigns.py`; modify `processing.py`, `worker.py`, `jobs.py`, `routes/*`, `base.html`, the role matrix, the hostile-payload test, `test_worker.py`.

**Interfaces:** job `campaign_rebuild`; `queue_rebuild(db)`; `rebuild(db, window_days, now=None) -> int`; `GET /api/v1/campaigns`, `GET /api/v1/campaigns/{id}`; pages `/campaigns` and `/campaigns/{id}`.

- [x] Tests: for nine messages the web app's three campaigns have the CLI's members, sizes, dates, verdicts, senders and shared kinds; a campaign shows what links it, its recipients and its messages' subjects; after its messages' tier 1 is deleted it keeps its shape but shows "same subject" and no addresses; one rebuild waits at a time, and a campaign keeps its ID as it grows; Delete completely rebuilds; an hourly rebuild is scheduled; the pages; the hostile subject shown in clear stays text.
- [x] They failed: 404 for every campaign route. The schedule and Delete-completely tests failed with their lines taken out.
- [x] `test_the_sweep_deletes_tier1...` now drains the queue: an analysis queues a rebuild before the sweep. Commit.

### Task 8: 500 messages as one batch

**Files:** modify `limits.py`, `tests/server/test_limits.py`, `.github/workflows/ci.yml`; create `tests/server/test_milestone.py`.

- [x] Test: a child starts with the engine already loaded (`phishhawk.report.html` in `sys.modules`, which nothing in the test imports). It failed with the spawn start method.
- [x] The forkserver with `PRELOAD` (the facade, processing, batches): 0.065 s per message, warm, against 0.6 s.
- [x] The milestone check (`PHISHHAWK_M2_CHECK=1`): a real server and worker take the five samples and 495 synthetic messages (`eval/make_corpus.py`, seeds 7 to 9) as one .zip, while the queue, the analyses and the campaign pages are fetched in a loop; all 500 done with their seven combined files; the slowest page under 1 s (0.09 s here); the campaigns equal `correlate()` over the same messages. 44 s here. CI runs it on Python 3.12. Commit.

### Task 9: Postgres and several workers

**Files:** modify `config.py`, migration 0002, `pyproject.toml` (`postgres` extra), `server.Dockerfile`, `ci.yml`, `tests/server/serverkit.py`, `conftest.py`, `test_config.py`, `test_db.py`, `test_migrations.py`; create `tests/server/test_workers.py`.

- [x] Tests: a Postgres URL is given the psycopg driver; the audit head exists with the schema; three workers on one Postgres database share a 40-message batch, each job claimed once (one attempt each, 40 analyses) and the audit chain verifies.
- [x] They failed: the URL kept `postgresql://`; no head row. Without the row lock in `jobs.claim()` the workers test saw 41 analyses.
- [x] The whole web app suite ran on Postgres 16 (two SQLite-specific tests adjusted: the WAL test is skipped there, and the M1 data uses `false`, not `0`). psycopg 3.2.1, the floor, passed too. Commit.

### Task 10: The queue's filters

**Files:** modify `views.py`, `routes/api.py`, `routes/pages.py`, `templates/queue.html`; create `tests/server/test_queue.py`.

- [x] Tests: filter by source and by who submitted; by day (an analysis at 23:59 on 30 September is in `until=2026-09-30` and not in `since=2026-10-01`; a malformed day is 422 in the API); the page has every filter and applies it.
- [x] They failed: every filter returned all four analyses. Commit.

### Task 11: Documentation

`docs/SERVER.md` (batches, campaigns, what each keeps, the limits, Postgres), `docs/FRONTEND.md` (the batch and campaign calls, the queue's filters), the README and the changelog; this plan.

### Task 12: The frontend's batch and campaign screens

The browser app in `frontend/` gains, against the API above: several files, an .mbox or a .zip on the Triage screen, opening a Batch screen (progress, each message's verdict, the combined reports); Campaigns and a Campaign screen (what links it, "same subject" while hidden, its messages); and the queue's source, user and date filters. Its own tests, the lock test for the files AI Studio must not change, `tsc`, the build, and the browser test against a real server at seven widths; the same files as a patch for Google AI Studio.

- [x] Tests (`npm test`): the routes for a batch, the campaigns and a campaign; the mock's batches (several files or an archive are a batch, one file is not), campaigns (the subject hidden in the list) and the queue's filters (a malformed day is 422); a shared trait's label, its defanged value, and "Same subject" once hidden.
- [x] They failed on the code before: the routes were "not found", the mock had no batches or campaigns and ignored the filters, and `@/lib/traits` did not exist.
- [x] The browser test: two messages with one attachment, uploaded together, open the batch page (Open in a new tab, Download), then their campaign ("Attachment (SHA-256)", both messages), then the queue's Paste, Batch, Only mine and From filters; nothing past the right edge on the four new pages at seven widths; no console errors. The locked files' fingerprints are updated, `traits.ts` and its test among them. Commit.
