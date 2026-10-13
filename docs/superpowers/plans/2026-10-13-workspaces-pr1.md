# Workspaces in the data (PR 1 of the sign-up work) implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every row the web app keeps belongs to a workspace, and no
workspace can read or change another's data. An upgraded server behaves
exactly as before, with all its data in "Default organization".

**Architecture:**
- Migration 0004 adds a `workspaces` table and `workspace_id` to the tables
  that hold workspace data.
- Uniqueness becomes per workspace.
- `Actor` carries the workspace. Every route and built-in page reads through
  scoped getters (`scope.py`), and an object of another workspace is 404.
- Settings become `(workspace_id, key)`. Server-wide values live under
  workspace 0.
- The audit log stays one chain. A record's `workspace_id` is hashed when it is
  set, so pre-upgrade records still verify.

**Tech stack:** FastAPI, SQLAlchemy 2, Alembic, SQLite and PostgreSQL, pytest.

## Global constraints

- Spec: `docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md`,
  sections 2, 3, 4 and 11 (isolation and migration tests).
- A row of another workspace is **404**, never 403.
- No new screens or API fields in this PR, except the `workspace` object in
  `GET /api/v1/session`.
- `intake.accept`, `batches.accept` and mailbox imports **require** a
  workspace; there is no default, so a forgotten argument fails loudly.
- `auth.create_user(db, username, password, role, workspace_id=None)`: None
  means "Default organization", created if missing. Only the CLI and tests
  rely on it.
- Run the existing suite, on SQLite and on PostgreSQL. The CLI is unchanged.
- Commits are made as Vinit Rami, with no co-author lines.

## Files

- Create:
  - `src/phishhawk/server/scope.py` (workspace-scoped getters and listings);
  - `src/phishhawk/server/migrations/versions/0004_workspaces.py`;
  - `tests/server/test_workspaces.py` (isolation, generated from the route
    table, and the upgrade).
- Modify:
  - `models.py`, `auth.py`, `deps.py`;
  - `views.py`, `routes/api.py`, `routes/pages.py`;
  - `appsettings.py`, `intake.py`, `batches.py`, `processing.py`;
  - `campaigns.py`, `retention.py`, `mailbox.py`, `mailboxes.py`;
  - `audit.py`, `worker.py`, `rotation.py`, `cli.py`;
  - `tests/server/conftest.py` and the tests that build rows directly;
  - `docs/SERVER.md`, `docs/api/openapi.json`, `CHANGELOG.md`.

### Task 1: Workspace table, columns and migration 0004

- [ ] Write the failing test `test_upgrade_puts_everything_in_default_organization`.
  - Build a 0003 database with a user, a message, a submission, an analysis,
    a mailbox, a setting and two audit records.
  - Upgrade to head.
  - Assert:
    - one workspace, "Default organization", of kind organization;
    - every row has its ID;
    - the first admin has `owner = true`;
    - `audit.verify()` is empty;
    - two messages with the same sha256 in two workspaces can both exist.
- [ ] Add `test_downgrade_refuses_with_two_workspaces`.
- [ ] Add the model:
  - `Workspace(id, name, kind, created_at)`;
  - `workspace_id` on users, messages, submissions, analyses, batches,
    campaigns, campaign_members, mailboxes and audit_log (nullable there);
  - `owner` on users;
  - `Setting` keyed by `(workspace_id, key)`;
  - `UniqueConstraint(workspace_id, sha256)` and `(workspace_id, name)`.
- [ ] Write migration 0004:
  - create the table and insert the default row;
  - add the columns, backfill them and make them not null (batch mode for
    SQLite);
  - swap the unique constraints;
  - rebuild `settings` with workspace 0 for `secret:trait_key` and the server
    limits, and the default workspace for the rest;
  - set owner on the first admin.
- [ ] Run `tests/server/test_migrations.py` and the new tests on SQLite and
  Postgres. Commit.

### Task 2: The actor knows its workspace

- [ ] Write failing tests:
  - `Actor.workspace_id` is set from a session and from a token;
  - `create_user` without a workspace uses Default organization;
  - `GET /api/v1/session` has `workspace: {id, name, kind}` and `owner`.
- [ ] Implement:
  - `Actor.workspace_id` and `Actor.owner`;
  - `find_session` and `find_token` fill them;
  - `create_user(..., workspace_id=None)`;
  - `default_workspace(db)`;
  - the session view.
- [ ] Tests pass. Commit.

### Task 3: Scoped reads for analyses, submissions, batches, messages and campaigns

- [ ] Write failing isolation tests.
  - Workspaces A and B each submit a message, through `intake.accept(...,
    workspace_id=)`.
  - As B, every `GET` of A's analysis, file, submission, batch, batch file,
    raw message and campaign is 404.
  - B's `/analyses` never lists A's.
  - A search for A's indicator finds nothing.
  - As B, every `POST`, `DELETE` and hold of A's message is 404.
- [ ] Create `scope.py` with `analysis(db, actor, id)`, `submission`, `batch`,
  `message`, `campaign`, `mailbox`, `user`, `token`. Each one returns the row
  or raises 404.
- [ ] Give `views.listing`, `usernames` and `mailbox_names` a `workspace_id`
  argument.
- [ ] Use them in `routes/api.py`.
- [ ] Make `intake.accept` and `batches.accept` take `workspace_id` (required)
  and dedup per workspace.
- [ ] Tests pass. Commit.

### Task 4: Settings per workspace, server limits under workspace 0

- [ ] Write failing tests:
  - A's provider keys and domain lists are not B's;
  - `analysis_options` for a submission uses its workspace's;
  - `trait_key` is one for the server;
  - `max_upload_mb` and `max_batch_messages` can only be changed by the owner
    (403 for another admin), and apply to everyone;
  - `retention_days` and `campaign_window_days` are per workspace.
- [ ] `appsettings` functions take `workspace_id`. `SERVER_LIMITS` are kept
  under 0. `public_view` shows both, and marks which ones only the owner can
  change.
- [ ] Tests pass. Commit.

### Task 5: Worker, campaigns, retention and rotation per workspace

- [ ] Write failing tests:
  - a campaign rebuild for A never touches B's campaigns;
  - a campaign never mixes workspaces;
  - the retention sweep uses each workspace's days;
  - key rotation reseals every workspace's secrets.
- [ ] Implement:
  - the `campaign_rebuild` payload carries `workspace_id`, and
    `queue_rebuild(db, ws)`;
  - `rebuild(db, ws, days)`;
  - `sweep` loops over the workspaces;
  - `processing` reads the options of the submission's workspace;
  - `rotation` covers every settings row.
- [ ] Tests pass. Commit.

### Task 6: Mailboxes, users and tokens scoped

- [ ] Write failing tests:
  - B's admin cannot see, change, poll or delete A's mailbox (404);
  - A mailbox's imports land in its workspace;
  - The users and tokens lists show only the workspace's members;
  - B's admin cannot change A's user, or make a token for them.
- [ ] Implement the scoped getters in the routes, `mailboxes.create(...,
  workspace_id)` and the import in `mailbox.py`.
- [ ] Tests pass. Commit.

### Task 7: Audit records per workspace

- [ ] Write failing tests:
  - a record has the actor's workspace;
  - the digest covers it when it is not NULL, and old records verify;
  - B's admin's `/audit` shows none of A's;
  - the default organization's admin also sees the pre-upgrade (NULL)
    records;
  - an analyst still sees only their own.
- [ ] Implement `audit.record(..., workspace_id=)` (required keyword; 0 for
  server events) and pass it from every caller.
- [ ] Tests pass. Commit.

### Task 8: Built-in pages scoped

- [ ] Write failing tests: the same isolation as task 3 and task 6, through
  `/queue`, `/analyses/{id}`, `/batches/{id}`, `/campaigns/{id}`,
  `/mailboxes`, `/users` and `/settings`.
- [ ] Use `scope.py` in `routes/pages.py`.
- [ ] Tests pass. Commit.

### Task 9: The route table guard

- [ ] Write `test_every_route_with_an_id_is_scoped`. It walks
  `app.routes`; for each path with `{..._id}` it calls it, with every method,
  as B with A's ID and expects 404, or 405 or 422 where the method does not
  exist.
  - A new route added without scoping fails it.
- [ ] It passes. Commit.

### Task 10: Docs, OpenAPI, the whole suite on both databases

- [ ] Update:
  - `docs/SERVER.md`: a Workspaces section and the upgrade note;
  - `docs/api/openapi.json`: regenerate it;
  - `CHANGELOG.md`.
- [ ] Run `check.sh`, Postgres with several workers, CodeQL and gitleaks.
- [ ] Push, open the PR, merge it when CI is green.
