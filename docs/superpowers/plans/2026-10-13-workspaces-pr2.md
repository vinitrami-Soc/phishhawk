# Setup, sign-up, invites and profile (PR 2 of the sign-up work) implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** People get into PhishHawk without an admin typing their password: the
owner sets the server up with a one-time code, anyone can create an Individual
or Organization account while the owner allows it, and an organization admin
invites the team with one-use links. Everyone edits their own profile.

**Architecture:**
- Account rules live in a new `accounts.py`: profile validation, setup, sign-up,
  invites and joining. The routes live in a new `routes/accounts.py`, so
  `routes/api.py` does not grow.
- Migration 0005 adds the profile fields to `users` and an `invites` table.
  Invite tokens are stored only as SHA-256 hashes.
- Server-wide values (sign-up open, the daily cap, the setup code) are settings
  of workspace 0, like the upload limits.
- The per-address sign-up limit is in memory, like the login throttle. The
  daily cap counts workspaces made in the last 24 hours, so it holds across
  processes.

**Tech stack:** FastAPI, SQLAlchemy 2, Alembic, Jinja2, pytest.

## Global constraints

- Spec: `docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md`,
  sections 5, 10 and 11.
- Setup: 403 with a wrong code, 404 once anyone has an account. The code works
  once.
- Sign-up is off after an upgrade. While it is off, `POST /api/v1/signup` is
  404 and no page links to it.
- Sign-up: 3 per address per hour, and a daily cap for the server (default
  100). Both answer 429 with `Retry-After`.
- Fields: username (the existing rules), password (12 or more), first and last
  name (required), location (required), organization (required for an
  Organization), job title (optional). Each is 80 characters at most, with no
  control characters. A 422 names the field.
- Invites: organization admins only, one use, 7 days, stored as a hash,
  revocable. An invite of another workspace is 404.
- Profile: the owner of the account changes their names, location and job
  title. An organization admin also renames the organization. A new password
  needs the current one and ends the account's other sessions.
- The owner alone reads and changes the server settings: sign-up, the daily
  cap and the upload limits.
- Everything is audited. Setup and sign-up are server events (workspace 0).
- Commits are made as Vinit Rami, with no co-author lines.

## Files

- Create:
  - `src/phishhawk/server/accounts.py`;
  - `src/phishhawk/server/routes/accounts.py`;
  - `src/phishhawk/server/migrations/versions/0005_accounts.py`;
  - `src/phishhawk/server/templates/setup.html`, `signup.html`, `join.html`,
    `profile.html`;
  - `tests/server/test_accounts.py`.
- Modify:
  - `models.py` (profile columns, `Invite`), `auth.py` (`SignupThrottle`);
  - `app.py` (the router, the throttle), `cli.py` (`setup-code`, the code in
    the log at start);
  - `routes/api.py` (the session view adds `profile`), `routes/pages.py`
    (setup, sign-up, join, profile and invites on Users);
  - `templates/login.html`, `templates/users.html`;
  - `docs/SERVER.md`, `docs/FRONTEND.md`, `docs/api/openapi.json`,
    `CHANGELOG.md`.

### Task 1: Migration 0005 and the model

- [ ] Write the failing test: upgrading a 0004 database with a user keeps the
  user and gives them empty profile fields; `invites` exists; downgrade
  removes both.
- [ ] Add `User.first_name`, `last_name`, `location`, `job_title` (String 80,
  default "") and `Invite(id, workspace_id, token_hash unique, role, note,
  created_by, created_at, expires_at, used_at, used_by, revoked_at)`.
- [ ] Write 0005. Run the migration tests on SQLite and Postgres. Commit.

### Task 2: Setup with a one-time code

- [ ] Write failing tests:
  - `accounts.setup_code(db, box)` makes a code while there are no users and
    returns the same one again; None once a user exists;
  - `GET /api/v1/setup` says whether setup is open;
  - `POST /api/v1/setup` with a wrong code is 403 (and throttled), with the
    right one it makes the owner in the default organization (renamed),
    stores the sign-up choice, opens a session, deletes the code, audits
    `setup` under workspace 0;
  - after that, `POST /api/v1/setup` is 404;
  - `phishhawk server setup-code` prints the code, or says setup is done (exit
    1); `run` prints it to the log at start.
- [ ] Implement. Tests pass. Commit.

### Task 3: Sign-up

- [ ] Write failing tests:
  - closed: `GET /api/v1/signup` says `open: false`, `POST` is 404, the login
    page has no "Create account";
  - open: an Individual sign-up makes a workspace named "First Last" of kind
    individual and an admin who is not the owner, signs them in, and they see
    none of the default organization's data;
  - an Organization sign-up needs the organization and names the workspace
    after it;
  - each missing or bad field is a 422 that names it; a taken username is 409;
  - the fourth sign-up from one address in an hour is 429; the daily cap is
    429 once that many workspaces were made in 24 hours.
- [ ] Implement `SignupThrottle`, `accounts.sign_up`, the routes. Commit.

### Task 4: Invites and joining

- [ ] Write failing tests:
  - an organization admin makes an invite (role, note) and gets the link once;
    the list shows it pending without the token; analysts and individuals
    cannot invite;
  - `GET /api/v1/join/{token}` names the organization and role;
    `POST` makes the member with that role in that workspace and signs them
    in; the invite then fails (404), as do an expired and a revoked one;
  - another workspace's admin cannot list or revoke it (404).
- [ ] Implement. Commit.

### Task 5: Profile and the owner's server settings

- [ ] Write failing tests:
  - `GET /api/v1/me` and `PATCH /api/v1/me` change names, location and job
    title; an organization admin renames the organization, an analyst cannot;
  - a new password needs the right current password, ends the other sessions
    and keeps this one;
  - `GET/PATCH /api/v1/server-settings` is the owner's alone (403 for another
    admin): sign-up open, the daily cap, the upload limits;
  - `GET /api/v1/session` adds `profile`.
- [ ] Implement. Commit.

### Task 6: Built-in pages

- [ ] Write failing tests: `/setup`, `/signup`, `/join/{token}` and `/profile`
  work without JavaScript; Users lists and makes invites; the login page links
  to sign-up only while it is open.
- [ ] Implement the templates and page routes. Commit.

### Task 7: Docs, OpenAPI, the suite on both databases

- [ ] `docs/SERVER.md` (Setup, Sign-up and invites, Profile),
  `docs/FRONTEND.md` (the new endpoints), `docs/api/openapi.json`,
  `CHANGELOG.md`.
- [ ] `check.sh` on SQLite, the server suite on Postgres, the browser tests.
- [ ] Push, open the PR, merge it when CI is green.
