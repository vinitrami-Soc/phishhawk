# Workspaces, sign-up, onboarding and feedback: design

Status: approved in conversation on 2026-10-13. Builds on the v3 web app (M1 to
M3) and the product page.

## 1. What the user asked for, and the decisions

- **Create an account** from the web app, with two kinds:
  - **Individual**: someone who only wants to check their own mail. No
    approval, no one else involved.
  - **Organization**: a team. The person who creates it is its admin and
    invites the others.
- The sign-up form asks for: username, password, first name, last name,
  location, organization and job title.
- **After sign-up, a short setup** (each step can be skipped):
  - invite the team;
  - connect a report mailbox;
  - reputation providers;
  - a short tour.
- **Feedback, both kinds:**
  - a Feedback form anywhere in the app (bug, idea, question, other);
  - on every analysis, "Was this verdict right?"
- Decisions confirmed by the user:
  - Reputation provider keys (VirusTotal, urlscan.io, AbuseIPDB) belong to each
    workspace.
  - There is no email verification, because PhishHawk sends no email.
    Sign-ups are limited per address instead.

Today everyone who can sign in sees every analysis. Open sign-up is only safe
if every account's data is kept apart, so the core of this work is
**workspaces**.

## 2. Concepts

- **Workspace.** Holds everything an organization or an individual works with:
  - messages, submissions, analyses, batches and campaigns;
  - mailboxes, API tokens and settings;
  - its part of the audit log.

  A workspace has a `kind`, which is `organization` or `individual`, a name,
  and the time it was created. It never sees another workspace's data.
- **Member.** Every user belongs to exactly one workspace, with a role in it:
  `admin` or `analyst`, as today.
  - An individual workspace has one member, who is its admin.
  - An organization workspace has any number of members.
- **Server owner.** The person who runs the PhishHawk server: `users.owner =
  true`. There is one owner, created at setup. The owner is also the admin of
  their own organization workspace.

  The owner alone can:
  - turn sign-up on or off;
  - set the server-wide limits;
  - read the general feedback.

  The owner does not see other workspaces' analyses.

## 3. Keeping data apart

- **New column.** These tables gain `workspace_id`, not null, with a foreign
  key and an index:
  - messages, submissions, analyses, batches;
  - campaigns, campaign_members;
  - mailboxes, users;
  - settings (see below), feedback, verdict_feedback, invites.

  These tables get theirs through a parent: indicators through analyses,
  mailbox_items through mailboxes, sessions and api_tokens through users.
- **Uniqueness becomes per workspace:**
  - `messages.sha256` becomes `(workspace_id, sha256)`. The same email
    reported in two workspaces is two messages, each with its own encrypted
    copy, retention and hold.
  - `mailboxes.name` becomes `(workspace_id, name)`.
  - Campaign IDs stay "the ID of the oldest message". Message IDs are global,
    so these stay unique.
- **Scoped getters.** Every query goes through scoped getters in a new
  `scope.py`: `scoped(db, actor)`, `get_analysis(db, actor, id)` and so on.
  - Each one filters by `actor.workspace_id`.
  - An object from another workspace is **404, never 403**, so its existence
    does not leak.
  - A test lists every route and calls it as a member of another workspace.
- **Settings.** The `settings` table becomes `(workspace_id, key)`.
  - Per-workspace settings: provider choices and keys, domain lists, retention
    days.
  - Server-wide settings use `workspace_id = 0`: whether sign-up is open, the
    trait key, and the server limits.
- **Campaigns.** Campaigns are rebuilt per workspace. The job payload carries
  the workspace.
- **Worker.** Jobs run as before. Each job finds its workspace through its
  submission or batch, and uses that workspace's provider keys and lists.
- **Audit log.**
  - It stays one hash chain for the whole server. The tamper evidence covers
    everything.
  - Records gain `workspace_id`:
    - NULL for records written before this change (they belong to the
      default organization);
    - 0 for server-wide events (sign-up, setup, owner settings);
    - otherwise the workspace's ID.
  - The hash covers `workspace_id` whenever it is not NULL, so old records
    still verify.
  - Admins see their workspace's records. The default organization also sees
    the NULL ones. The owner can verify the whole chain (CLI, and an owner-only
    API).

## 4. Upgrading an existing server (migration 0004)

- **Default workspace.** It creates one organization workspace, "Default
  organization", and gives it every existing row.
- **Owner.** The first admin by ID becomes the owner.
- **Sign-up.** Sign-up stays **off** after an upgrade, so an existing server
  does not open itself. The owner turns it on in Settings. A new installation
  asks during setup.
- **Downgrade.** It removes the workspace columns only if the server has one
  workspace. Otherwise it refuses with a clear message.

## 5. Setup, sign-up, invites, profile

- **First run.** When there are no users, the server prints a one-time
  **setup code** to its log at start. `phishhawk server setup-code` prints it
  too.
  - `/app/setup` asks for the code and the owner's account and profile. It
    creates the owner, their organization workspace, and the sign-up choice
    (on or off).
  - The code works once, and setup then closes.
  - `phishhawk server create-admin` keeps working for scripted installs.
- **Sign-up** (`/app/signup`, linked as "Create account" from the product page
  and the sign-in page, only while sign-up is on).
  - Step 1 chooses **Individual** or **Organization**.
  - Step 2 asks for:
    - username (the existing rules);
    - password (at least 12 characters);
    - first name, last name;
    - location (free text, up to 80 characters);
    - organization (required for Organization, optional for Individual);
    - job title (optional).
  - It creates the workspace (named after the organization, or "first last" for
    an individual), the user as its admin, and a session.
  - Limits:
    - **3 sign-ups per address per hour**;
    - a server-wide **daily sign-up cap** (default 100, set by the owner);
    - "username taken" is shown, behind the same throttle.
- **Invites** (organization admins only, on the Users page).
  - An invite has a role and an optional note ("for Priya, SOC team").
  - It gives a link `/app/join/<token>`: one use, valid 7 days, and stored only
    as a hash.
  - The admin copies it and sends it however they like.
  - `/app/join/<token>` asks for the same fields except organization, then
    signs the person in.
  - Admins see pending invites and can revoke them.
  - The existing "Add user" stays for admins who prefer to set a password
    themselves.
- **Profile** (`/app/profile`). Anyone can change:
  - first and last name, location, job title;
  - their organization's name (organization admins only);
  - their own password, after entering the current one. This ends their other
    sessions, as today.

## 6. Setup after sign-up (onboarding)

`users.onboarded_at` is null until the person finishes or skips the setup. The
console opens the setup once, after the first sign-in.

| Who | Steps |
|---|---|
| Organization admin | 1. Invite your team (rows of note and role, then copy the links). 2. Connect a report mailbox (opens the existing form). 3. Reputation providers (the existing settings, per workspace). 4. Tour. |
| Individual | 1. Reputation providers (optional; offline is fine). 2. Tour. A mailbox can be connected later from More. |
| Invited member | Tour only. |

The tour is five cards: Triage, Queue, an analysis, Campaigns and Audit. Each
has one sentence and a "Show me" link. Every step has "Skip", and the wizard
has "Skip setup".

## 7. Feedback

- **General feedback.**
  - A "Feedback" item in More and in the console footer opens a dialog:
    - kind: bug, idea, question or other;
    - message: up to 4,000 characters;
    - the page it was sent from, filled in by the app.
  - It is stored as `feedback (workspace_id, user_id, kind, message, page,
    created_at, status)`.
  - The owner reads all feedback on a **Feedback** page and marks it done.
  - Each person sees what they sent.
- **Verdict feedback.**
  - On every analysis: "Was this verdict right?" with three answers:
    - Right;
    - It was phishing (missed);
    - It was not phishing (false alarm).

    There is also an optional note of up to 1,000 characters.
  - One answer per person per analysis; they can change it.
  - It is stored as `verdict_feedback (workspace_id, analysis_id, user_id,
    opinion, note, created_at, updated_at)`.
  - The Queue gains a filter, "Disputed" (any missed or false-alarm answer).
  - Workspace admins see a summary on the Feedback page (counts, and the
    disputed analyses).
  - The owner can download every workspace's disputed verdicts as CSV, without
    the messages, to improve the engine.
- **Audit.** Both kinds are audited. Feedback is kept until the person who sent
  it, a workspace admin (verdict feedback) or the owner deletes it.

## 8. Limits and abuse

- **Per workspace.** A daily cap on submitted messages: default 500 for an
  organization and 100 for an individual, set by the owner. When it is reached
  the answer is 429 with when it resets.
- **Fair worker.** Jobs are picked oldest first across workspaces, at most N
  running per workspace (default 2), so one busy workspace cannot starve the
  others.
- **Unchanged.** The 1 MB rule for anonymous bodies, the login throttle,
  same-site checks and every upload limit stay as they are.

## 9. Privacy

- **Personal data.** Profile fields and feedback are personal data. The
  Privacy page says what they are, why they are kept, and that they go when
  the account is deleted.
- **Account deletion.**
  - An admin can delete a member.
  - The owner can delete a workspace, which deletes everything in it,
    including its blobs.
  - An individual can delete their own account and workspace.
- **Who sees profiles.** Profile fields are shown only inside the workspace.
  The owner sees a workspace list with names, kinds and member counts, not
  members' profiles.

## 10. API (additions; existing shapes stay, only scoped)

- `GET /api/v1/session` adds `workspace {id, name, kind}`, `owner`,
  `onboarded`, and `profile {first_name, last_name, location, organization,
  job_title}`.
- Setup:
  - `GET /api/v1/setup` returns whether setup is open;
  - `POST /api/v1/setup` takes the code, the account and the sign-up choice.
- Sign-up:
  - `GET /api/v1/signup` returns whether it is open;
  - `POST /api/v1/signup` takes the kind and the fields.
- Invites:
  - `GET/POST /api/v1/invites` and `DELETE /api/v1/invites/{id}` (admin);
  - `GET /api/v1/join/{token}` (is it valid, and for which organization);
  - `POST /api/v1/join/{token}`.
- Profile and onboarding:
  - `GET/PATCH /api/v1/me` (profile and password);
  - `POST /api/v1/me/onboarded`.
- Feedback:
  - `POST /api/v1/feedback`;
  - `GET /api/v1/feedback` (the owner gets all; anyone else their own);
  - `PATCH /api/v1/feedback/{id}` (owner);
  - `DELETE /api/v1/feedback/{id}`.
- Verdict feedback:
  - `PUT /api/v1/analyses/{id}/feedback` and `DELETE` (own);
  - `GET /api/v1/analyses/{id}/feedback`;
  - `GET /api/v1/feedback/verdicts` (admin: summary; owner: CSV with
    `?format=csv`).
- Owner:
  - `GET /api/v1/workspaces` and `DELETE /api/v1/workspaces/{id}`;
  - `GET/PATCH /api/v1/server-settings` (sign-up, caps, limits).
- `docs/api/openapi.json` is regenerated and the frontend types follow it.

## 11. Testing

- **Isolation.** Two workspaces, A and B. For every API route and every
  built-in page, a member of B gets 404 for A's objects. A's lists never show
  B's rows, and the Queue search never finds B's indicators. This is generated
  from the route table, so a new route without scoping fails.
- **Migration.** Fill a 0003 database, upgrade, and check that every row is in
  "Default organization", that the old audit chain verifies, and that the first
  admin is the owner. The downgrade refuses when there are two workspaces.
- **Setup.** The code works once. Without it setup is 403, and after it 404.
- **Sign-up.**
  - Both kinds work.
  - The per-address throttle and the daily cap hold.
  - A closed sign-up returns 404 and no link is shown.
  - Validation errors name the field.
- **Invites.** An invite works once and expires after 7 days; a revoked one
  fails. It brings the role it was made with. Individuals cannot invite.
- **Feedback.**
  - Who can send, read, change and delete each kind.
  - The Disputed filter.
  - The CSV holds no message content.
- **Limits.** The daily cap returns 429. The worker never runs more than N jobs
  for one workspace while another waits.
- **Browser tests.** The product page leads to Create account (Individual),
  then setup, then the first analysis. An organization sign-up leads to an
  invite link, which joins in a second browser, and the new member sees the
  organization's analyses but not the individual's. Both run at all widths.
- **Security review round 6.** At the end, the review attacks the new
  surfaces: IDOR across workspaces, invite and setup tokens, sign-up abuse,
  and feedback injection.

## 12. Delivery, as pull requests (each TDD, CI green, merged)

1. **Workspaces in the data.**
   - Migration 0004, `scope.py`, and every query scoped.
   - The audit `workspace_id`, per-workspace settings and provider keys.
   - The isolation test suite.
   - No new screens: an upgraded server behaves as before.
2. **Setup, sign-up, invites and profile.** The server and API, the built-in
   pages, the per-address throttle, the daily cap and the owner's server
   settings.
3. **Frontend for 2.** Setup, Create account (both kinds), Join, Profile,
   invites on Users, owner settings, and the mock preview.
4. **Onboarding.** Server flag plus the wizard and the tour.
5. **Feedback.** Both kinds: API, pages, Queue filter and CSV.
6. **Limits and fairness.** Per-workspace daily cap and a fair worker.
7. **Security review round 6, and docs.** Docs, Privacy, CHANGELOG and the
   Gemini txt.
