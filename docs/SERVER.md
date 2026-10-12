# PhishHawk web app

The web app puts PhishHawk's engine behind a browser and an API for a small SOC
team on one machine you control. An analyst uploads or pastes a reported
message, sees the verdict and the full HTML report, and downloads all six
export formats. Every action is recorded in a hash-chained audit log.

This is milestone 1 of v3: one message at a time. Batch upload, campaigns and
mailbox import come in later milestones (see the
[design](superpowers/specs/2026-10-06-phishhawk-v3-web-design.md)).

- [Start it with Docker Compose](#start-it-with-docker-compose)
- [Start it without Docker](#start-it-without-docker)
- [Settings](#settings)
- [Users, roles and API tokens](#users-roles-and-api-tokens)
- [Reputation lookups](#reputation-lookups)
- [What is stored, and for how long](#what-is-stored-and-for-how-long)
- [Backups](#backups)
- [Changing the keys](#changing-the-keys)
- [The audit log](#the-audit-log)
- [Upgrades](#upgrades)
- [Health and troubleshooting](#health-and-troubleshooting)
- [Commands](#commands)

## Start it with Docker Compose

```bash
git clone https://github.com/vinitrami-Soc/phishhawk.git && cd phishhawk
mkdir -m 700 secrets
openssl rand -base64 32 > secrets/phishhawk_secret_key
openssl rand -base64 32 > secrets/phishhawk_encryption_key
chmod 644 secrets/*        # the container's user reads them; the folder keeps others out
docker compose up -d --wait
docker compose exec phishhawk phishhawk server create-admin admin
```

Open <http://127.0.0.1:8000> and log in. Compose publishes the port on this
machine only. To reach it from other machines, put a reverse proxy with TLS
(Caddy or nginx) in front of it; do not publish port 8000 on a network.

**Keep a copy of `secrets/phishhawk_encryption_key` somewhere safe.** Every
stored message and report is encrypted with it. Without it, nothing in a backup
can be read, by you or anyone else.

The container runs as an unprivileged user with a read-only file system, no
Linux capabilities and `no-new-privileges`. Its only writable places are the
`phishhawk-data` volume (`/data`) and a `/tmp` in memory.

## Start it without Docker

```bash
pip install "phishhawk[server]"
export PHISHHAWK_DATA_DIR=/var/lib/phishhawk
export PHISHHAWK_SECRET_KEY="$(openssl rand -base64 32)"
export PHISHHAWK_ENCRYPTION_KEY="$(openssl rand -base64 32)"   # keep a copy
phishhawk server create-admin admin
phishhawk server run
```

`run` brings the database up to date, then starts the web app and one worker.
Stop it with Ctrl+C or SIGTERM. The worker finishes the message in hand if it
can within 30 seconds; otherwise it is stopped and that message is analysed
again after the next start.

Session cookies are marked `Secure`. Browsers accept them on
`http://127.0.0.1` and `http://localhost`, and over HTTPS. Set
`PHISHHAWK_COOKIE_SECURE=false` only to test over plain HTTP with a client
that is not a browser.

For TLS without a proxy, set `PHISHHAWK_TLS_CERT` and `PHISHHAWK_TLS_KEY`.

## Settings

From the environment, or from files in `/run/secrets` named like the variable
in lower case (Docker secrets). A variable wins over a file.

| Variable | Default | What it does |
|---|---|---|
| `PHISHHAWK_SECRET_KEY` | none, required | Keys the session cookies. A new value logs everyone out; nothing else changes. |
| `PHISHHAWK_ENCRYPTION_KEY` | none, required | 32 bytes in base64. Encrypts every stored message, report and API key. The server refuses to start without a valid one. |
| `PHISHHAWK_DATA_DIR` | `/var/lib/phishhawk` | The database (SQLite) and the encrypted files. |
| `PHISHHAWK_DATABASE_URL` | SQLite in the data folder | Milestone 1 is built and tested on SQLite only; Postgres support, for several workers, comes with milestone 2. |
| `PHISHHAWK_HOST`, `PHISHHAWK_PORT` | `127.0.0.1`, `8000` | Where the web app listens. |
| `PHISHHAWK_TLS_CERT`, `PHISHHAWK_TLS_KEY` | empty | Serve HTTPS directly. |
| `PHISHHAWK_RETENTION_DAYS` | `30` | Days before a message's sensitive data is deleted (see below). |
| `PHISHHAWK_MAX_UPLOAD_MB` | `25` | Largest message accepted. |
| `PHISHHAWK_SESSION_IDLE_MINUTES` | `480` | A session not used for this long ends. |
| `PHISHHAWK_ANALYSIS_MEMORY_MB`, `PHISHHAWK_ANALYSIS_CPU_SECONDS` | `2048`, `120` | Limits for the process that analyses one message. A message that exceeds them fails; the server does not. |
| `PHISHHAWK_COOKIE_SECURE` | `true` | See above. |
| `PHISHHAWK_FRONTEND_DIR` | empty | The build of your own frontend, served at `/app/`; see [FRONTEND.md](FRONTEND.md). |

An admin can change the retention period and the upload limit on the Settings
page; the value set there wins over the variable.

## Users, roles and API tokens

There are two roles.

- **Analyst**: submits messages, sees every analysis, downloads reports and
  exports, re-analyses, deletes the sensitive data of messages they submitted,
  and downloads the raw message of those messages. Sees their own entries in
  the audit log.
- **Admin**: everything an analyst can, for every message, plus users, API
  tokens, settings, hold and release, deleting a message completely, and the
  whole audit log.

Passwords need at least 12 characters and are stored as argon2id hashes.
After three wrong passwords for a user or from an address, each further try
waits twice as long as the last, up to five minutes.

An admin creates API tokens on the Users page, for a user and with one scope:
`read` (look up analyses and download exports) or `submit` (also submit
messages). A token is shown once. Send it as `Authorization: Bearer phk_...`.
Admin actions, raw message downloads and deletions need a logged-in session;
a token cannot do them, whoever it belongs to.

The API is described in [docs/api/openapi.json](api/openapi.json). To build
your own frontend on it (for example in Google AI Studio) and serve it from
this server at `/app/`, see [FRONTEND.md](FRONTEND.md).

## Reputation lookups

A new installation makes no outbound lookups. An admin turns providers on
under Settings (VirusTotal, urlscan.io, RDAP and AbuseIPDB) and enters the API
keys, which are stored encrypted and shown afterwards only as their last four
characters. With providers on, an analyst can still tick "offline" for a
message. Every analysis records which providers were asked and each request
made, without the keys.

## What is stored, and for how long

Each message has two tiers.

- **Sensitive (tier 1)**: the raw message, the full JSON report and the six
  exports. Encrypted with AES-256-GCM under the encryption key, each file bound
  to its own ID. Deleted after the retention period by an hourly job.
- **Summary (tier 2)**: SHA-256, size, verdict, score, report ID, sender and
  sender domain, recipient count, indicators and ATT&CK techniques. Kept until
  someone deletes it. The subject and the sender's display name are kept only
  as keyed hashes, for matching campaigns later; they cannot be read back.

Recipient addresses, the subject in clear, body text and attachment names
never reach tier 2.

On a message's page:

- **Delete now** removes its tier 1 at once (an analyst for their own
  submissions, an admin for any).
- **Hold** (admin) keeps its tier 1 past the retention period, for an
  investigation, until released. A message on hold cannot be deleted, by
  anyone, until an admin releases it.
- **Delete completely** (admin) removes both tiers. The audit log keeps the
  message's SHA-256 and who deleted it.

The same message submitted twice is one message with two submissions.

## Backups

Back up the data folder (or the `phishhawk-data` volume) and, with Postgres,
the database, at the same moment. Keep the encryption key separately: a backup
without it cannot be read, by design.

## Changing the keys

`PHISHHAWK_SECRET_KEY` can be changed at any time; everyone has to log in
again.

To change the encryption key, stop the server, then:

```bash
PHISHHAWK_NEW_ENCRYPTION_KEY="$(openssl rand -base64 32)"   # keep a copy
export PHISHHAWK_NEW_ENCRYPTION_KEY
phishhawk server rotate-key
```

It re-encrypts every stored file and API key under the new key and records the
rotation in the audit log. Then set `PHISHHAWK_ENCRYPTION_KEY` to the new key
and start the server. If it stops halfway, run it again with the same two keys:
what has already moved is skipped. If something opens under neither key, it
stops and deletes nothing.

With Compose: `docker compose stop`, then
`docker compose run --rm -e PHISHHAWK_NEW_ENCRYPTION_KEY phishhawk rotate-key`,
then replace `secrets/phishhawk_encryption_key` and `docker compose up -d`.

## The audit log

Logins (and failed ones), submissions, analyses, downloads, re-analyses,
deletions, holds, settings changes, user and token changes, key rotation and
each retention run are recorded with who did it and when. Each record holds the
hash of the one before it, so an edited, removed, reordered or cut-off record
is detected:

```bash
phishhawk server audit verify      # exit code 0 when intact, 1 otherwise
docker compose exec phishhawk phishhawk server audit verify
```

## Upgrades

```bash
git pull && docker compose up -d --build --wait
```

`run` applies database migrations on start. Without Docker:
`pip install -U "phishhawk[server]"`, then restart; `phishhawk server migrate`
does the same step on its own.

## Health and troubleshooting

`GET /healthz` needs no login and answers with the version, the number of
queued jobs, the last worker heartbeat and the free disk space. The Docker
image's health check uses it.

- **"missing or not valid: PHISHHAWK_..."** at start: the named variables are
  not set or not valid. Values are never printed.
- **A submission stays queued**: the worker is not running. `phishhawk server
  run` starts one; check its output.
- **"this message exceeded the analysis limits"**: the message needed more
  memory or CPU time than allowed. Raise the limits if the message is genuine.
- **More than one worker**: `run` already starts one. SQLite takes one writer
  at a time, so extra workers (`phishhawk server worker`) mostly wait; Postgres
  support comes with milestone 2.

## Commands

```text
phishhawk server run            bring the database up to date, then start the web app and one worker
phishhawk server worker         run a worker without the web app
phishhawk server migrate        create the database or bring it up to date
phishhawk server create-admin   create an admin user (--password-stdin to read it from standard input)
phishhawk server rotate-key     re-encrypt everything under PHISHHAWK_NEW_ENCRYPTION_KEY
phishhawk server audit verify   check the audit log's hash chain
```

Exit codes: 0 done, 1 the audit log failed verification, 2 a usage error,
3 a setting or input problem (the message says which).
