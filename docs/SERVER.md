# PhishHawk web app

The web app puts PhishHawk's engine behind a browser and an API for a small SOC
team on one machine you control. An analyst uploads or pastes a reported
message, or a batch of them, sees the verdict and the full HTML report,
downloads all six export formats, and sees which messages belong to the same
campaign. An admin can connect the report mailbox itself, read-only, so every
message reported to it is analysed as it arrives. Every action is recorded in a
hash-chained audit log.

This is v3 after milestone 3: single messages, batches, campaigns and mailbox
import (see the [design](superpowers/specs/2026-10-06-phishhawk-v3-web-design.md)).

- [Start it with Docker Compose](#start-it-with-docker-compose)
- [Start it without Docker](#start-it-without-docker)
- [Settings](#settings)
- [Users, roles and API tokens](#users-roles-and-api-tokens)
- [Reputation lookups](#reputation-lookups)
- [Batches](#batches)
- [Campaigns](#campaigns)
- [Mailboxes](#mailboxes)
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

Open <http://127.0.0.1:8000> and log in: it opens the web app at `/app/`. The
built-in pages, the backup and admin interface, stay at `/login`, `/queue` and
the rest. Compose publishes the port on this machine only. To reach it from other machines, put a reverse proxy with TLS
(Caddy or nginx) in front of it; do not publish port 8000 on a network.

## HTTPS through a reverse proxy

On this machine, Caddy gets a certificate, sends plain HTTP to HTTPS and passes
the rest on, with this `Caddyfile`:

```
phishhawk.example.org {
    reverse_proxy 127.0.0.1:8000
}
```

The server believes a proxy's `X-Forwarded-Proto` and `X-Forwarded-For` only
from the addresses in `PHISHHAWK_TRUSTED_PROXIES`. Compose trusts this machine
and Docker's networks (`127.0.0.1,172.16.0.0/12`), where a proxy on this
machine or in another container comes from. With that:

- pages reached over HTTPS carry `Strict-Transport-Security`, so the browser
  uses HTTPS from then on;
- the login throttle slows down each person's own address, not the proxy's
  (which would slow down everyone);
- a browser that reaches the server over plain HTTP by any name other than
  `localhost` or `127.0.0.1`, without a proxy, is redirected to HTTPS (the
  health check at `/healthz` is not).

Every answer carries `X-Robots-Tag: noindex, nofollow` and `/robots.txt`
disallows everything, so a server reachable from the internet stays out of
search engines. The frontend's files are sent compressed; its hashed files in
`/app/assets/` are cached for a year and its page is checked on every load.

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
| `PHISHHAWK_DATABASE_URL` | SQLite in the data folder | `postgresql://user@host:5432/phishhawk` for Postgres (the `postgres` extra, in the Docker image already), where several workers can share the queue. |
| `PHISHHAWK_HOST`, `PHISHHAWK_PORT` | `127.0.0.1`, `8000` | Where the web app listens. |
| `PHISHHAWK_TLS_CERT`, `PHISHHAWK_TLS_KEY` | empty | Serve HTTPS directly. |
| `PHISHHAWK_RETENTION_DAYS` | `30` | Days before a message's sensitive data is deleted (see below). |
| `PHISHHAWK_MAX_UPLOAD_MB` | `25` | Largest message accepted. A whole upload (several files, an .mbox or a .zip) may be four times this, and so may its messages together. |
| `PHISHHAWK_MAX_BATCH_MESSAGES` | `500` | Most messages in one batch. |
| `PHISHHAWK_CAMPAIGN_WINDOW_DAYS` | `90` | Campaigns are found among the messages first seen in this many days. |
| `PHISHHAWK_SESSION_IDLE_MINUTES` | `480` | A session not used for this long ends. |
| `PHISHHAWK_ANALYSIS_MEMORY_MB`, `PHISHHAWK_ANALYSIS_CPU_SECONDS` | `2048`, `120` | Limits for the process that analyses one message. A message that exceeds them fails; the server does not. |
| `PHISHHAWK_COOKIE_SECURE` | `true` | See above. |
| `PHISHHAWK_TRUSTED_PROXIES` | `127.0.0.1` (Compose: `127.0.0.1,172.16.0.0/12`) | Addresses or networks, comma-separated, of reverse proxies whose `X-Forwarded-*` headers count. See "HTTPS through a reverse proxy". |
| `PHISHHAWK_FRONTEND_DIR` | empty (the image: its built-in `frontend/`) | A frontend build, served at `/app/`, which the server's address then opens; see [FRONTEND.md](FRONTEND.md). |

An admin can change the retention period, the upload and batch limits and the
campaign window on the Settings page; the value set there wins over the
variable.

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

## Batches

Several files, an .mbox or a .zip (of .eml, .msg or .mbox files) become one
batch: each message in it is a submission of its own, analysed and stored as
if it had been uploaded alone, in the order uploaded. An .mbox is split exactly
as the CLI reads it. Inside a .zip, other files and archives are skipped, and
no name from it is ever used, as a path or otherwise; an archive that would
inflate past the limits is refused before it does.

The batch page shows each message's progress and verdict. When the last one is
done, the batch gets combined reports: every format for all its messages
together, as one run of the CLI over them would write. They are tier 1 (below).

Uploads stay in memory: a request body larger than the limit is refused before
it is read, and nothing of a message is written to a temporary file.

## Campaigns

After each analysis, PhishHawk groups the messages first seen in the campaign
window by what they share, exactly as `phishhawk campaign` does: an
attachment, a phishing domain or link, a sender, a QR payload, or two weaker
traits together (a subject and a display name, say). It works from the
summary kept for each message (tier 2), so a campaign outlives its messages'
content. A campaign is named after its oldest message.

The campaign page shows what links its messages in clear, except the subject
and the sender's display name: tier 2 keeps those only as keyed hashes, so the
page shows them while one of the campaign's messages still has its tier 1, and
"same subject" afterwards. Recipient addresses are listed while the messages'
tier 1 exists; after that, only how many there were.

## Mailboxes

An admin connects a report mailbox under Mailboxes: over IMAP, through
Microsoft Graph (Microsoft 365) or through the Gmail API (Google Workspace).
PhishHawk reads it and changes nothing: it never marks a message read, moves
or deletes one, and asks only for read access (IMAP: EXAMINE and BODY.PEEK;
Graph and Gmail: GET requests, after one request for a token).

The worker polls each mailbox every few minutes (5 or more; 5 by default).
The first poll imports the newest 50 messages and remembers where it stopped;
each later poll imports what has arrived since. Older mail is not imported on
its own: upload it as an .mbox if you want it. Each new message becomes a
submission (source `mailbox`, submitted by the mailbox) and is analysed as an
upload is, with the reputation lookups you turned on.

No message is imported twice: one already stored (uploaded, pasted, or from
another mailbox) or with a Message-ID a mailbox has already imported is
counted as a duplicate and skipped. A message larger than the upload limit is
skipped and counted. Each mailbox shows its status, when it was last polled
and what that poll imported, skipped as a duplicate or skipped for good;
"Poll now" polls it at once.

When a poll fails (a refused sign-in, an unknown folder, a certificate that
does not verify, a provider that throttles) the mailbox shows `error` and the
reason in PhishHawk's own words, never the credential, and the failure is
recorded in the audit log. Polling backs off: 10, 20, 40 minutes, then once an
hour, until a poll works again or you enter a new credential.

Credentials are stored encrypted like API keys, bound to their mailbox, and
never shown again; leave the field empty when you change a mailbox to keep
the one it has. Changing where a mailbox is (its host, user, folder or label,
tenant or address) makes the next poll start again, without importing twice.
Deleting a mailbox keeps the messages it imported.

The worker connects only to the mailbox hosts you enter and, for Graph and
Gmail, to `login.microsoftonline.com` and `graph.microsoft.com`, or
`oauth2.googleapis.com` and `gmail.googleapis.com`.

### IMAP

Host, port (993 with TLS, or 143 with STARTTLS), user, password and folder
(INBOX by default). PhishHawk never connects without TLS, and always verifies
the server's certificate. Use an app password where the provider offers one;
for a personal Gmail account (2-Step Verification on), the host is
`imap.gmail.com` and the password an app password.

### Microsoft 365 (Graph)

1. In the Microsoft Entra admin center, under App registrations, register an
   application (single tenant). Note its application (client) ID and the
   directory (tenant) ID.
2. Under API permissions, add Microsoft Graph's **Mail.Read** as an
   *application* permission (not delegated), and grant admin consent. Nothing
   else is needed.
3. Under Certificates & secrets, add a client secret and copy its value.
4. Restrict the application to the report mailbox, so it cannot read anyone
   else's: in Exchange Online, with RBAC for Applications, or with an
   application access policy:
   ```powershell
   New-ApplicationAccessPolicy -AppId <client ID> -PolicyScopeGroupId <a mail-enabled security group holding the report mailbox> -AccessRight RestrictAccess -Description "PhishHawk: report mailbox only"
   Test-ApplicationAccessPolicy -Identity phish@example.com -AppId <client ID>
   ```
5. In PhishHawk: the tenant ID (or its domain, such as
   `contoso.onmicrosoft.com`), the client ID, the report mailbox's address,
   the folder (the Inbox by default; a folder you made, at the top level or in
   the Inbox, by its name) and the client secret.

PhishHawk asks for a token for each poll with the client-credentials flow and
reads the folder through a delta query. When the secret expires, the mailbox
shows "sign-in refused (invalid_client)": add a new secret and enter it.

### Gmail (Google Workspace)

1. In the Google Cloud console, in a project of your organisation, enable the
   Gmail API, create a service account, and create a JSON key for it.
2. In the Google Admin console, under Security, Access and data control, API
   controls, Domain-wide delegation, add the service account's client ID with
   one scope only: `https://www.googleapis.com/auth/gmail.readonly`.
3. In PhishHawk: the report mailbox's address, the label (INBOX by default; a
   label you made, by its name) and the JSON key's contents. Only the service
   account's address and private key are kept, encrypted; you can delete the
   file afterwards.

PhishHawk signs a token request for `gmail.readonly` as the report mailbox for
each poll, and follows the mailbox's history from there. "sign-in refused
(unauthorized_client)" usually means the delegation is missing or has another
scope.

## What is stored, and for how long

Each message has two tiers.

- **Sensitive (tier 1)**: the raw message, the full JSON report, the six
  exports and the analysis kept for a batch's combined reports. Encrypted with
  AES-256-GCM under the encryption key, each file bound to its own ID. Deleted
  after the retention period by an hourly job. A batch's combined reports are
  tier 1 too: deleted after the retention period, or as soon as any message in
  them is deleted.
- **Summary (tier 2)**: SHA-256, size, verdict, score, report ID, sender and
  sender domain, recipient count, indicators and ATT&CK techniques. Kept until
  someone deletes it. The subject and the sender's display name are kept only
  as keyed hashes, for matching campaigns later; they cannot be read back.

Recipient addresses, the subject in clear, body text and attachment names
never reach tier 2.

For each mailbox, PhishHawk keeps what it has seen there, so nothing is
imported twice: the provider's ID for each message and its Message-ID as a
keyed hash, never its content.

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

It re-encrypts every stored file, API key and mailbox credential under the new
key and records the rotation in the audit log. Then set `PHISHHAWK_ENCRYPTION_KEY` to the new key
and start the server. If it stops halfway, run it again with the same two keys:
what has already moved is skipped. If something opens under neither key, it
stops and deletes nothing.

With Compose: `docker compose stop`, then
`docker compose run --rm -e PHISHHAWK_NEW_ENCRYPTION_KEY phishhawk rotate-key`,
then replace `secrets/phishhawk_encryption_key` and `docker compose up -d`.

## The audit log

Logins (and failed ones), submissions, analyses, downloads, re-analyses,
deletions, holds, settings changes, user and token changes, mailbox changes
and failed polls, key rotation and each retention run are recorded with who
did it and when (a mailbox's imports are submitted by `mailbox:<its name>`). Each record holds the
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
  at a time, so extra workers (`phishhawk server worker`) mostly wait; on
  Postgres they share the queue, each job claimed by one of them.
- **A batch shows a message as failed**: that message could not be analysed
  (the reason is shown); the rest of the batch and its combined reports go on
  without it.
- **A mailbox shows an error**: the reason says what failed. Fix it (a new
  password or secret, the folder's name, the delegation), then "Poll now".
  "the stored credential cannot be opened" means the encryption key changed
  without `rotate-key`: enter the credential again.

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
