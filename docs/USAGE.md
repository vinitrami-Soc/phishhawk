# PhishHawk usage guide

Everything PhishHawk's command line can do, with worked examples. For
installation, see the [README](../README.md#installation).

- [Commands](#commands)
- [scan: triage messages](#scan-triage-messages)
  - [Inputs](#inputs)
  - [Display options](#display-options)
  - [Reports](#reports)
  - [Detection options](#detection-options)
  - [Enrichment options](#enrichment-options)
  - [Cache options](#cache-options)
- [imap: triage a mailbox folder](#imap-triage-a-mailbox-folder)
- [graph and gmail: triage a mailbox through its API](#graph-and-gmail-triage-a-mailbox-through-its-api)
- [Evidence and sandbox packs](#evidence-and-sandbox-packs)
- [campaign: group reports into campaigns](#campaign-group-reports-into-campaigns)
- [sweep: find the other copies of a reported message](#sweep-find-the-other-copies-of-a-reported-message)
- [The config file](#the-config-file)
- [YARA rules](#yara-rules)
- [doctor: check your setup](#doctor-check-your-setup)
- [cache: manage the lookup cache](#cache-manage-the-lookup-cache)
- [techniques: the ATT&CK catalogue](#techniques-the-attck-catalogue)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [stdout, stderr and piping](#stdout-stderr-and-piping)
- [The JSON report](#the-json-report)
- [Recipes](#recipes)

## Commands

```text
phishhawk [-h] [-V] <command> ...

  scan         triage .eml, .msg or .mbox files, folders or stdin (the default command)
  imap         triage messages straight from an IMAP folder, read-only
  graph        triage messages from a Microsoft 365 mailbox through Microsoft Graph, read-only
  gmail        triage messages from a Gmail or Google Workspace mailbox through the Gmail API, read-only
  campaign     group reported messages into campaigns by what they share, offline
  sweep        find the other copies of a reported message in mailboxes, read-only
  evidence     verify the messages and custody log kept with --evidence
  doctor       check dependencies, API keys, cache and network
  cache        show or clear the lookup cache
  techniques   list the MITRE ATT&CK techniques PhishHawk can evidence
  help         show help for a command
```

`scan` is the default, so `phishhawk mail.eml` and `phishhawk scan mail.eml`
are the same. `phishhawk help <command>` and `phishhawk <command> -h` print the
full help for one command. `phishhawk -V` prints the version.

## scan: triage messages

```text
phishhawk scan [options] PATH [PATH ...]
```

### Inputs

| Input | Meaning |
|---|---|
| `mail.eml` | One message |
| `Invoice overdue.msg` | An Outlook message, as saved from Outlook or reported with its "Report phishing" button. It is rebuilt as the email that was sent, with its original transport headers when Outlook kept them |
| `Inbox.mbox` | Every message in an mbox export (Google Takeout, Thunderbird), labelled `Inbox.mbox#1`, `#2`, ... |
| `reported/` | Every regular file ending in `.eml`, `.msg` or `.mbox` under that folder, searched recursively and in name order |
| `-` | One message read from stdin |

Several inputs can be mixed: `phishhawk scan a.eml b.eml reported/`. One
unreadable or malformed file does not stop a batch; it is reported on stderr,
the rest are analysed and the exit code becomes `3`. Only regular files are
read, so a named pipe or a link to a device in a scanned folder is skipped
instead of hanging the batch, and so is any message over `--max-size`.

To measure PhishHawk on your own mail without sending anything anywhere, point
the evaluation script at an export: `python eval/run_eval.py --benign Inbox.mbox`
prints totals only (how many messages were flagged), never a subject or a sender.

When a message was **reported as an attachment** (the user forwarded the phish
as an attached `.eml`, which is what most "Report phishing" buttons do),
PhishHawk analyses the attached original, up to three layers deep, and names
the reporter. When it was forwarded **inline**, the original sender is
recovered from the quoted `From:` block.

Every layer that was unwrapped is analysed as well. A phish that carries a
harmless attached message, so that the attachment gets analysed instead, keeps
its own findings: they are listed as `carrier email: ...`.

### Display options

| Option | Meaning |
|---|---|
| *(none)* | Full colour report per message: headers, key findings, indicators, ATT&CK techniques, recommended actions |
| `-q`, `--quiet` | One short summary block per message, then a batch table. No banner. |
| `-v`, `--verbose` | Every signal, including low ones, MD5 hashes and all recommended actions |
| `--no-color` | No ANSI colours (also `NO_COLOR=1`, or `TERM=dumb`) |
| `--no-banner` | No start-up banner (also `PHISHHAWK_NO_BANNER=1`) |

A batch of more than one message ends with a summary table:

```text
-- BATCH SUMMARY (4 messages) --------------------------------------------
  file                                   verdict               score  urls files
  samples/sample_bec_smuggling.eml       LIKELY PHISHING          32     2     5
  samples/sample_benign.eml              NO STRONG INDICATORS      0     1     0
  samples/sample_phish.eml               LIKELY PHISHING          36     6     1
  samples/sample_reported.eml            LIKELY PHISHING          36     6     1
```

### Reports

Each report flag takes a file path. All except `--html` also accept `-` for
stdout; only one report can go to stdout at a time.

| Option | Output | Several messages |
|---|---|---|
| `--json PATH` | The full structured analysis ([format below](#the-json-report)) | `{"reports": [ ... ]}` |
| `--html PATH` | Self-contained HTML report; follows the system's light or dark mode, with an Auto / Light / Dark switch; prints to A4 with page numbers | An index first, then one section per message, each starting on a new printed page |
| `--stix PATH` | STIX 2.1 bundle: an indicator per IOC, the ATT&CK attack patterns and a report object per message | One bundle, duplicate indicators merged |
| `--md PATH` | Markdown ticket note | Notes separated by `---` |
| `--csv PATH` | One row per indicator: `type, value, defanged, context, verdict, subject, source_file` | All rows in one file |
| `--misp PATH` | A MISP event: every indicator as an attribute (with `ip-src` for the sending IP, `btc`/`xmr` for wallets), an `email` object, the ATT&CK techniques as galaxy tags and a TLP tag (`--tlp`, default `amber`). Ready for *Add Event → Populate from JSON* or the `/events/add` API | A list of events |

The terminal, HTML and Markdown reports show indicators **defanged**
(`hxxps://evil[.]top`), so they cannot be clicked by accident. CSV has both a raw
`value` and a `defanged` column. JSON and STIX carry raw values, because machines
consume them. Well-known brand domains, your protected domains, shorteners and
free-mail providers are never exported as domain-level blocks.

### Detection options

| Option | Meaning |
|---|---|
| `-p DOMAIN`, `--protect DOMAIN` | Your organisation's domain. Repeat for several. Lookalikes of it (`examp1e.com`, `example-payments.com`, `example.co`) are flagged as impersonation, and it is never sent to reputation services. Also read from `PHISHHAWK_PROTECT`. |
| `--no-auto-protect` | By default the recipients' domains are protected too, because a lookalike of the recipient's own domain is the classic BEC pattern. This turns that off, for example when analysing mail sent to a shared or free-mail inbox. |
| `--no-unwrap` | Analyse the covering note from the reporter, not the attached original |
| `--trusted-authserv ID` | Your mail server's authserv-id, the first word of the `Authentication-Results` headers it writes (for example `mx.google.com`). Repeat for several; also read from `PHISHHAWK_TRUSTED_AUTHSERV`. Without it, only the block of headers at the top (the receiving server's) is believed, and a pass claimed further down is ignored and flagged as forged. |
| `--no-qr` | Do not decode QR codes. Decoding needs the optional extra, `pip install 'phishhawk[qr]'` (included by `install.sh` and the Docker image); `phishhawk doctor` shows whether it is available. |
| `--max-size MB` | Skip messages larger than this (default 50) |
| `--psl FILE` | A copy of the [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat), used instead of the built-in approximation to find each host's registrable domain. With it, a lookalike on shared hosting (`paypal-billing.github.io`) is judged as its own domain rather than as `github.io`. Also read from the config file (`public_suffix_list`) and `PHISHHAWK_PSL`. A file that cannot be read, or holds no rules, is an error. |
| `--allow DOMAIN` | A partner's domain: never reported as a lookalike, never exported as an indicator. Repeat for several. |
| `--block DOMAIN` | A domain your organisation has already judged hostile: a message that uses it as sender, Reply-To, Return-Path or link host raises a high signal. Repeat for several. |
| `--yara PATH` | Your [YARA rules](#yara-rules), a file or a folder of them |
| `--config PATH` | The [config file](#the-config-file) to use |
| `--fail-on LEVEL` | For pipelines: exit `0` unless a message reaches `suspicious`, `likely` (phishing) or `malicious`, then `1`. `never` always exits `0`. Errors still exit `3`. |

### Enrichment options

| Option | Default | Meaning |
|---|---|---|
| `-o`, `--offline` | off | No network access at all, and no cache |
| `--vt-key KEY` | `$VT_API_KEY` | VirusTotal API key (`$VIRUSTOTAL_API_KEY` is read too) |
| `--vt-rate N` | 4 | VirusTotal lookups per minute. 4 matches the free tier; raise it for a premium key. |
| `--vt-budget N` | 20 | Maximum VirusTotal network lookups per message. The most suspicious indicators go first; cached answers do not count. |
| `--no-virustotal` | | Skip VirusTotal |
| `--urlscan-key KEY` | `$URLSCAN_API_KEY` | urlscan.io key, only needed to submit |
| `--no-urlscan` | | Skip urlscan.io searches |
| `--urlscan-submit` | off | Submit each URL to urlscan.io as an **unlisted** scan. This sends the full URL, so it is never on by default. |
| `--abuseipdb-key KEY` | `$ABUSEIPDB_API_KEY` | AbuseIPDB key, for the reputation of the sending IP |
| `--no-abuseipdb` | | Skip AbuseIPDB |
| `--no-rdap` | | Skip RDAP domain-age lookups |
| `--timeout SECONDS` | 20 | HTTP timeout per request |

Prefer environment variables to `--*-key` flags: a key on the command line ends
up in your shell history and is visible to other users in `ps`.

### Cache options

| Option | Default | Meaning |
|---|---|---|
| `--no-cache` | | Neither read nor write the cache for this run |
| `--cache-ttl HOURS` | 24 | How long an answer stays fresh |
| `--cache-path PATH` | `$XDG_CACHE_HOME/phishhawk/lookups.sqlite3`, else `~/.cache/phishhawk/lookups.sqlite3` | The SQLite file |

Only definitive answers are cached: a result, or "not found". Errors, timeouts,
rejected keys and rate-limit responses are not, so they are retried on the next run.

## imap: triage a mailbox folder

```text
phishhawk imap --host HOST --user USER [--folder FOLDER] [options]
```

Reads messages straight from an IMAP folder, such as a shared "report
phishing" mailbox, and triages each one as `scan` would. The folder is opened
**read-only** (`EXAMINE`) and messages are fetched with `BODY.PEEK[]`, so
nothing is marked read, moved or deleted. TLS certificates are always verified.

| Option | Meaning |
|---|---|
| `--host HOST` | The IMAP server, e.g. `outlook.office365.com`, `imap.gmail.com` |
| `--user USER` | The login (or `$PHISHHAWK_IMAP_USER`) |
| `--folder FOLDER` | The folder to read (default `INBOX`) |
| `--port PORT`, `--starttls` | Port 993 with TLS by default; `--starttls` upgrades a plain connection on port 143 |
| `--since YYYY-MM-DD` | Only messages received on or after this date |
| `--unseen` | Only messages nobody has read yet |
| `--limit N` | The newest N messages (default 50) |
| `--out DIR` | Also write a JSON and an HTML report per message, named after its UID |
| `--watch SECONDS` | Keep running: every SECONDS, triage the messages that arrived since the last round. A connection that drops is reported and retried on the next round. |

Every `scan` option for reports, detection and enrichment works here too.

The password is never taken on the command line, where other users could read
it in the process list: set `PHISHHAWK_IMAP_PASSWORD`, or answer the prompt. For
Microsoft 365 and Gmail, which want OAuth, put an access token in
`PHISHHAWK_IMAP_TOKEN` and it is sent with `XOAUTH2`.

```bash
export PHISHHAWK_IMAP_PASSWORD='...'
phishhawk imap --host mail.example.com --user soc --folder "Phish reports" --unseen --out reports/
phishhawk imap --host mail.example.com --user soc --folder "Phish reports" --watch 300 --quiet
```

## graph and gmail: triage a mailbox through its API

```text
phishhawk graph [--mailbox USER] [--folder FOLDER] [options]
phishhawk gmail [--mailbox USER] [--label LABEL] [--query TERMS] [options]
```

Many Microsoft 365 and Google Workspace tenants no longer allow IMAP. These
two commands read the same "report phishing" mailbox through Microsoft Graph
or the Gmail API instead, and triage each message as `scan` would. They only
ever send `GET` requests: Graph's `$value` and Gmail's `format=raw` return a
message's MIME without touching it, so nothing is marked read, moved or deleted.

| Option | Meaning |
|---|---|
| `--mailbox USER` | A user id or address. The default, `me`, is the mailbox of the token's own account; another mailbox needs a token allowed to read it (an app permission, or delegated access). |
| `--folder FOLDER` (graph) | A folder name or id. The default is the Inbox. Well-known names (`inbox`, `junkemail`, `archive` …) work in every language; a folder you made is found by its display name at the top level or inside the Inbox. |
| `--label LABEL` (gmail) | A label. The default is the inbox. |
| `--query TERMS` (gmail) | More terms, as typed in Gmail's search box, e.g. `has:attachment` |
| `--since YYYY-MM-DD` | Only messages received on or after this date |
| `--unread` | Only messages nobody has read yet |
| `--limit N` | The newest N messages (default 50) |
| `--out DIR` | Also write a JSON and an HTML report per message, named after its message id (plus a short hash when the id has characters a file name cannot hold) |
| `--watch SECONDS` | Keep running: every SECONDS, triage the messages not seen yet. A message the API throttled, or that failed to download, is asked for again on the next round. |

Every `scan` option for reports, detection and enrichment works here too.

The access token is read from `PHISHHAWK_GRAPH_TOKEN` or `PHISHHAWK_GMAIL_TOKEN`,
never from the command line. It travels only in the `Authorization` header and
is only ever sent to the API's own host: a Graph `@odata.nextLink` pointing
anywhere else is not followed. It needs `Mail.Read` (Graph) or
`gmail.readonly` (Gmail); getting one is left to your identity platform. For a
quick test with Microsoft Graph, `az account get-access-token --resource-type
ms-graph` prints one. A refused token is reported with the permission it needs.
A message larger than `--max-size` is skipped, never cut short; Gmail's size
is checked before anything is downloaded.

```bash
export PHISHHAWK_GRAPH_TOKEN='...'
phishhawk graph --mailbox soc@example.com --folder "Phish reports" --unread --out reports/
phishhawk graph --mailbox soc@example.com --watch 300 --quiet

export PHISHHAWK_GMAIL_TOKEN='...'
phishhawk gmail --label "Phish reports" --since 2026-09-01
phishhawk gmail --query "has:attachment" --out reports/
```

## Evidence and sandbox packs

Every report names the exact bytes it analysed: their SHA-256 and
size (for a reported message, the report as it arrived, not the original
unwrapped from it). Two options of `scan`, `imap`, `graph` and `gmail` keep
more:

| Option | What it writes |
|---|---|
| `--evidence DIR` | Each message, exactly as read, as `DIR/<sha256>.eml` (or `.msg`), read-only; and one record per analysis appended to `DIR/custody.jsonl`: SHA-256, size, source (file, `mbox#n`, `imap://`, `graph://`, `gmail://`), time, analyst (`$PHISHHAWK_ANALYST`, else the login name), tool version, verdict and score. Each record includes the hash of the one before it; the record's own hash (`custody` in the report's `evidence` block) is shown in every report. A message seen again is kept once and recorded again. |
| `--sandbox DIR` | `DIR/<message sha256>.zip`, encrypted with the password `infected`: `message.eml` (`message.msg` for an Outlook message), every file pulled out of it as `files/<first 16 hex digits of its SHA-256>-<name>` (archive members too, so a payload behind a password PhishHawk guessed arrives unpacked), `urls.txt` (the links worth detonating: not defanged, not trusted brands) and `manifest.json` (each file's name, hashes, type, parent and notes; the message's SHA-256 and verdict). Up to 50 MB of files per pack; the rest is listed in the manifest. Nothing is sent anywhere: upload the pack to your sandbox. |

```bash
phishhawk scan reported/ --quiet --evidence /cases/4711 --sandbox /cases/4711/sandbox
phishhawk evidence verify /cases/4711
```

The sandbox pack is encrypted with ZipCrypto and the password `infected`,
the convention sandboxes and analysts expect. That keeps it from being opened
by accident or quarantined in transit; it is not confidentiality against a
determined reader. A pack is not a secure evidence vault: it holds the
message, so store it like evidence, and keep evidence with `--evidence`.

`phishhawk evidence verify DIR` recomputes the chain and every kept message's
hash, reports any record changed, removed or reordered and any message changed
or missing, and prints the chain's last link (`head`). The chain alone cannot
catch someone who rewrites the whole log, so put the head, or a report's
`custody` value, in the ticket, and check against it later:
`phishhawk evidence verify DIR --head VALUE` fails unless that value is still
in the log. Exit code `0` when everything checks out, `1` when something does
not.

## campaign: group reports into campaigns

```bash
phishhawk campaign reported/                        which reports belong together
phishhawk campaign reported/ --md campaigns.md      a ticket note per campaign
phishhawk campaign a.mbox b.mbox --json - | jq '.clusters[0].recipients'
```

Reads `.eml`, `.msg` and `.mbox` files and folders like `scan`, analyses each
message offline, and groups them. Two messages belong together when they share
one strong trait or two weak ones, and links are followed: A with B and B with
C make one campaign.

| Strong (one is enough) | Weak (two are needed) |
|---|---|
| an attachment (by SHA-256), a phishing domain, a link (without its query), a host on free hosting or a platform, a cloud-storage bucket, a QR payload, a sender or reply-to address, a sender domain, a crypto wallet, a phone number | a subject that differs only in numbers and `Re:`/`Fwd:` prefixes, a display name, an originating IP |

What would glue unrelated mail together never links: known brands and your
protected and allowed domains, shorteners, free-mail providers (one free-mail
address does link: it is one person), bulk-mail and click-tracking services
and mail-security gateways that rewrite links (only the very same link
counts), web plumbing such as fonts and XML namespaces, a mailing list's own
links, embedded images, and weak traits shared by more than 200 messages. A
domain under which the messages use many different host names is a platform
(Cloud Run, a registry zone such as `sa.com`, a help desk) and links by host;
the report lists the platforms it found. A web address (link, domain or host)
links only messages at least half of which PhishHawk judged suspicious or
worse, because ordinary sites turn up in ordinary mail. That rule still lets
phishing that links to a news or reference site join the legitimate mail
that links there too: on held-out data, 4 of 742 campaigns mixed
phishing with legitimate mail that way. Read a campaign's shared traits
before acting on all of it.

Each campaign shows what its messages share and how many share each trait
(web addresses of mostly clean mail are left out: they link nothing), its
recipients (from each message's To line, the original's for a reported
message), its senders, its first and last sighting (from the Date lines) and
its verdicts. Output: the terminal summary, `--json`, `--csv` (one row per
message with its campaign) and `--md` (a note per campaign), each `-` for
stdout. `--min-size N` sets the smallest group reported (default 2). The
detection options (`--protect`, `--allow`, `--psl`, `--config` ...) apply.

## sweep: find the other copies of a reported message

```bash
export PHISHHAWK_GRAPH_TOKEN='...'   # an application token with Mail.Read for every mailbox swept
phishhawk sweep graph --like reported.eml --mailboxes staff.txt
phishhawk sweep graph --from billing@1nvoice-desk.top --mailbox alice@example.com --mailbox bob@example.com
export PHISHHAWK_GMAIL_TOKEN='...'   # gmail.readonly, for the token's own mailbox
phishhawk sweep gmail --like reported.eml --since 2026-09-01 --csv copies.csv
```

| Option | Meaning |
|---|---|
| `--like FILE` | The reported `.eml` or `.msg`. Its Message-ID, sender and reply-to addresses, subject and phishing domains are searched for; a brand's own domain or address, free-mail providers and other shared services never are, and a platform's customer is searched by its host (`shop.myshopify.com`), never the whole platform. |
| `--from`, `--subject`, `--domain`, `--message-id` | Search for these too (each repeatable) |
| `--mailbox ADDRESS` | A mailbox to search (repeatable; default `me`, the token's own) |
| `--mailboxes FILE` | One mailbox per line; `#` starts a comment |
| `--since YYYY-MM-DD` | Only copies received on or after this date |
| `--limit N` | Results per search and mailbox (default 100, at most 1000) |
| `--json PATH`, `--csv PATH` | Every copy found, and which searches found it (`-` for stdout) |

Each copy is listed with its mailbox, received time, folder (Graph's folder
name; Gmail's Inbox, Spam, Trash or Archive), whether it was read, whether
the mailbox's owner replied (wrote to the copy's sender or reply-to address in
its thread: a forward to the SOC is not a reply), and what matched. Gmail
searches `in:anywhere`, spam and trash included; Graph searches every folder.
Every hit is checked against what was asked before it counts: the sender's
address, the subject, the Message-ID, and for Graph the domain in the body (or
a host under it; the body is read for that check and never kept). Gmail's
search for a domain is taken as it is, and such copies are marked "(Gmail's
search, not checked again)": look at them before purging.

Only GET requests are sent, the token is read from the environment and only
sent to the API's host, and a mailbox that is refused or not found is reported
without stopping the others. One search or lookup that fails (throttling, an
error) marks its mailbox incomplete and keeps what the others found; a copy
deleted while the sweep runs is skipped. A Gmail token belongs to one mailbox
(with domain-wide delegation, mint one per mailbox). Exit code `0` when no copy
was found, `1` when copies were, `3` when a mailbox could not be searched, or
only partly. Whether
anyone clicked a link or opened an attachment is not in the mailbox: search
your proxy and EDR logs for the domains and hashes in the scan report.

**What `sweep` sends, and to whom.** `sweep` is online by design, and it talks
only to the provider that already holds the mail, Microsoft Graph or the Gmail
API. It sends as search terms the reported message's sender and reply-to
addresses, its subject, its Message-ID and the phishing domains it links to
(or the values given with `--from`, `--subject`, `--domain` and
`--message-id`), for Gmail the `--since` date, and the mailbox names in the
request paths. To tell whether someone replied, it also lists each copy's own
thread, by the provider's conversation or thread id. Recipients' addresses are
never search terms. PhishHawk sends only GET requests, with the
token in the Authorization header and only to the API's host, but what a token
can do is set by its scope: give it a read-only one (`Mail.Read`,
`gmail.readonly`), and to sweep many Microsoft 365 mailboxes, limit an
application token to them with an application access policy (see
[INTEGRATIONS.md](INTEGRATIONS.md)).

## The config file

Settings a SOC sets once live in a TOML (Python 3.11+) or JSON file. It is read
from `--config`, else `$PHISHHAWK_CONFIG`, else
`~/.config/phishhawk/config.toml` (or `config.json`). It is **never** read from
the current folder, so a file dropped into a folder of reported mail cannot
allowlist an attacker's domain. Command-line options win over the file.

```toml
protect = ["example.com", "example.co.uk"]       # your domains (as --protect)
trusted_authserv = ["mx.example.com"]            # your mail servers (as --trusted-authserv)
allow_domains = ["partner-payroll.com"]          # partners: never lookalikes, never indicators
block_domains = ["known-bad.top"]                # always flagged
yara = "~/soc/rules/"                            # as --yara
fail_on = "likely"                               # as --fail-on
tlp = "amber"                                    # MISP events
offline = false
max_size = 50                                    # MB
public_suffix_list = "~/soc/public_suffix_list.dat"  # as --psl
vt_rate = 4                                      # VirusTotal lookups per minute
vt_budget = 20                                   # VirusTotal lookups per message

[brands]                                         # your own brands, for lookalike checks
examplebank = ["examplebank.com", "examplebank.co.uk"]

[lures]                                          # extra lure phrases, by category
credential = ["verify your examplebank card"]
```

An unknown setting, a domain with a space in it, or a lure shorter than four
letters is refused with a message that says which line is wrong.
`phishhawk doctor` shows which config file is in use.

## YARA rules

With `pip install 'phishhawk[yara]'`, `--yara PATH` runs your rules (a `.yar`
file, or a folder of `.yar` and `.yara` files) on the raw message and on every
file PhishHawk opens, including files inside archives, disk images and
documents. A match raises a signal; a rule's `meta` can set how:

```yara
rule Invoice_HTML_Smuggling
{
    meta:
        description = "HTML attachment that assembles a file in the browser"
        severity = "high"              // high (default), medium or low
        mitre = "T1027.006"            // ATT&CK techniques, comma-separated
    strings:
        $a = "createObjectURL" ascii
        $b = "atob(" ascii
    condition:
        all of them
}
```

Each buffer gets at most 10 seconds; a rule that times out counts as no match.

## doctor: check your setup

```text
phishhawk doctor [--network]
```

Checks the Python version, the `requests` library, QR decoding, YARA, the
config file in use, the Public Suffix List if one is set (loaded, so a broken
path shows up here rather than in the next scan), each API key (shown masked),
the protected domains and the cache. `--network` also calls each reputation
service once to show it can be reached from this machine, which is useful behind
a corporate proxy. Run it after installing and whenever enrichment seems not to work.

## cache: manage the lookup cache

```bash
phishhawk cache                      # same as `cache stats`: entries per provider, size, location
phishhawk cache clear                # remove everything
phishhawk cache clear --provider rdap   # only one provider: virustotal, urlscan, rdap or abuseipdb
phishhawk cache path                 # print the cache file's location
```

Clear a provider's entries when you want fresh verdicts, for example to
re-check a URL that VirusTotal did not know about yesterday.

## techniques: the ATT&CK catalogue

```bash
phishhawk techniques           # the 29 techniques and what PhishHawk looks for
phishhawk techniques --json    # the same, machine-readable
```

## Environment variables

| Variable | Meaning |
|---|---|
| `VT_API_KEY` | VirusTotal key. `VIRUSTOTAL_API_KEY` is also read. |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key |
| `URLSCAN_API_KEY` | urlscan.io key, only needed for `--urlscan-submit` |
| `PHISHHAWK_PROTECT` | Comma-separated domains to treat as your own, e.g. `example.com,example.co.uk` |
| `PHISHHAWK_TRUSTED_AUTHSERV` | Comma-separated authserv-ids of your own mail servers, e.g. `mx.google.com` |
| `PHISHHAWK_CONFIG` | The [config file](#the-config-file) to use |
| `PHISHHAWK_IMAP_USER` | The IMAP login for `phishhawk imap` |
| `PHISHHAWK_IMAP_PASSWORD` | The IMAP password (never pass it on the command line) |
| `PHISHHAWK_IMAP_TOKEN` | An OAuth access token for IMAP (`XOAUTH2`), instead of a password |
| `PHISHHAWK_GRAPH_TOKEN` | The access token for `phishhawk graph` (`Mail.Read`) |
| `PHISHHAWK_GMAIL_TOKEN` | The access token for `phishhawk gmail` (`gmail.readonly`) |
| `PHISHHAWK_PSL` | A copy of the Public Suffix List, as `--psl` |
| `PHISHHAWK_ANALYST` | The analyst named in `--evidence` custody records (default: the login name) |
| `PHISHHAWK_NO_BANNER` | Any value turns the banner off |
| `NO_COLOR` | Any value turns colour off ([no-color.org](https://no-color.org)) |
| `XDG_CACHE_HOME` | Where the cache folder goes (default `~/.cache`) |
| `PHISHHAWK_HOME`, `PHISHHAWK_BIN` | Used by `install.sh` only: where the virtualenv and the command are installed |

A good place for them is `~/.bashrc`, `~/.zshrc` or a file you `source`:

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export PHISHHAWK_PROTECT="example.com,example.co.uk"
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing notable in any message |
| `1` | At least one message is `SUSPICIOUS` or `LIKELY PHISHING` |
| `2` | At least one message is `MALICIOUS` (confirmed by VirusTotal) |
| `3` | An input could not be read or analysed, or a report could not be written. Takes priority over the verdicts. |
| `130` | Interrupted with Ctrl+C |
| `141` | Output pipe closed early (for example, piped into `head`); exits quietly |

In a batch, the exit code reflects the worst message. With `--fail-on LEVEL`
the verdict codes become `1` when a message reaches that level and `0`
otherwise; `3` still means an error.

`campaign` exits `0`, or `3` when an input could not be read. `sweep` exits
`0` when no copy was found, `1` when copies were and `3` when a mailbox could
not be searched, or only partly. `evidence verify` exits `0` when everything checks out and
`1` when it does not.

## stdout, stderr and piping

- **stdout** carries the report, or the one machine-readable export sent to `-`.
- **stderr** carries the banner, progress, `[i]` notices and `[!]` errors.
- The banner only appears when stderr is an interactive terminal. It is never
  shown with `--quiet` or when a report goes to stdout.
- Colour is only used on a terminal, so redirecting to a file gives plain text.

So `phishhawk scan mail.eml --json - | jq .` always receives clean JSON.

## The JSON report

For one message, `--json` writes a single object; for several, `{"reports": [...]}`.
In `jq`, `(.reports // [.])[]` handles both shapes. Every report carries
`report_version` (`"2.0"`), which changes only when a field is renamed or
removed; new fields can appear at any time. The full format is a JSON Schema,
[`docs/report.schema.json`](report.schema.json). The main fields:

| Field | Contents |
|---|---|
| `verdict`, `score` | The verdict and the risk score |
| `evidence` | Since 2.2: `sha256` and `size` of the bytes analysed; with `--evidence`, the kept `file` and the `custody` record's chain value |
| `authentication` | Since 2.2: `status` (`pass`, `fail` or `unknown`) for the From domain; `checks[]` with each of SPF, DKIM and DMARC's `result`, `domain` and whether it is `aligned` with From; `identities[]` (From, Reply-To, Return-Path, each with `same_organisation`); `explanation[]`, sentences for a ticket |
| `auth_checks[]` | Since 2.2: every SPF, DKIM and DMARC result in the receiving server's headers, with the `domain` it checked |
| `summary` | The plain-language summary lines, e.g. `"6 URLs found."` |
| `signals[]` | `severity`, `label`, `techniques` and, since 2.1, `family`: the part of the message the finding is about (`auth`, `sender`, `link`, `attachment`, `content`, `evasion`, `intel` or `policy`; empty for a finding added outside PhishHawk's checks) |
| `techniques[]` | `id`, `name`, ATT&CK `url` and the `evidence` behind it |
| `iocs[]` | `type` (url, domain, ipv4, ipv6, email, sha256, crypto-wallet, phone), `value`, `context`. Only indicators worth blocking. |
| `recommendations[]` | The actions to take, in order. They are for the analyst: PhishHawk itself never blocks, moves or deletes anything |
| `analysis_status` | Since 2.3: `status` (`complete` or `incomplete`) with the `reasons[]` a part of the message was not read or checked (links past the cap, archive members not opened, MIME nested too deep), and `reputation` (`checked`, `partially checked` or `not checked`) with `reputation_detail`. No answer from a reputation service is never reported as clean |
| `limitations[]` | Since 2.3: what this report cannot tell, for this message |
| `auth_header`, `auth_receiver`, `auth_pinned` | Since 2.3: where the SPF, DKIM and DMARC results were read (`Authentication-Results`, `Received-SPF` or empty), the authserv-id of the server that wrote them (empty when it names none, as Exchange Online does), and whether `--trusted-authserv` named it |
| `subject`, `date`, `message_id`, `to` | Message metadata |
| `from_display`, `from_address`, `from_domain`, `reply_to`, `return_path`, `originating_ip`, `auth` | Sender and SPF/DKIM/DMARC details |
| `forged_auth[]` | Pass results claimed below the receiving server's own: `claim`, `authserv`, and `impersonates` when the forged header uses the receiving server's name |
| `qr_codes[]` | Every QR code found: `where` it was (an image, a PDF, an embedded image, a drawn table or block characters), its `payload`, and the `url` it leads to |
| `reported_by`, `forwarded_from` | Set when the message was reported as an attachment or forwarded inline |
| `hops[]` | The mail path, oldest hop first: `from`, `by`, `with`, `ip`, `time` and `delay_seconds` |
| `calendar[]` | Meeting invitations: organiser, summary, links and attachments |
| `wallets[]`, `phones[]` | Crypto-wallet addresses (with their currency) and callback numbers |
| `yara[]` | YARA matches: `rule`, `where`, `severity` |
| `allowed_domains`, `blocked_domains` | Your lists, as applied to this message |
| `urls_dropped`, `mime_depth` | Links past the 1,000 kept, and the deepest MIME nesting |
| `urls[]` | Every URL with its sources, anchor texts, notes, unwrap/redirect details, and `vt` and `urlscan` results |
| `attachments[]` | Name, declared and true type, size, MD5/SHA-1/SHA-256, the `parent` it came out of, archive listing, HTML-attachment findings, per-format `details` (Office, PDF, RTF, shortcut, OneNote), `vt` result |
| `lookalikes[]` | `domain`, the `target` it imitates, the `method` (homoglyph, typosquat, combosquat, tld-swap …) and `where` it appeared |
| `domain_intel`, `ip_intel` | RDAP domain ages and AbuseIPDB results |
| `errors[]` | Anything that could not be parsed or looked up |
| `generated_at`, `tool_version` | Provenance |

Message bodies are never included. The only body text a report quotes is short evidence: up
to 80 characters of hidden filler text when that trick is found (`hidden_sample`).

## Recipes

**Only the verdict:**

```bash
phishhawk scan mail.eml --json - | jq -r .verdict
```

**Every URL, defanged, from a folder of reports:**

```bash
phishhawk scan reported/ --json - | jq -r '(.reports // [.])[].urls[].defanged' | sort -u
```

**A block list of the URLs and domains worth blocking:**

```bash
phishhawk scan reported/ --json - \
  | jq -r '(.reports // [.])[].iocs[] | select(.type=="url" or .type=="domain") | .value' | sort -u
```

**Only the malicious or likely-phishing messages from a batch:**

```bash
phishhawk scan reported/ --json - \
  | jq -r '(.reports // [.])[] | select(.verdict=="MALICIOUS" or .verdict=="LIKELY PHISHING") | .path'
```

**Watch a drop folder and triage each new report** (Linux, with `inotify-tools`):

```bash
inotifywait -m -e close_write --format '%w%f' /srv/reported/ | while read -r f; do
  [[ $f == *.eml ]] && phishhawk scan "$f" --quiet --html "${f%.eml}.html"
done
```

**Fast first pass, then enrich only what matters:**

```bash
phishhawk scan reported/ --offline --json - \
  | jq -r '(.reports // [.])[] | select(.verdict!="NO STRONG INDICATORS") | .path' \
  | xargs -r phishhawk scan --html flagged.html
```

**Fail a CI or SOAR step only on likely phishing, and hand the event to MISP:**

```bash
phishhawk scan reported/ --quiet --fail-on likely --misp events.json
```

**Check your own legitimate mail for false positives before a roll-out:**

```bash
python eval/run_eval.py --benign ~/exported-legit-mail/
```
