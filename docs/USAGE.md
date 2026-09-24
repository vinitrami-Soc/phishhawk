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

  scan         triage .eml files, folders or stdin (the default command)
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
| `reported/` | Every file ending in `.eml` under that folder, searched recursively and in name order |
| `-` | One message read from stdin |

Several inputs can be mixed: `phishhawk scan a.eml b.eml reported/`. One
unreadable or malformed file does not stop a batch; it is reported on stderr,
the rest are analysed and the exit code becomes `3`.

When a message was **reported as an attachment** (the user forwarded the phish
as an attached `.eml`, which is what most "Report phishing" buttons do),
PhishHawk analyses the attached original, up to three layers deep, and names
the reporter. When it was forwarded **inline**, the original sender is
recovered from the quoted `From:` block.

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
| `--html PATH` | Self-contained HTML report, light and dark themes; prints to A4 with page numbers | An index first, then one section per message, each starting on a new printed page |
| `--stix PATH` | STIX 2.1 bundle: an indicator per IOC, the ATT&CK attack patterns and a report object per message | One bundle, duplicate indicators merged |
| `--md PATH` | Markdown ticket note | Notes separated by `---` |
| `--csv PATH` | One row per indicator: `type, value, defanged, context, verdict, subject, source_file` | All rows in one file |

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

## doctor: check your setup

```text
phishhawk doctor [--network]
```

Checks the Python version, the `requests` library, each API key (shown masked),
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
phishhawk techniques           # the 18 techniques and what PhishHawk looks for
phishhawk techniques --json    # the same, machine-readable
```

## Environment variables

| Variable | Meaning |
|---|---|
| `VT_API_KEY` | VirusTotal key. `VIRUSTOTAL_API_KEY` is also read. |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key |
| `URLSCAN_API_KEY` | urlscan.io key, only needed for `--urlscan-submit` |
| `PHISHHAWK_PROTECT` | Comma-separated domains to treat as your own, e.g. `example.com,example.co.uk` |
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

In a batch, the exit code reflects the worst message.

## stdout, stderr and piping

- **stdout** carries the report, or the one machine-readable export sent to `-`.
- **stderr** carries the banner, progress, `[i]` notices and `[!]` errors.
- The banner only appears when stderr is an interactive terminal. It is never
  shown with `--quiet` or when a report goes to stdout.
- Colour is only used on a terminal, so redirecting to a file gives plain text.

So `phishhawk scan mail.eml --json - | jq .` always receives clean JSON.

## The JSON report

For one message, `--json` writes a single object; for several, `{"reports": [...]}`.
In `jq`, `(.reports // [.])[]` handles both shapes. The main fields:

| Field | Contents |
|---|---|
| `verdict`, `score` | The verdict and the risk score |
| `summary` | The plain-language summary lines, e.g. `"6 URLs found."` |
| `signals[]` | `severity`, `label` and `techniques` for every finding |
| `techniques[]` | `id`, `name`, ATT&CK `url` and the `evidence` behind it |
| `iocs[]` | `type` (url, domain, ipv4, email, sha256 …), `value`, `context`. Only indicators worth blocking. |
| `recommendations[]` | The actions to take, in order |
| `subject`, `date`, `message_id`, `to` | Message metadata |
| `from_display`, `from_address`, `from_domain`, `reply_to`, `return_path`, `originating_ip`, `auth` | Sender and SPF/DKIM/DMARC details |
| `reported_by`, `forwarded_from` | Set when the message was reported as an attachment or forwarded inline |
| `urls[]` | Every URL with its sources, anchor texts, notes, unwrap/redirect details, and `vt` and `urlscan` results |
| `attachments[]` | Name, declared and true type, size, MD5/SHA-1/SHA-256, archive listing, HTML-attachment findings, `vt` result |
| `lookalikes[]` | `domain`, the `target` it imitates, the `method` (homoglyph, typosquat, combosquat, tld-swap …) and `where` it appeared |
| `domain_intel`, `ip_intel` | RDAP domain ages and AbuseIPDB results |
| `errors[]` | Anything that could not be parsed or looked up |
| `generated_at`, `tool_version` | Provenance |

Message bodies are never included.

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

**Check your own legitimate mail for false positives before a roll-out:**

```bash
python eval/run_eval.py --benign ~/exported-legit-mail/
```
