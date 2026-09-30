# Security review: PhishHawk attacked by its own author

PhishHawk reads hostile input for a living, so it was tested the way a
bug-bounty hunter would test it: as a target, not as a detector. It was tested
twice before 2.0.0: once against 1.2.0, and again after 2.0 added a dozen
file-format readers of its own. Every finding below was reproduced, fixed, and
turned into a test in [`tests/test_security.py`](../tests/test_security.py)
that fails on the old code.

## Threat model

| Attacker | Controls | Wants |
|---|---|---|
| Phishing sender | every byte of the email: headers, bodies, attachments, file names | a clean verdict, or to act on the analyst's machine |
| Someone who can drop files where a batch runs | file names and file types in a folder of reported mail | to stop or confuse the batch |
| Anyone who reads a report | nothing directly | to be tricked by what the report shows |

The analyst runs PhishHawk on a workstation, in a terminal, and pastes the
Markdown note into a ticketing system.

## Round 1: 1.2.0 attacked (fixed in 2.0.0)

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 1 | **Terminal escape injection.** Subject, display name, file names and file paths reached the terminal raw. `OSC 52` wrote to the analyst's clipboard, `OSC 8` turned text into a hidden link, `ESC[2J` cleared the screen. | A pasted "command" from the clipboard, a hidden link to the attacker, a report the analyst cannot trust | High | Every attacker string is made printable before display: control characters are shown escaped (`\x1b`), bidirectional overrides are named (`<U+202E>`) |
| 2 | **Unwrap evasion.** A phish with a harmless `.eml` attached was analysed as the attachment: the phish became "the reporter" and the verdict was *NO STRONG INDICATORS*. | Any phish passes | High | Every unwrapped layer is analysed as well; a suspicious carrier keeps its signals, links and lookalikes (`carrier email: ...`) |
| 3 | **Forged `Authentication-Results`.** All such headers were read, so when the receiving server's own header left out a check, a `dmarc=pass` written by the sender further down was believed. A forged `Received-SPF: pass` filled a missing SPF result. | Authentication failures hidden | Medium | Only the receiving server's block at the top is trusted (one header, or one per check under the same authserv-id, as ProtonMail writes them). A pass claimed below it is ignored and flagged; `--trusted-authserv` pins your own server |
| 4 | **A planted file hangs a batch.** A FIFO or a symlink to `/dev/zero` named `*.eml` blocked or exhausted memory forever; a 300 MB file took minutes. | SOC automation stalls | Medium | Only regular files are read, and messages over `--max-size` (50 MB) are skipped with a message |
| 5 | **Link flood.** A message with 50,000 links took 31 s (quadratic loops, and the brand checks repeated for every link). | Slow triage on hostile mail | Medium | Linear data structures and cached brand work: 3 s. In 2.0 a message keeps at most 1,000 links and is flagged past that (#19), so padding cannot hide a link |
| 6 | **Markdown ticket injection.** Attacker text in the note became live links, remote images (a beacon when the ticket is opened) and raw HTML; bare URLs were auto-linked by GitHub and GitLab. | Clickable phishing links inside the ticketing system | Medium | Markdown syntax is escaped, `<` and `>` encoded, bare URLs defanged, and code spans cannot be closed from inside |
| 7 | **Right-to-left override in file names.** `invoice‮fdp.exe` rendered as `invoiceexe.pdf` in the reports. | The analyst misreads the file type | Low | The override is shown as `<U+202E>`; the detection still sees the real name |
| 8 | **World-readable lookup cache.** `~/.cache/phishhawk/lookups.sqlite3` was `0644`. It lists every URL looked up, victims' addresses inside URLs included. | Other users of a shared analysis box read the SOC's investigations | Low | The cache is `0600` in a `0700` directory |
| 9 | **urlscan.io submissions carried recipient addresses** (plain, URL-encoded or base64), and unlisted scans are visible to other urlscan customers. | Victims' addresses published | Low (opt-in) | Your recipients' and protected domains' addresses are replaced with `user@example.com` before submission |
| 10 | **Lookalike evasions:** `paypal-com.top`, `www-paypal.com`, `paypalcom.top`, `micros-oft.com` were not found. | Missed lookalikes | Detection | Spelled-out domain words (`com`, `www`, `net`, `org`, ...) count as combosquat filler, and a name split by hyphens is compared joined |

## Round 2: the 2.0 readers attacked (fixed before release)

2.0 reads Outlook `.msg`, OLE2, RAR, 7z, ISO, FAT, shortcut, OneNote, RTF,
PDF, TNEF and calendar files itself, in pure Python. Each reader, and the
pipeline around them, was attacked by hand, by a mutation fuzzer (9.7 million
runs over four rounds, against every reader and the whole pipeline with every
report rendered, under a 2 GB memory limit), by a ReDoS scan, and by running
19,917 real messages through every report format.

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 11 | **A charset name crashes Python's email package.** A NUL or 8-bit byte in an RFC 2231 charset (`filename*=utf\x00-8''a.html`), or a charset such as `idna` or `undefined`, made CPython raise inside `message_from_bytes`, `get_filename`, `get_boundary` or `get_payload`. | The phish is reported as an error instead of being triaged | High | Every message is parsed with a tolerant policy: a header that will not parse is re-read without control characters, and a filename, boundary or body in a charset that will not decode is read as UTF-8. The hidden `invoice.html` is still found and flagged |
| 12 | **Evasion by structure.** Four shapes were never read: a whole message of type `message/rfc822`, an email attached below the three unwrapped layers, a second attached email behind a harmless first one, and a `multipart` part with no boundary (which mail clients show as text). | Any phish passes | High | All four are read. An attached email that is not unwrapped still has its links, invitations and files checked |
| 13 | **MIME nested a thousand levels deep** raised `RecursionError` in the parser. | The phish is reported as an error | High | The body is read as plain text, so its links still count, and the nesting itself is flagged. Nesting past 15 levels is a signal too: 19,458 real messages never went past 4 |
| 14 | **Disk images and `.msg` files read the same bytes hundreds of times.** 480 ISO directory records pointing at one 20 MB extent made the reader hold 9.6 GB (81 s); 150 `.msg` attachment streams sharing one 5 MB sector chain took 7.2 GB (137 s). | The analyst's machine runs out of memory | High | Reads count against a budget per file: 100 MB for a disk image, four times the file's size for a compound file. Past it, files are listed by name without their content |
| 15 | **Quadratic header parsing in CPython.** A `To:` header of 50,000 double quotes took 49 s, and the library parses a header again every time it is read (a part's `Content-Type` dozens of times). | One message stalls a batch or an IMAP run | Medium | Structured headers over 4 KB are kept as text (their parameters are still read, so a boundary behind 9 KB of junk is found), parsed headers are cached, and messages are re-serialised with their original headers |
| 16 | **Office parts inflating to 8 MB each.** A 12 MB `.docx` of such parts took 37 s. | Slow triage | Medium | Parts are read against 64 MB per document. (Recent Python versions also refuse zips whose entries overlap.) |
| 17 | **PDF stream search was quadratic.** 180 KB took 61 s; 527 KB, over five minutes. | Slow triage | Medium | A linear scanner replaced the regular expression |
| 18 | **Two regular expressions backtracked** from every position of a long run of letters: a 30,000-character `To:` header took 5 s, and a crafted `.rels` part 0.2 s per element. | Slow triage | Medium | Both are anchored |
| 19 | **Link floods, again.** 20,000 links took 14 s and made a 19 MB report: adding a signal checked every earlier signal. | Slow triage, unusable report | Medium | At most 1,000 links are kept and a flood past that is a signal, so padding cannot push the real link out of sight. Signals are de-duplicated in constant time, Received headers are read without parsing, and only `Authentication-Results` headers are decoded |
| 20 | **Report notes showed live links.** URLs inside QR payloads, shortcut command lines and remote templates reached the notes undefanged. | A clickable attacker link in a ticket | Medium | Notes are defanged where they are made, and a test renders every report and fails on any live attacker link |
| 21 | **QR decoding of PDF images was slow.** Every stream was decoded, and `/Filter/FlateDecode/DecodeParms<</Predictor 15>>` was read as five filters, so ordinary predictor images were undone a byte at a time in Python: one real phish took 2 s. | Slow triage | Low | Streams are capped and checked for `/Image` first, `/Filter` is parsed on its own so predictor images go through Pillow, and the Python fallback only takes small images |
| 22 | **A 7z header asking for a 4 GB dictionary** made the decoder try to allocate it. | A crash under a memory limit | Low | The dictionary is capped at the header's own size |
| 23 | **A link followed by 1.4 MB of NUL bytes** became one 1.4 MB URL that took seconds to show in each report; tabs and line breaks inside an `href` stayed in the URL, breaking IOC exports. | Slow reports, broken blocklist entries | Low | Links stop at control characters, are capped at 8,192 characters, and drop tabs and line breaks the way browsers do |
| 24 | **Reader errors escaped.** Truncated RAR, compound-file and FAT data raised `struct.error`; a deeply nested config file raised `RecursionError`. | An error instead of a verdict; a traceback | Low | Truncated data gives a partial listing or a `ValueError`; the config file gets a plain error message |
| 25 | **A shortcut's padding was lost.** Command lines hidden behind hundreds of spaces were stripped before the check that looks for them. | A missed signal | Low | The padding length is recorded first |
| 26 | **IMAP folder names with CR/LF** could end the `SELECT` command early. The folder comes from the analyst, not the mail. | Local only | Low | Control characters are refused before connecting |
| 27 | **Address headers full of colons.** `email.utils.parseaddr` recurses once per `:` (group syntax), so a `From:` or `To:` with a few thousand colons raised `RecursionError`. Found by the fuzzer. | The phish is reported as an error | High | Address headers with more than 100 colons are read with a plain address search; the sender is still recovered and checked |
| 28 | **A dropped IMAP connection** during `SELECT` or `SEARCH` raised `imaplib`'s abort out of the command, ending a `--watch` run. | Monitoring stops | Low | Reported as an error; `--watch` retries on the next round |
| 29 | **The address search in base64 bodies** retried up to 64 characters from every position: 1.7 s for one real 2 MB phish. | Slow triage | Low | Matches start only where a run of address characters starts: 0.3 s |

## Tested and found safe

| Attack | Result |
|---|---|
| Script injection in the HTML report (`<script>`, `onerror`) | Escaped; the report's Content-Security-Policy also blocks scripts and remote requests |
| Spreadsheet formula injection in the CSV (`=HYPERLINK(...)`) | Every cell starting with `= + - @` or a control character is neutralised |
| Regular-expression denial of service | All 117 patterns in the package (every literal, and every pattern built at import time) against 204 pathological strings of 60,000 characters each: worst 0.12 s, after the fixes above |
| Mutation fuzzing | 9.7 million runs in four rounds over every reader and the pipeline, every report rendered each time, 2 GB memory limit. Every finding of the first three rounds is fixed and replays in under 0.5 s; the last round, 3.6 million runs on the final code, found nothing. Hypothesis property tests of the same targets run in CI |
| Hostile charsets | 247 combinations of 19 hostile charset names and 13 header and body positions, through triage and every report: no errors |
| Real mail | 19,917 real messages through triage and all seven report formats, the JSON validated against the schema: no errors, no schema violations. The 5,373 tuning messages were rescanned after every fix, and all 19,511 scored ones after the last: no verdict changed |
| Archive bombs and tricks | A 200 MB member is capped, 20,000 members stop at 200, 12 levels of nesting stop at 2, corrupt and path-traversal archives are listed and never extracted to disk |
| PDF bombs | Stream inflation is capped at 20 MB in total |
| Image bombs (QR decoding) | Images over 25 megapixels are refused from their header, before any pixel is decoded |
| 14 malformed messages (empty, binary noise, no headers, a 1 MB header line, 10,000 headers, 300 nested multiparts, 50 nested messages, broken base64, an unknown charset, garbage encoded words, 1,000 attachments, a million nested tags, a 100 KB URL, null bytes) | No crash; a million nested tags takes 5 s, every other case under 1 s |
| SQL injection through cache keys | Parameterised queries throughout |
| API keys | Sent in request headers only, masked in `phishhawk doctor`, never written to reports or the cache |
| TLS | Certificates are always verified |
| CI | Read-only token, no `pull_request_target`, no untrusted input in shell steps |
| Container | Runs as an unprivileged user; CI runs it with `--network none` |

## What remains

- **A forged `Authentication-Results` header when the receiving server writes
  none.** Nothing in the message shows who wrote it. Set `--trusted-authserv`
  (or `PHISHHAWK_TRUSTED_AUTHSERV`) to your mail server's authserv-id and only
  its results are believed.
- **VirusTotal URL lookups** tell VirusTotal which URL was asked about. They
  are lookups, never submissions; use `--offline` for mail that must not leave.
- **Images on remote servers are never fetched**, so a QR code hosted on a web
  server is not decoded. Fetching attacker content from an analyst's machine
  would be worse.
- **GitHub Actions are pinned to version tags**, not commit hashes; Dependabot
  keeps them current.
- **An IMAP server is trusted** to send what it says it sends: `imaplib` reads
  a whole message literal into memory whatever its declared size. Point
  `phishhawk imap` only at your own mail server.
- **Python's email package is not written for hostile input.** Every issue
  found in it is worked around in [`mailpolicy.py`](../src/phishhawk/mailpolicy.py),
  and the fuzzer keeps looking for more.

Report anything new privately: see [SECURITY.md](../SECURITY.md).
