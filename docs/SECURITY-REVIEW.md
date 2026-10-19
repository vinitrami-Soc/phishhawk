# Security review: PhishHawk attacked by its own author

PhishHawk reads hostile input for a living, so it was tested the way a
bug-bounty hunter would test it: as a target, not as a detector. It was tested
twice before 2.0.0, once against 1.2.0 and again after 2.0 added a dozen
file-format readers of its own, and a third time before 2.1.0, which added
7z decompression, virtual disks and NTFS, and two mail APIs. Round 4 covered
2.2, round 5 the web app of 3.0 (the server, its API, its pages and its
mailbox import), and round 6 its workspaces, sign-up, invitations, feedback
and deletion. Every finding below was reproduced, fixed, and turned into a
test that fails on the old code (most in
[`tests/test_security.py`](../tests/test_security.py), the web app's in
[`tests/server/`](../tests/server/)).

## Threat model

| Attacker | Controls | Wants |
|---|---|---|
| Phishing sender | every byte of the email: headers, bodies, attachments, file names | a clean verdict, or to act on the analyst's machine |
| Someone who can drop files where a batch runs | file names and file types in a folder of reported mail | to stop or confuse the batch |
| Anyone who reads a report | nothing directly | to be tricked by what the report shows |
| Anyone who can reach the web app | requests without a login, and pages on other sites the analysts visit | to take it down, log in, or act as an analyst |
| An analyst | a session or an API token of their own | to do what only an admin may, or to see raw messages that are not theirs |
| A hostile or broken mail server | everything an IMAP, Graph or Gmail answer holds | to take the worker down or the credential away |

The analyst runs PhishHawk on a workstation, in a terminal, and pastes the
Markdown note into a ticketing system; or a SOC team runs the web app on a
server, behind a TLS reverse proxy, and imports reported mail from a mailbox.

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

## Round 3: the 2.1 readers and mail APIs attacked (fixed before release)

2.1 decompresses 7z members, reads RAR's stored members, opens VHD and VHDX
disks down to their FAT and NTFS volumes, reads mailboxes through Microsoft
Graph and the Gmail API, and loads a Public Suffix List. The branch was
reviewed line by line, then by an independent reviewer given only the diff
and the requirements, and the fuzzer was given the new readers. Fixing the
fuzzer itself came first: in 2.0 it sent most mail seeds to the compound-file
reader instead of the pipeline, so the pipeline was fuzzed less than its run
count suggested. Three of the findings below (#32, #34 and #52) were in 2.0
already and were found once that was fixed.

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 30 | **A virtual disk's file contents were budgeted per partition.** Sixteen GPT entries can name one NTFS volume, and a file made of holes reads as zeros without touching the disk, so a small `.vhdx` could hand over 1.6 GB of zeros. | Memory exhaustion | Medium | One content budget for the whole disk, holes included |
| 31 | **A damaged volume hid the others.** An error in any partition made the whole disk "unreadable", so a payload in partition 1 went uninspected behind a broken partition 2. The disk itself was still flagged. | A missed payload | Medium | Each volume is read on its own; the disk is unreadable only when no volume could be read |
| 32 | **Attached messages sharing a name looped the reports.** Files were linked to their parent by name, and every attached message is called `attached-message.eml`, so two of them became each other's child: the console and HTML reports recursed until Python gave up. Found by the fuzzer. | No report for the message | High | Each file records the object that opened it; a child always comes after its parent |
| 33 | **The reports' printable copy lost those links**, so siblings fell back to name matching and every one became the parent of the next: twelve siblings drew 2^11 rows, and a fuzzed message with 400 of them ran the HTML report out of memory. Found by the fuzzer. | No report; memory exhaustion | High | The copy keeps non-field attributes, copies each object once, and points copied links at the copies |
| 34 | **A Received date with a year too large for C** raised `OverflowError` (not `ValueError`) out of the date parser and ended the analysis. Found by the fuzzer. | The phish is reported as an error | High | The date is ignored |
| 35 | **Grouping weak findings by kind was quadratic.** The label normaliser's `\S+\[\.\]\S+` pattern took 44 s on a 200 kB label. | Slow triage | Medium | Linear replacements with identical output on every label of the evaluation scans |
| 36 | **`--watch` dropped a throttled message.** A message Graph or Gmail answered with HTTP 429 was marked as seen and never asked for again. | A reported phish never triaged | Medium | Only messages that were read, or skipped for good (too big, undecodable), are marked as seen |
| 37 | **`--out` report names could collide.** Graph message ids contain `/`, `+` and `=` and differ by case; made file-safe, or on a disk that ignores case, two ids shared one file name and one report overwrote the other. | A lost report | Low | Ids that are not plain lowercase get a hash of the full id in the name |
| 38 | **A 7z member whose data the archive does not hold** was handed on as an empty file. | A misleading result | Low | It is listed as unread |
| 39 | **Unicode host names missed the Public Suffix List**, whose rules are kept in ASCII: `shishi.公司.cn` gave `公司.cn`. Three of the list's 52 official test vectors failed. | Wrong registrable domain with `--psl` | Low | Hosts are matched through their ASCII form and given back as they came; all 52 vectors pass |
| 40 | **A carrier email's findings lost their family** when copied to the reported message, so they could not corroborate. | A weaker verdict | Low | The family is copied too |
| 41 | **The new quoted-From pattern backtracked quadratically.** Two whitespace runs back to back split a long run of spaces every possible way before failing: 11 s for 50,000 spaces. Found by the regular-expression scan. | Slow triage | Medium | One whitespace run, anchored on the quote |
| 42 | **A 7z folder declaring 0 bytes inflated without limit.** zlib reads a `max_length` of 0 as "no limit", so a Deflate folder that declared no output decompressed everything: 300 MB from a 305 kB archive. Found by an independent review. | Memory exhaustion | High | Nothing is decoded for a folder that declares no output |
| 43 | **7z output was charged only when it decoded, and per section.** Folders that broke off just before their end decompressed for free, and each repeated stream section got the whole budget again: 10,000 such folders, or one section repeated 170,000 times, meant minutes to hours of CPU. Found by the review. | CPU exhaustion | High | A folder is paid for before it is decoded; header sections must come once and in order, as 7-Zip reads them |
| 44 | **Containers were budgeted one at a time.** Each 7z had a fresh 64 MB and each virtual disk 256 MB, never counted when the output was thrown away, so a message of many small ones could cost gigabytes. Found by the review. | CPU and memory exhaustion | Medium | One 256 MB budget for everything a message's archives and disk images decompress or read; once spent, further containers are noted and not opened |
| 45 | **A RAR5 extra area could reach back before its header**, so each of 4,000 headers re-read the archive: quadratic, about 800 s for 1 MB. Found by the review. | CPU exhaustion | High | The extra area must lie inside its own header |
| 46 | **With `--psl`, a host's lookup was quadratic in its labels**: 0.26 s for one 4,000-label host, 5 s for a message with five such links. Found by the review. | Slow triage | Medium | Only as many labels as the longest rule can match are looked at |
| 47 | **One torn NTFS file record hid its whole volume**, so the shortcut next to it was never inspected, though Windows would mount the volume. Found by the review. | A missed payload | Medium | A damaged record is skipped; sparse files, 4K-sector disks and NTFS on 4096-byte sectors are read too |
| 48 | **A download that broke off** raised out of `graph` and `gmail` with a traceback and ended `--watch`. Found by the review. | Monitoring stops | Medium | The message is skipped and asked for again next round |
| 49 | **A token with a space or control character** made `requests` refuse the header with an error that quoted it, and the error was printed. Found by the review. | The token in the terminal or a log | Medium | Refused before any request, without being echoed |
| 50 | **`--watch` walked back through the mailbox**, triaging older mail each round when nothing new came, contrary to its help. Found by the review. | Old mail re-triaged; API quota spent | Low | Each round looks at the newest `--limit` messages only |
| 51 | **`graph --unread` alone** sent a filter that Graph refuses next to its sort (InefficientFilter). Found by the review. | The command fails | Low | The filter starts with the date; API errors name their code |
| 52 | **A long MIME parameter name hung Python's email library.** Writing a part back out (to read the text of a multipart part with no usable boundary) refolds its headers, and Python's folder never finds a split point for a parameter whose name is longer than a line: `_fold_mime_parameters` loops for ever. Recent Python patch releases refold every non-ASCII header even with `refold_source="none"`, so `Content-Type: multipart/mixed; boundar<100 NULs>y="\xc5..."` with an empty body hung the analysis. Also in 2.0. Found by the fuzzer. | The analysis hangs for ever | High | Headers read from a message are written back exactly as they came in, never refolded |

## Round 4: campaigns, sweeps, evidence and sandbox packs (fixed before release)

2.2 groups reports into campaigns, sweeps mailboxes through Graph and Gmail
for a reported message's other copies, keeps evidence with a hash-chained
custody log, writes password-protected packs for a sandbox, and explains
authentication in every report. Each new module was written test-first and
then mutation-tested: the code was broken on purpose in every way that
matters (a check skipped, an escape dropped, a limit lifted, a permission
loosened) and the tests had to fail. All did, once three tests were added
for the mutants that first survived. The diff was reviewed line by line, then
by an independent reviewer given only the diff and the requirements; the
regular-expression scan and the fuzzer were run over the new code, the
fuzzer now also correlating, packing and deriving sweep searches from every
mutated message; and every installed dependency and every commit were
checked by pip-audit and gitleaks, which now run in CI.

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 53 | **Paging never ended when an API kept offering empty pages.** `graph`, `gmail` and `sweep` followed `@odata.nextLink` or `nextPageToken` while they held fewer messages than asked for, so a listing offering empty page after empty page kept them asking for ever. Also in 2.1. Found by the review. | The command hangs; API quota spent | Medium | Every listing stops after 100 pages |
| 54 | **`sweep` put any mailbox name into the request path.** A name such as `..` or `a/b` in a mailbox list would have addressed another resource of the API, with the token. Found by the review, before release. | A request with the token to the wrong API path | Low | A mailbox must be an address, a user id or a GUID; anything else is refused before a request is sent |
| 55 | **The authentication-check pattern was quadratic** when searched from every position: over 60 s on 60,000 spaces. Triage only ever matched it at the start of one clause, so no message was slowed, but the pattern was fixed rather than relied on. Found by the ReDoS scan. | None in use | Low | Clauses are stripped and matched at their start |
| 56 | **`sweep --like` searched whole platform zones**, and Graph's body check was a substring test. A phish on `evil-store.myshopify.com` searched for `myshopify.com`, and a body naming `tesco.com` matched a search for `co.com`, so legitimate mail could be listed as copies, and purged by a playbook following the documented workflow. Found by the independent review. | Legitimate mail purged | High | A known platform is searched by its customer's host; a body must name the domain or a host under it; Gmail hits are checked against their headers, and a domain only Gmail's search vouches for is labelled so |
| 57 | **A file name that is not UTF-8** crashed `--evidence` (after keeping the message, before recording it), `campaign --json`/`--md`, and `scan --json` (since before 2.2). Found by the independent review. | The run stops; custody incomplete | Medium | Such bytes are written as `\xNN` escapes |
| 58 | **One failed request discarded a mailbox's sweep results**: a copy deleted mid-sweep, a 429 or a 400 on one search. An attacker controls subject and Message-ID lengths that could provoke a 400. Found by the independent review. | Copies missed | Medium | Each failure is a warning on its mailbox and the rest is kept; a deleted copy is skipped; terms are capped and KQL operators neutralised; an incomplete sweep exits 3 |
| 59 | **Campaigns merged through shared providers**: path-style IPFS gateways linked every message using `ipfs.io`, and form and file-sharing links with the document id in the query collapsed into one. Found by the independent review. | Unrelated phish shown as one campaign | Medium | IPFS links by content identifier; document ids stay in the link |
| 60 | **A forward to the SOC counted as a reply** to the phish. Found by the independent review. | Users wrongly shown as having replied | Medium | Only mail sent to the copy's sender or reply-to address counts |
| 61 | **`evidence verify` could not catch a rewritten log**, and a crash mid-write left half a message that later read as tampering. Found by the independent review. | False assurance; false alarms | Medium | `--head` checks against a value recorded elsewhere; messages are written to a temporary file and linked into place |

## Round 5: the 3.0 web app attacked (fixed before release)

The web app was mapped route by route (every API route, page and form, who
may call it, and what it reads), scanned by CodeQL's security-extended
queries for Python and TypeScript and by Bandit, and attacked on a running
server: without a login, as an analyst, with API tokens of each scope, from
another site, and from a hostile IMAP server.

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 62 | **Anyone could make the server hold 100 MB requests.** Every request that was not a GET could be as large as a whole upload (4 x `MAX_UPLOAD_MB`), and its body was read before anyone was asked to log in. Four unauthenticated 99 MB requests took a running server from 194 MB to 1.46 GB. | Memory exhausted without a password | High | Only an upload may be larger than 1 MB, and one over 1 MB is read only from a caller with a valid session or API token; anything else over 1 MB is refused from its `Content-Length`. The same requests leave the server at 196 MB |
| 63 | **A password reset left the old session working.** Sessions were checked against the user's disabled flag only, so an account reset because someone else had it stayed in their hands. | Account takeover survives the response | Medium | A new password ends every other session of that user; an admin changing their own keeps the one in use |
| 64 | **A disabled user got their session back** when enabled again before it was next used: a session ended only when it was presented. | Disabling did not log out | Low | Disabling ends the user's sessions at once |
| 65 | **Login CSRF.** A form on another site could sign an analyst into an account of the attacker's, and read what they then submit. SameSite=Strict cookies do not stop a login. | Submissions shown to an attacker | Low | Any request that changes something, a login included, is refused when the browser marks it `Sec-Fetch-Site: cross-site` |
| 66 | **A damaged deflate, bzip2 or LZMA stream in an uploaded .zip** raised `zlib.error`, `OSError` or `LZMAError`, a server error. | An error page instead of a reason | Low | Refused as an archive that could not be read (415) |
| 67 | **An IMAP server could send gigabytes as one message.** `imaplib` reads a literal of whatever size is announced; the poll checks `RFC822.SIZE` first, but a server could understate it. The CLI's `imap` command read the same way. | The worker's memory exhausted by a hostile or broken server | Low | A literal larger than the limit plus 64 KB stops the connection unread; the mailbox shows why |
| 68 | **Idle sessions stayed in the database for ever** unless their cookie came back. | A table that only grows | Low | The hourly sweep removes sessions idle past `SESSION_IDLE_MINUTES` |
| 69 | **The CSRF token was compared with `!=`.** | None measurable over a network | Hardening | Compared in constant time |

### The web app: tested and found safe

| Attack | Result |
|---|---|
| Every route as every role | The role matrix test calls every API route as an admin, an analyst, a read token, a submit token and nobody. Admin actions, raw message downloads and deletions need a person's session. A token cannot do them, whoever owns it. Analysts read only their own audit records |
| Raw messages of other analysts | Only the submitter or an admin downloads a raw message or deletes it (analysts share one queue of analyses by design) |
| Stored script in pages | Every template is autoescaped, nothing is marked safe, and the hostile-payload test renders a sender-controlled payload in every field on every page. The frontend renders text only; no `dangerouslySetInnerHTML`, and no indicator becomes a link |
| The stored HTML report | Served with its own policy (`sandbox` without scripts, `default-src 'none'`), so it runs in an opaque origin even when opened directly, outside the frontend's frame |
| CSRF on a session | `SameSite=Strict`, `HttpOnly` and `Secure` cookies, and a CSRF token on every change: a header for the API, a form field for the pages |
| Sessions and passwords | Argon2id passwords, at least 12 characters; session cookies and API tokens random and stored only as an HMAC or a hash, so a copy of the database logs nobody in; a new `SECRET_KEY` ends every session; the same work for an unknown user as for a wrong password |
| Guessing passwords | After three failures for a name or an address, each attempt waits twice as long (up to 5 minutes); the address comes from `X-Forwarded-For` only through a trusted proxy |
| SQL injection | Every query is built by SQLAlchemy with parameters; the search escapes `%` and `_` |
| Paths | A stored file is found by its name in the analysis's list, never on disk; the frontend's files are served by Starlette, which keeps to its folder |
| Uploads | Never spooled to disk; an archive bomb, a 2,000-entry archive and an over-limit batch are refused before they are inflated; a name inside an archive is never used |
| Mailbox credentials | Sealed with the encryption key and bound to the mailbox, never returned (only `secret_set`); Graph and Gmail tokens go only to their API's host, a next link elsewhere stops the poll, the key's own `token_uri` is ignored, and every reason shown is stripped of the credential, any bearer token and control characters |
| Static analysis | CodeQL security-extended: 3 results, none a flaw. The CLI prints a count of re-encrypted secrets (a count, not a secret). The domain pattern in the settings is cut at 253 characters and only an admin reaches it (0.0 s at worst). One pattern is in a frontend test. Bandit: two constant SQL strings in a migration |
| Headers | A strict Content-Security-Policy, `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `Cross-Origin-Opener-Policy`, HSTS behind TLS, `no-store` on API answers, nothing indexed |
| The container | Runs as an unprivileged user on a read-only file system, every capability dropped, `no-new-privileges`; Compose publishes the port on this machine only |

## Round 6: workspaces, sign-up, feedback and deletion (fixed before release)

The surfaces added since round 5 were attacked on a running server with two
organizations and people on their own: one workspace's admin against
another's rows, lists, searches and built-in pages; the invitation and setup
tokens, raced and guessed; sign-up from one address with forged
`X-Forwarded-For` headers; markup, formulas and bidirectional overrides in
feedback, notes and names; and the new deletions, as every role and with API
tokens. Bandit was run again over the server.

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 70 | **Any admin of the owner's organization could become the owner.** `PATCH /api/v1/users/{id}` (and the built-in Users page) let an admin set the owner's password, demote them or disable them, as for any member. A new password let them sign in as the owner: server settings, everyone's feedback, and deleting any workspace. | Privilege escalation to the whole server | High | Only the owner changes their own account; anyone else gets 403, through the API and the page |
| 71 | **A message for a workspace deleted meanwhile left its encrypted copy.** An upload or a mailbox import writes the raw message before its row; when the row's workspace was gone, the insert failed and the file stayed. | Deleted data kept on disk, encrypted and unreachable | Low | The file is removed when the insert fails |

### Workspaces and accounts: tested and found safe

| Attack | Result |
|---|---|
| Another workspace's rows by ID | Every route and page that names a row is called by another workspace's admin, generated from the route table, so a new route without scoping fails the suite: 404, as for a row that does not exist. The owner's workspace routes answer 404 to anyone else |
| Another workspace's rows in lists and searches | The Queue's search by SHA-256, report ID or indicator, its filters by user and by dispute, campaigns, the audit log, users, tokens, mailboxes, invitations, feedback, the summary of answers and the settings (provider keys included) show only the caller's workspace, in the API and on the built-in pages |
| IDs in request bodies | A token for another workspace's user, and an answer removed through another analysis, are refused (404) |
| Invitation tokens | 32 random bytes, stored as a hash; one use, enforced by an atomic update, so six joins raced at once make one account; revoked, used and expired ones answer 404 |
| The setup code | Compared in constant time, throttled, sealed with the encryption key, and closed (404) once anyone has an account |
| Sign-up from one address | Three an hour per address and a daily cap for the server; `X-Forwarded-For` counts only from a trusted proxy, so forged addresses from anywhere else are throttled as one |
| Markup and formulas in feedback, notes and names | Kept as text and shown as text; nothing is rendered as HTML. The owner's CSV holds no message, note or person, only numbers, hashes, report IDs and verdicts, and no cell starts with a formula character |
| Bidirectional overrides and control characters | Refused in feedback, notes, profile fields and organization names |
| Deleting | An admin deletes only their own workspace's members, never themselves or the owner; only the owner deletes a workspace, never their own; someone on their own deletes their account only with their password, throttled as logins are. None of it with an API token. A deleted workspace's sessions, tokens, rows, settings and encrypted files go with it, and the audit chain still verifies |
| The owner's API tokens | A token never acts as the owner: server settings, everyone's feedback, the CSV and the workspace list need a person's session |
| Bandit | Constant SQL strings in two migrations, a token endpoint's URL taken for a password, and `assert` used to narrow types: none a flaw |

## Tested and found safe

| Attack | Result |
|---|---|
| Script injection in the HTML report (`<script>`, `onerror`) | Escaped; the report's Content-Security-Policy also blocks scripts and remote requests |
| Markup in every field a sender controls, in the HTML report: subject, display names, Reply-To, Return-Path, To, Message-ID, Received, the Authentication-Results server name, attachment names, calendar invitations, link text and `javascript:`, `data:` and `vbscript:` links | The rendered page is checked against an allowlist: only the report's own tags, no event-handler or loading attribute, and links only to the report's own sections, MITRE ATT&CK and VirusTotal. Nothing is loaded from the network. In the Markdown note the payload stays inside code spans, and the only links are the report's MITRE references |
| A script, an inline handler and a remote image smuggled into the HTML report past escaping | Checked in Chromium: the Content-Security-Policy (`default-src 'none'`, plus `base-uri 'none'` and `form-action 'none'`) stops all three; the image request never leaves the browser |
| Report file names from the message | A folder given to a report option gets a name made of hex digits and the date only (`phishhawk-report-<12 hex digits of the message's SHA-256>-<date>`), so a subject or file name with `../`, a control character or a misleading extension never reaches the disk. The HTML report links another report file only by a bare name of letters, digits, `.`, `_` and `-` that cannot start with `.`, and only when it is in the same folder |
| Spreadsheet formula injection in the CSV (`=HYPERLINK(...)`) | Every cell starting with `= + - @` or a control character is neutralised, in the indicator CSV and in the campaign and sweep CSVs |
| Tampering with the custody log | A record edited, removed or reordered, and a kept message changed or deleted, are each reported by `evidence verify`. A planted file or a symlink under a message's name is refused; the log and every kept message are opened without following symlinks and must be regular files |
| The sandbox pack | Every member encrypted; the names inside are fixed (`message.eml`, or `message.msg` for an Outlook message; `files/<first 16 hex digits of the SHA-256>-<safe name>`; `urls.txt`; `manifest.json`) and can hold no path; written 0600 without following a symlink or blocking on a FIFO; at most 50 MB of files. Opened by Python's `zipfile` and Info-ZIP `unzip` |
| Search injection in `sweep` | A Graph `$search` value cannot leave its quotes, and Graph's hits are checked against what was asked before they count; OData filter values double their quotes; Gmail phrases are quoted. Only GET requests, the token only to the API's host |
| Hostile corpora for `campaign` | Weak traits shared by more than 200 messages are ignored, so pairing cannot grow without bound; 5,125 real messages correlate in 45 s, triage included |
| Dependencies | pip-audit finds no known vulnerability in anything PhishHawk installs (requests, urllib3, idna, certifi, charset-normalizer, pillow, zxing-cpp); checked in CI on every change |
| Secrets | gitleaks over every commit finds none; checked in CI on every change |
| Regular-expression denial of service | All 140 patterns in the package (every literal, and every pattern built at import time) against 204 pathological strings of 60,000 characters each, every pattern searched from every position: worst 0.2 s on 2.2's final code, after the fixes above (#35, #41, #55) |
| Mutation fuzzing | Every reader and the pipeline, every report rendered each time, 2 GB memory limit. 2.0: 9.7 million runs in four rounds; the last, 3.6 million runs on 2.0's final code, found nothing. 2.1: more than 1.5 million runs in four more rounds, with the new readers added and the pipeline fuzzed as intended; the last, 378,597 runs on 2.1's final code, found nothing. 2.2: the sandbox pack, campaign correlation with its reports and sweep's search criteria added to the pipeline target; 362,634 runs before the independent review's fixes, 147,461 after them and 148,311 on 2.2's released code found no crash and no hang, only garbage 2 to 3 MB `--psl` files that load in about 5 s (see A hostile `--psl` file below). All 32 findings of the earlier releases are fixed and replay on 2.2's released code without error, the slowest in 1.9 s. Hypothesis property tests of the same targets run in CI |
| Hostile charsets | 247 combinations of 19 hostile charset names and 13 header and body positions, through triage and every report: no errors |
| Real mail | 19,917 real messages through triage and all seven report formats, the JSON validated against the schema: no errors, no schema violations, with 2.0's code and again with 2.1's and 2.2's final code. The 5,373 tuning messages were rescanned after every 2.1 security fix, and with 2.2's final code: no verdict changed |
| A hostile `--psl` file | Loading is linear and capped at 8 MB: about 1.5 s per MB of non-ASCII rules (Python's IDNA codec), so a garbage 3 MB list takes 4 to 7 s; the real list loads in 0.1 s. The file is the analyst's own choice, never anything from mail |
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

- **Usernames are the server's, and a deleted one can be taken again.** The
  audit log keeps the name of whoever did each thing, so after a deletion a
  record may name someone who no longer has that account. Sign-up also says
  when a username is taken.
- **The owner sees each workspace's name**, and someone on their own is named
  after their first and last name. It shows no profile, member or message.
- **The daily caps and the hourly feedback limit are counted, not locked.**
  Requests raced at the same moment can pass a cap by a few.
- **An invitation keeps its role** after the admin who made it is demoted or
  deleted, until it is used, withdrawn by another admin, or 7 days old.
- **A forged `Authentication-Results` header when the receiving server writes
  none.** Nothing in the message shows who wrote it. Set `--trusted-authserv`
  (or `PHISHHAWK_TRUSTED_AUTHSERV`) to your mail server's authserv-id and only
  its results are believed.
- **VirusTotal URL lookups** tell VirusTotal which URL was asked about. They
  are lookups, never submissions; use `--offline` for mail that must not leave.
- **Images on remote servers are never fetched**, so a QR code hosted on a web
  server is not decoded. Fetching attacker content from an analyst's machine
  would be worse.
- **A GitHub Action's own code is trusted** at the commit it is pinned to.
  Every action is pinned to a full commit SHA (its version in a comment), so
  a moved tag or branch cannot change what CI runs; Dependabot proposes each
  update as a reviewable change.
- **An IMAP server is trusted** to answer as a mail server should. A message
  larger than the limit is no longer read (#67), but the server still decides
  what the messages say. Point `phishhawk imap`, and a mailbox in the web app,
  only at your own mail server.
- **A Graph or Gmail token can do what its permission allows.** PhishHawk
  only sends `GET` requests, but it cannot stop a token with `Mail.ReadWrite`
  from being used elsewhere: give it a read-only one (`Mail.Read`,
  `gmail.readonly`). Tokens are read from the environment, which other
  processes of the same user can see.
- **Logical partitions** (inside an MBR extended partition) and RAR's
  compressed members are listed or skipped, not read.
- **Python's email package is not written for hostile input.** Every issue
  found in it is worked around in [`mailpolicy.py`](../src/phishhawk/mailpolicy.py),
  and the fuzzer keeps looking for more.
- **The custody log proves integrity and order, not authorship.** Someone who
  can rewrite the whole log can recompute every link after a change. The
  chain value in each report, copied into the ticket, is what pins the log as
  it was then; keep the evidence folder where only the SOC can write.
- **The sandbox pack's encryption is ZipCrypto**, which keeps the pack from
  being opened or quarantined by accident, not from a determined reader. The
  pack holds the message: treat it like the evidence it is.
- **`sweep` sends search terms to your mail host**: the reported message's
  addresses, subject, Message-ID and phishing domains, to Microsoft or Google,
  which already hold the mail. Sweeping many Graph mailboxes needs an
  application token with `Mail.Read` for all of them; scope it with an
  application access policy.
- **Clicks and opened attachments are not in a mailbox.** `sweep` reports
  copies, read state and replies; who clicked is in your proxy and EDR logs.
- **`/healthz` needs no login**, so a load balancer can call it. It says the
  version, the queue length and the free disk space. If the server is
  reachable from outside the SOC, keep `/healthz` to the proxy's own checks.
- **A slow upload holds a connection.** The server has no time limit for
  reading a body. Put the TLS reverse proxy that the docs ask for in front of
  it, with its own timeouts.
- **An admin chooses a mailbox's IMAP host**, and the poll connects wherever
  that is, inside the network too. The reason it shows tells whether a port
  answered. Admins are trusted with this.
- **Submissions are not rate-limited per user.** An analyst, or a submit
  token, can fill the queue. Each analysis is limited in memory, CPU and
  time, so one message cannot take the worker down.
- **Very old browsers send no `Sec-Fetch-Site`.** Their sessions are still
  protected by SameSite=Strict cookies and the CSRF token; only a login
  started on another site (#65) gets through there.

Report anything new privately: see [SECURITY.md](../SECURITY.md).
