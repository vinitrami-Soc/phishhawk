# Security review: PhishHawk attacked by its own author

PhishHawk reads hostile input for a living, so before 1.3.0 it was tested the
way a bug-bounty hunter would test it: as a target, not as a detector. Every
finding below was reproduced against 1.2.0, fixed, and turned into a test in
[`tests/test_security.py`](../tests/test_security.py) that fails on the old code.

## Threat model

| Attacker | Controls | Wants |
|---|---|---|
| Phishing sender | every byte of the email: headers, bodies, attachments, file names | a clean verdict, or to act on the analyst's machine |
| Someone who can drop files where a batch runs | file names and file types in a folder of reported mail | to stop or confuse the batch |
| Anyone who reads a report | nothing directly | to be tricked by what the report shows |

The analyst runs PhishHawk on a workstation, in a terminal, and pastes the
Markdown note into a ticketing system.

## Findings (all fixed in 1.3.0)

| # | Finding | Impact | Severity | Fix |
|---|---|---|---|---|
| 1 | **Terminal escape injection.** Subject, display name, file names and file paths reached the terminal raw. `OSC 52` wrote to the analyst's clipboard, `OSC 8` turned text into a hidden link, `ESC[2J` cleared the screen. | A pasted "command" from the clipboard, a hidden link to the attacker, a report the analyst cannot trust | High | Every attacker string is made printable before display: control characters are shown escaped (`\x1b`), bidirectional overrides are named (`<U+202E>`) |
| 2 | **Unwrap evasion.** A phish with a harmless `.eml` attached was analysed as the attachment: the phish became "the reporter" and the verdict was *NO STRONG INDICATORS*. | Any phish passes | High | Every unwrapped layer is analysed as well; a suspicious carrier keeps its signals, links and lookalikes (`carrier email: ...`) |
| 3 | **Forged `Authentication-Results`.** All such headers were read, so when the receiving server's own header left out a check, a `dmarc=pass` written by the sender further down was believed. A forged `Received-SPF: pass` filled a missing SPF result. | Authentication failures hidden | Medium | Only the receiving server's block at the top is trusted (one header, or one per check under the same authserv-id, as ProtonMail writes them). A pass claimed below it is ignored and flagged; `--trusted-authserv` pins your own server |
| 4 | **A planted file hangs a batch.** A FIFO or a symlink to `/dev/zero` named `*.eml` blocked or exhausted memory forever; a 300 MB file took minutes. | SOC automation stalls | Medium | Only regular files are read, and messages over `--max-size` (50 MB) are skipped with a message |
| 5 | **Link flood.** A message with 50,000 links took 31 s (quadratic loops, and the brand checks repeated for every link). | Slow triage on hostile mail | Medium | Linear data structures and cached brand work: 3 s. Lookalike checks stop at 5,000 distinct hosts, and the message is flagged when they do, so padding cannot hide a link |
| 6 | **Markdown ticket injection.** Attacker text in the note became live links, remote images (a beacon when the ticket is opened) and raw HTML; bare URLs were auto-linked by GitHub and GitLab. | Clickable phishing links inside the ticketing system | Medium | Markdown syntax is escaped, `<` and `>` encoded, bare URLs defanged, and code spans cannot be closed from inside |
| 7 | **Right-to-left override in file names.** `invoice‮fdp.exe` rendered as `invoiceexe.pdf` in the reports. | The analyst misreads the file type | Low | The override is shown as `<U+202E>`; the detection still sees the real name |
| 8 | **World-readable lookup cache.** `~/.cache/phishhawk/lookups.sqlite3` was `0644`. It lists every URL looked up, victims' addresses inside URLs included. | Other users of a shared analysis box read the SOC's investigations | Low | The cache is `0600` in a `0700` directory |
| 9 | **urlscan.io submissions carried recipient addresses** (plain, URL-encoded or base64), and unlisted scans are visible to other urlscan customers. | Victims' addresses published | Low (opt-in) | Your recipients' and protected domains' addresses are replaced with `user@example.com` before submission |
| 10 | **Lookalike evasions:** `paypal-com.top`, `www-paypal.com`, `paypalcom.top`, `micros-oft.com` were not found. | Missed lookalikes | Detection | Spelled-out domain words (`com`, `www`, `net`, `org`, ...) count as combosquat filler, and a name split by hyphens is compared joined |

## Tested and found safe

| Attack | Result |
|---|---|
| Script injection in the HTML report (`<script>`, `onerror`) | Escaped; the report's Content-Security-Policy also blocks scripts and remote requests |
| Spreadsheet formula injection in the CSV (`=HYPERLINK(...)`) | Every cell starting with `= + - @` or a control character is neutralised |
| Regular-expression denial of service | 828 pattern-and-input combinations (every module-level regex against 23 pathological strings of 60,000 characters): worst 0.09 s |
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

Report anything new privately: see [SECURITY.md](../SECURITY.md).
