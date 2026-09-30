# Changelog

All notable changes to PhishHawk are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/): the command line, the exit codes and
the JSON and STIX output are the public interface.

## [Unreleased]

### Added

- **QR-code phishing detection.** With the optional extra
  (`pip install 'phishhawk[qr]'`, included by `install.sh` and the Docker
  image), QR codes are decoded in image attachments, inline images (named or
  not), images embedded in the HTML as `data:` URIs, images inside PDFs (JPEG,
  Flate with PNG predictors, CCITT fax) and codes drawn with HTML table cells or
  block characters. Their links are analysed like any other link, and a QR code
  that leads somewhere suspect, or comes with a credential or MFA ask, is high.
  `--no-qr` turns decoding off; `phishhawk doctor` shows whether it is available.
- `.mbox` input: `phishhawk scan Inbox.mbox` reads every message in a Google
  Takeout or Thunderbird export, and `eval/run_eval.py --benign Inbox.mbox`
  measures false positives on your own mail and prints totals only.
- `--trusted-authserv ID` (and `PHISHHAWK_TRUSTED_AUTHSERV`) names your mail
  server, so only its `Authentication-Results` are believed.
- `--max-size MB` (default 50) skips oversized messages.
- The JSON report has `qr_codes` and `forged_auth`.
- [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md): PhishHawk attacked as a
  target, every finding with its fix and a test.
- Crypto-wallet lures (seed and recovery phrases, "validate your wallet",
  airdrops; high with two or more) and casino "free spins" lures in five
  languages. Ledger joins the brand list.
- A new evaluation on every email in phishing_pot: 5,714 held-out phishing
  emails from 2022 to 2026, 78.5% flagged (1.2.0: 75.4%), with no change in
  false positives. The split is in `eval/splits/phishing_pot_2026.json` and
  `eval/fetch_phishing_pot.py --full` rebuilds it.
- A quishing sample, `samples/sample_quishing.eml`, with its QR code in a PDF.

### Security

- Control characters from a message (terminal escape sequences that clear the
  screen, write the clipboard or hide a link) no longer reach the terminal: they
  are shown escaped, and right-to-left overrides are shown as `<U+202E>`.
- The Markdown note escapes Markdown and HTML in message text and defangs bare
  URLs, so a subject cannot put a live link, an image or HTML into a ticket.
- A phish that carries a harmless attached message is no longer analysed as the
  attachment alone: every unwrapped layer is analysed, and a suspicious one keeps
  its findings (`carrier email: ...`).
- Only the receiving server's `Authentication-Results` are believed. A pass
  written further down by the sender is ignored and flagged, and a forged
  `Received-SPF` no longer fills in a missing SPF result.
- Named pipes, device files and messages over `--max-size` are skipped instead
  of hanging a batch.
- The lookup cache is readable by its owner only (`0600` in a `0700` folder).
- `--urlscan-submit` replaces your recipients' addresses in a URL, plain,
  URL-encoded or base64, with `user@example.com` before submitting it.

### Fixed

- Lookalikes that spell a domain into the name (`paypal-com.top`,
  `www-paypal.com`, `paypalcom.top`) or split it with a hyphen (`micros-oft.com`)
  are found.
- A message with 50,000 links takes 3 s instead of 31 s. Lookalike checks stop
  at 5,000 distinct hosts, and a message over that is flagged, so padding cannot
  hide a link.
- A malformed header such as a broken `Message-Id` no longer erases the SPF,
  DKIM and DMARC results; `Authentication-Results` sent as base64 encoded words
  (Microsoft 365) are decoded.
- MFA, SSO, VPN and Microsoft 365 words count in combosquats
  (`example-corp-mfa.top`).

## [1.2.0] - 2026-09-29

### Added

- `eval/fetch_spamassassin.py` fetches the legitimate-mail evaluation set and
  splits it into a tuning and a held-out part.
- The JSON report has `mailing_list` and `list_domains`.

### Changed

- Empty cells in the evaluation tables (`README.md`, `eval/README.md`) read
  *n/a*, and signals with no ATT&CK technique in `docs/DETECTIONS.md` read
  *none*, each explained under its table, instead of a dash.

### Fixed

- **False positives on real legitimate mail, from about one message in four
  to 0.7%.** Tested for the first time on 4,150 real legitimate emails (the
  SpamAssassin public corpus), 1.1.0 flagged 23% of everyday mail and 55% of
  legitimate mail that looks like spam. On the held-out part, scored once
  after the fixes, it now flags 10 of 1,400 everyday messages and 29 of 125
  spam-like ones. Held-out phishing recall is 70.5% (was 71.0%).
- A mailing list that sets Reply-To to its own address is no longer scored as
  high-severity reply diversion. List mail is recognised by `List-Post`,
  `Mailing-List`, `X-Mailing-List`, `X-BeenThere` or `Precedence: list`, never
  by `List-Id` or `Precedence: bulk`, which the bulk services phishers rent
  also set.
- A link mismatch through an ordinary click tracker is medium, and counts once
  per destination; it stays high when the link text shows a brand, government,
  free-mail or your own domain, or the destination is suspect. An email address
  in link text is no longer read as a claimed website.
- A combosquat must add only lure or business words, digits or a short code to
  the name (`outlooksecure`, `paypal-billing`, `example-corp-payroll`):
  `linuxmafia.com` is no longer a lookalike of `linux.ie`, nor `yahoogroups.com`
  of Yahoo, nor `storage.googleapis.com` of Google.
- A brand's own country site (`yahoo.co.uk`, `santander.com.br`) is not a
  lookalike, and a brand word in a subdomain (`outlook.4team.biz`) is medium
  unless something else is wrong with the site.
- A missing `Authentication-Results` header is no longer scored.
- A digest with thousands of links parses about twice as fast.

## [1.1.0] - 2026-09-24

### Changed

- **The HTML report is redesigned in the IntelPulse console's design language.**
  The verdict and risk score lead the page, followed by counts of URLs, files,
  signals and ATT&CK techniques, sender authentication and the recommended
  actions. The evidence follows: a severity bar over the signals table, then
  lookalike domains, numbered URLs, attachments, infrastructure, ATT&CK and the
  copy-ready indicators. Every severity carries a glyph and a word as well as a
  colour, and every text colour clears 4.5:1 in both themes.
- **The report takes the PhishHawk logo's amber-orange.** Severity is one
  validated ramp: on paper high is deep rust, medium orange and low amber; on
  a dark screen the order runs the other way, so the most severe is brightest.
- **A score ring shows where the risk score came from.** It fills to the score
  on a 0 to 30 scale, split into high, medium and low points, with ticks at
  the verdict thresholds (4 and 8), and a legend gives the signals and points
  behind each part. A line under the verdict says which rule produced it.
- **The report opens in the reader's light or dark mode,** and an Auto / Light /
  Dark switch in the top bar changes it. The switch is plain HTML and CSS, so
  the report still runs no scripts; a printout is always light.
- **More detail in the same wording.** Count tiles say how many URLs and files
  were flagged, how many files came from archives, signals per severity and
  ATT&CK tactics covered. The sender card adds Received hops, Forwarded from
  and addresses found in the body; the report shows the reputation sources and
  who reported the message. The signals panel shows how the score adds up,
  URLs show their link text, attachments list SHA-1 and MD5 beside SHA-256,
  ATT&CK techniques are grouped by tactic, and the indicators list counts each
  type. Processing errors get their own panel.
- **The report prints properly.** A4 pages, the summary on page one and the
  evidence from page two, column headers repeated on every page, no row split
  across a page break, and page numbers in the footer. In a batch, each
  message starts on a new page.
- The report embeds Outfit and JetBrains Mono (SIL OFL 1.1) as data URIs, so it
  still loads nothing from the network; the Content-Security-Policy now allows
  `font-src data:` and nothing else. A report is about 150 KB.
- Tables turn into labelled cards on a phone, so nothing scrolls sideways at 390px.

### Added

- `tools/make_report_shots.py` renders the README's report images, including the
  printed pages.

## [1.0.1] - 2026-09-24

### Fixed

- **Lookalikes of trusted redirectors are no longer unwrapped.** A link on
  `evilbing.com/ck/a`, `notfacebook.com/l.php`, `fakeyoutube.com/redirect` or
  `mylinkedin.com/redir/redirect` matched the suffix check for the real site,
  so the report called an attacker's own domain "Bing redirect" (and so on).
  Hosts now have to be the domain itself or a subdomain of it. Resolves
  CodeQL alerts 1 to 5; alert 6 was a test assertion, now a set comparison.

## [1.0.0] - 2026-09-23

The first release under the PhishHawk name, as a standalone project.

### Added

- **Command line** with `scan` (the default), `doctor`, `cache`, `techniques` and
  `help`, full `--help` text with examples, environment variables and exit codes,
  and a start-up banner that only appears on an interactive terminal.
- **Parsing** of reported mail: phish attached to a report is unwrapped up to
  three layers deep; for inline forwards, the original sender is recovered from
  the quoted header block in six languages. ZIP archives, HTML attachments and
  PDFs (including compressed streams) are inspected in memory.
- **Detection**: lookalike-domain engine (homoglyph, typosquat, combosquat,
  TLD swap, brand-as-subdomain) against 66 brands and your own domains; link
  checks including Safe Links, Proofpoint and Barracuda unwrapping and
  open-redirect decoding; magic-byte attachment typing; HTML smuggling and
  credential-form detection; lure wording in five languages; callback-phishing,
  QR-code and free-mail BEC patterns.
- **MITRE ATT&CK** tags on every signal, covering 18 techniques.
- **Enrichment** from VirusTotal, urlscan.io, RDAP domain age and AbuseIPDB,
  with a SQLite cache, free-tier rate limiting and a per-message VirusTotal budget.
  Protected and well-known brand domains are never sent to third parties.
- **Reports**: colour terminal, self-contained HTML with a strict
  Content-Security-Policy, JSON, STIX 2.1 with deterministic IDs, Markdown ticket
  notes and CSV with formula-injection protection.
- **Evaluation** tooling: a labelled synthetic corpus, a runner that reports
  recall and false-positive rate, and a fetcher for the phishing_pot corpus.
  CI fails if synthetic recall drops below 95% or false positives rise above 2%.
- **Packaging**: `install.sh` (pipx or a private virtualenv, no root), a
  non-root Docker image that works with `--network none`, and a
  run-from-checkout launcher.
- **Documentation**: usage, detections and integrations guides, charts of the
  evaluation results, contribution and security policies.

### Changed (compared with the phishtriage prototype)

- Low-severity signals now add at most 3 points between them, and
  `SUSPICIOUS` needs a high signal or a score of 4. False positives on the CPython
  email test corpus fell from 12.5% to 2.1%.
- Held-out recall on real phishing rose from 70.0% to 71.0% and tuning-set
  recall from 75.0% to 81.0% (offline, no reputation lookups).

### Fixed

- A 100 KB base64 image in an HTML body made the address regex quadratic, so
  one message took 60 seconds to parse. Every regex that sees message bodies is
  now bounded; the worst case is under half a second.
- Letter-spaced lures (`v e r i f y`) and brand names with punctuation
  (`Trust-Wallet`) slipped past keyword and brand checks.
- Links inside compressed PDF object streams were not extracted.
- Output piped into `head` no longer prints a traceback, and Ctrl+C exits with
  code 130.

## Before PhishHawk

PhishHawk grew out of two earlier iterations kept in the author's portfolio
repository: a single-file IOC extractor (20 September 2026) and the
`phishtriage` package (versioned 2.0.0, 23 September 2026). Version numbering
restarted at 1.0.0 with the new name.

[Unreleased]: https://github.com/vinitrami-Soc/phishhawk/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.2.0
[1.1.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.1.0
[1.0.1]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.0.1
[1.0.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.0.0
