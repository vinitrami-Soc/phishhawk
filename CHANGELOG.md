# Changelog

All notable changes to PhishHawk are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/): the command line, the exit codes and
the JSON and STIX output are the public interface.

## [Unreleased]

### Security

- Every GitHub Action in CI and the release workflow is pinned to a full
  commit SHA, with its version in a comment. The PyPI publishing action
  followed a branch (`release/v1`), which anyone with push access there
  could move.
- Tests for spreadsheet-formula escaping in the campaign and sweep CSVs: a
  cell opening with `=`, `+`, `-` or `@` gets a leading `'`. The escaping was
  already applied; each output path is now tested on its own.

### Fixed

- Documentation: the sandbox pack's member names (`message.msg` for an
  Outlook message; `files/<first 16 hex digits of the SHA-256>-<name>`).
- Documentation: USAGE now says next to `--sandbox` that ZipCrypto is not
  confidentiality against a determined reader, and lists what `sweep` sends
  to Microsoft or Google.

## [2.2.0] - 2026-10-06

PhishHawk now follows a phish past the first report: `phishhawk campaign`
groups a folder of reports into campaigns by what they share, and
`phishhawk sweep` finds the other copies of a reported message in Microsoft
365 or Gmail mailboxes, with whether each was read or replied to. Every
report names the exact bytes it analysed and explains, in sentences for a
ticket, whether the sender's domain is authenticated. `--evidence` keeps
each message with a hash-chained custody log, and `--sandbox` writes a
password-protected pack for any sandbox. PhishHawk stays read-only, and
none of this sends anything anywhere except `sweep`, which only asks your
own mail host. No verdict changed on the 5,373
tuning messages; of the 14,138 held-out messages, scored once, three did (see
Fixed).

### Added

- **`phishhawk campaign PATH...`** groups reported messages into campaigns,
  offline. Messages link by one strong trait (an attachment, a phishing
  domain, link or host, a QR payload, a sender or reply-to address, a
  wallet, a phone number) or two weak ones (a subject that differs only in
  numbers, a display name, an originating IP), followed transitively. Each
  campaign lists what links it, its recipients (blast radius), senders and
  first and last sighting, in the terminal, JSON, CSV and Markdown.
  Shared infrastructure never glues campaigns together: known brands and
  your protected and allowed domains, shorteners, free-mail, bulk-mail
  services and mail-gateway link rewrites, web plumbing (fonts, schemas,
  CDNs), mailing lists' own links and embedded images; platforms whose
  customers each get a host name (Cloud Run, registry zones such as
  `sa.com`, help desks) link by that host; and web addresses link only
  messages most of which were judged suspicious. On the 2,500 real phishing
  messages of the tuning set the largest campaign is 86 messages, and mixed
  with 2,625 legitimate ones no campaign mixes the two. Run once on the
  held-out data, 4 of 742 campaigns mix the two, through links to well-known
  news and reference sites; see [eval/README.md](eval/README.md).
- **`phishhawk sweep graph|gmail`** finds the other copies of a reported
  message: `--like reported.eml` searches for its Message-ID, its sender and
  reply-to addresses, its subject and the phishing domains it links to (or
  give `--from`, `--subject`, `--domain`, `--message-id`), in the mailboxes
  named by `--mailbox` or `--mailboxes FILE`. Each copy is listed with its
  folder, whether it was read and whether the mailbox's owner replied in its
  thread; JSON and CSV too. Read-only like `graph` and `gmail`: GET requests
  only, the token from `PHISHHAWK_GRAPH_TOKEN` or `PHISHHAWK_GMAIL_TOKEN` and
  only to the API's host. Every hit is checked against what was asked before
  it counts; a platform's customer is searched by its host, never the whole
  platform; "replied" means mail sent to the copy's sender or reply-to
  address, not a forward to the SOC. One failed search marks its mailbox
  incomplete without losing the rest. Exit 1 when copies are found, 3 when a
  mailbox could not be searched fully.
- **An authentication block in every report**: pass, fail or unknown for the
  domain the reader sees in From; which domain SPF, DKIM and DMARC each
  vouched for and whether it is aligned with From; the Reply-To and
  Return-Path organisations; and plain sentences to paste into a ticket
  ("SPF passed for a bulk mailer's bounce domain: it vouches for the bounce
  address, not the sender the reader sees"). The receiver's DMARC result
  always wins. In JSON as `authentication` and, per check, `auth_checks`.
  Explanation only: no signal or verdict changes.
- **Evidence.** Every report names the SHA-256 and size of the
  bytes it analysed (for a reported message, the report as it arrived), in
  JSON as `evidence`. `--evidence DIR` keeps each message there, read-only and
  named by its SHA-256, and appends a hash-chained record to
  `DIR/custody.jsonl` (SHA-256, size, source, time, analyst, tool version, verdict);
  the report carries the record's chain value. `phishhawk evidence verify DIR`
  finds a record changed, removed or reordered and a kept message changed or
  missing; with `--head`, a log rewritten after the head you recorded.
- **`--sandbox DIR`** writes, per message, a ZIP for your sandbox: the message
  as read, every file pulled out of it (archive members included), the links
  to detonate and a manifest, every member encrypted with the password
  `infected`. Nothing is sent anywhere.
- **CI** audits every dependency PhishHawk installs with pip-audit and
  searches every commit for secrets with gitleaks.
- 641 tests (2.1: 528), including one for every finding of the reviews that
  fails on the old code.

### Fixed

- Without `--psl`, every site under a country registry's second-level name
  (`com.ar`, `gob.ar`, `co.th`, `ne.jp`, `or.at`, `gouv.fr` and the like) was
  one organisation named after the registry: lookalike checks read
  `paypal-login.com.ar` as `com`. Common registry names under a two-letter
  country code are now suffixes. Found by campaign correlation. On held-out
  data this moved three 2005 phishing emails from senders on `paypal.co.us`,
  `ebay.co.us` and `xbox.com.bo` from suspicious to not flagged (Nazario's
  corpus 56.9% → 56.7%): they now get 2.1's allowance for a brand's own
  country domain, as `paypal.us` did.
- Exchange Online's Authentication-Results header has no authserv-id; its
  first check's domain is now read too.
- `scan --json` crashed on a file whose name is not UTF-8; such bytes are now
  written as `\xNN` escapes.

### Security

Found by a fourth security review, an independent code review, mutation
testing of every new module, a regular-expression scan and fuzzing; the full list is in
[docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) (#53 to #61).

- `graph`, `gmail` (also in 2.1) and `sweep` kept paging for ever when an API
  offered empty page after empty page: every listing stops after 100 pages.
- `sweep` refuses a mailbox that is not an address, user id or GUID (`..`,
  `a/b`) before anything is sent for it.
- The new authentication-check pattern was quadratic when searched from
  every position; clauses are now matched at their start.
- Before release, the independent review also found `sweep --like`
  searching whole platform zones (legitimate mail could have been listed as
  copies and purged), one failed request discarding a mailbox's results,
  forwards to the SOC counted as replies, campaigns merged through IPFS
  gateways and shared forms, and `evidence verify` unable to catch a
  rewritten log. All are fixed.
- Fuzzing found no crash and no hang: 362,634 runs before the independent
  review's fixes, 147,461 after them and 148,311 on the released code, with
  the new modules added to the pipeline target. Its only findings were 2 to 3
  MB garbage `--psl` files taking about 5 s to load, which is linear in size
  and only ever the analyst's own file.

## [2.1.0] - 2026-10-05

PhishHawk now weighs independent evidence instead of counting high-severity
signals: a lookalike sender that also links to a raw IP is likely phishing even
when only one of them is high. It decompresses 7z attachments, reads RAR's
stored files, opens VHD and VHDX disk images down to their FAT and NTFS
volumes, and reads report mailboxes through Microsoft Graph and the Gmail API
where IMAP is switched off. The 2.0 false positives found in its own
evaluation are fixed. On held-out real mail, scored once after all tuning:
81.3% of 5,714 phishing emails from 2022 to 2026 flagged (2.0: 79.9%), and
46.9% called likely phishing (2.0: 30.5%), while false positives fell to 0.8%
of 5,945 legitimate emails (2.0: 0.9%). No field was removed from the JSON
report; `report_version` stays `2.0`.

### Added

- **`phishhawk graph` and `phishhawk gmail`** triage a Microsoft 365 or Gmail
  mailbox through its API, read-only: only `GET` requests, so nothing is marked
  read, moved or deleted. `--mailbox`, `--folder` (Graph) or `--label` and
  `--query` (Gmail), `--since`, `--unread`, `--limit`, `--out` and `--watch`,
  like `phishhawk imap`. The access token comes from `PHISHHAWK_GRAPH_TOKEN` or
  `PHISHHAWK_GMAIL_TOKEN`, travels only in the `Authorization` header and is
  never sent off the API's own host; a refused token is reported with the
  permission it needs (`Mail.Read`, `gmail.readonly`).
- **7z members are decompressed in memory**: LZMA, LZMA2, Deflate, BZip2 and
  stored folders, behind x86, ARM, PowerPC, IA-64 and SPARC branch filters or a
  delta filter, up to 64 MB per archive within the message's budget. Every
  member is then inspected like an attachment. Encrypted folders are listed
  only.
- **RAR's stored members are read** (RAR 4 and 5). RAR's compression is
  proprietary, so compressed members are still listed from the headers.
- **VHD and VHDX disk images are opened**: fixed, dynamic and differencing VHD,
  and VHDX; MBR and GPT partitions, or a disk with no partition table; FAT12,
  FAT16 and **FAT32** volumes (FAT images mailed on their own gain FAT32 too);
  and **NTFS** volumes through the master file table. A block table pointing
  every entry at one block, sixteen partitions naming one volume or a file made
  of holes costs no more than the disk's budget.
- **`--psl FILE`**: a copy of the Public Suffix List, used instead of the
  built-in approximation, so a lookalike on shared hosting
  (`paypal-billing.github.io`) is judged as its own domain. Also
  `public_suffix_list` in the config file and `PHISHHAWK_PSL`; `phishhawk
  doctor` loads it and shows its rule count.
- **Signal families.** Every signal says what part of the message it is about
  (`auth`, `sender`, `link`, `attachment`, `content`, `evasion`, `intel`,
  `policy`), in the JSON report as `signals[].family` and in the schema.
- New signals: a From address that is a whole address in quotes with no
  domain of its own (`<"service@adac.de">`), or a quoted address in front of
  the real domain; a sender on free web hosting (`x.firebaseapp.com`).
- 53 more brands (187 in all), among them Temu, SHEIN, the US Social Security
  Administration, Banco do Brasil, Receita Federal, Mercado Pago, Lidl, IKEA,
  Deutsche Bahn, Klarna, N26, the Exodus and Electrum wallets, crypto
  exchanges (OKX, Bitget, Bitpanda, Crypto.com) and national post offices. Lure
  phrases in Dutch and Italian, and more in German, Portuguese, Spanish and
  French (268 phrases in seven languages).
- 528 tests (2.0: 403), including one for every finding of the security and
  code reviews that fails on the old code, and `phishhawk doctor` reports the
  Public Suffix List in use.

### Changed

- **Independent evidence decides `LIKELY PHISHING`.** Besides two high signals,
  or one with a score of 8: one high signal backed by a medium or high signal
  from another family, or medium signals from three families with a score of 8.
  DKIM and DMARC failing together are one finding, not two.
- **Weak findings of one kind count once.** A newsletter's links to a dozen
  sign-in pages add one point, not three; low signals still add at most three.
- A brand's own name on a country domain (`paypal.de`, `amazon.co.jp`,
  `lidl.fr`) is not an impersonation, unless the TLD is sold as a generic one
  (`.co`, `.io`) or is a high-abuse one.
- The HTML report explains which rule decided the verdict, and its score ring
  counts low signals one per kind.

### Fixed

The false positives found in 2.0's own evaluation:

- A Russian (or any non-Latin) display name typed with one Latin letter is a
  typo, not a disguise; words that pass for Latin with borrowed letters
  (`МеtaМask`, Cherokee `Ꮮеdgеr`) are still flagged.
- A subject in another charset decoded as Latin-1 (soft hyphens between
  symbols) is not filter evasion; soft hyphens and zero-width characters inside
  a word still are.
- Free-mail domains in any country (`yahoo.com.tw`, `hotmail.fr`) and the
  documentation domains `example.com`, `.net` and `.org` are never guessed as
  the recipient's own domain.
- A sign-in word in the address of an image or a style sheet is not a
  credential-harvesting link.

### Security

Found by a third security review, an independent code review and fuzzing of
the new readers; the full list is in
[docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) (#30 to #52).

- Messages attached inside messages, which all share the name
  `attached-message.eml`, no longer loop the console and HTML reports or blow
  the HTML report up exponentially (in 2.0 they raised `RecursionError`).
- A `Received` date with a year too large for C no longer ends the analysis
  with `OverflowError` (also in 2.0).
- A MIME parameter whose name is longer than a line no longer hangs the
  analysis for ever inside Python's header folding (also in 2.0, on recent
  Python patch releases): headers are written back exactly as they came in.
- A damaged partition no longer hides the files of the others on a disk image.
- Decompression bombs and amplifiers in the new readers are defused: a 7z
  folder declaring 0 bytes, folders that break off near their end, repeated
  header sections, RAR5 headers reaching back over the archive, and many
  small containers in one message. Every archive and disk image of a message
  shares one 256 MB budget.
- One torn NTFS record no longer hides its volume; sparse files, 4K-sector
  disks and NTFS on 4096-byte sectors are read.
- `graph` and `gmail`: a download that breaks off, or a throttled message, is
  asked for again on the next `--watch` round instead of ending it or being
  dropped; a round looks at the newest `--limit` messages only; a malformed
  token is refused without being echoed; `--unread` alone works with Graph;
  `--out` report names can no longer collide.
- Three quadratic patterns, new in this release, are linear (one only with
  `--psl`).
- The fuzzer itself sent most mail to the wrong reader in 2.0; it now fuzzes
  the pipeline as intended. More than 1.5 million runs in four rounds over the
  new readers and the whole pipeline found #32 to #34 and #52; the last round,
  378,597 runs on the final code, found nothing.

## [2.0.0] - 2026-09-30

PhishHawk now reads nearly every format phish arrive in, finds the evasions
built to get past mail filters, and fits into a SOC's workflow (IMAP, MISP,
a config file, YARA). It was then attacked as a target: fuzzed for 9.7 million
runs, scanned for regular-expression denial of service, and run on 19,917 real
messages through every report format. On held-out real mail, scored once after
all tuning: 79.9% of 5,714 phishing emails from 2022 to 2026 flagged (1.2.0:
75.4%), and 0.9% of 5,945 legitimate emails (1.2.0: 1.0%). No field was removed
from the JSON report; `report_version` starts at `2.0`.

### Added

- **Outlook `.msg` files**, read directly by a pure-Python compound-file
  reader: the message is rebuilt as the email it was sent as, with its original
  transport headers when Outlook kept them, its RTF body decompressed, and its
  attachments and attached messages. Folders pick up `.msg` files too.
- **`phishhawk imap`** triages a mailbox folder, such as a shared "report
  phishing" mailbox, read-only (`EXAMINE` and `BODY.PEEK`): `--unseen`,
  `--since`, `--limit`, `--out DIR` for a report per message, and `--watch
  SECONDS` to keep going. Password from `PHISHHAWK_IMAP_PASSWORD` or a prompt,
  or an OAuth token (`XOAUTH2`) for Microsoft 365 and Gmail.
- **Every file is opened in memory, and nothing is run.** RAR (4 and 5) and 7z
  are listed, including 7z headers packed with LZMA or LZMA2, and archives that
  encrypt even their file names are flagged. ISO 9660 and FAT disk images are
  opened (their files lose the Mark of the Web). gzip, tar and `winmail.dat`
  are unpacked. A password-protected ZIP is opened when the message gives the
  password. Office files are read for VBA and Excel 4.0 macros, DDE fields,
  remote templates and frames, Follina-style protocol handlers, ActiveX and
  embedded packages; PDFs for launch actions, JavaScript, embedded files and
  forms; RTF for Equation Editor and other exploit objects, remote templates
  and packages; OneNote sections for embedded payloads; shortcuts (`.lnk`) for
  command interpreters, encoded PowerShell, downloads and padded command lines;
  SVG images for script. Files inside files are checked down to three levels.
- **QR-code phishing.** With the optional extra (`pip install
  'phishhawk[qr]'`), QR codes are decoded in image attachments, inline images,
  images embedded as `data:` URIs, images inside PDFs and codes drawn with HTML
  table cells or block characters. `--no-qr` turns decoding off.
- **Calendar invitations** (`.ics` files, `text/calendar` parts): organiser,
  links and attachments; an organiser who is not the sender is flagged.
- **Filter evasion:** text hidden with CSS to break up words or to feed filters
  filler, words split by tags one letter at a time, styled Unicode and
  invisible characters in the subject, mixed alphabets inside a word, brand
  names spelled with look-alike characters (`PayPaI`, `Amaz0n`, `Iedger`),
  IP addresses written as one number (`http://3232235777/`), IPv6 hosts,
  `javascript:` and `data:` links, MIME nested past any mail client, and floods
  of links past the 1,000 checked.
- **Sender and money:** a brand's own domain in the From line without the
  authentication to back it (a forged sender); links that download runnable
  files; business email compromise from a lookalike of your own domain
  (T1657); crypto wallets (Bitcoin, Litecoin and TRON checksum-verified,
  Ethereum and Monero by shape) and payment demands; callback numbers.
  Crypto-wallet recovery and casino lures, 68 more brands (134 in all), and
  11 more ATT&CK techniques (29 in all).
- **Exports and workflow:** `--misp` writes a MISP event per message, with
  ATT&CK galaxy tags and a TLP tag (`--tlp`). A config file
  (`~/.config/phishhawk/config.toml`, never read from the current folder) holds
  your domains, partners, block list, own brands and lure phrases. `--allow`
  and `--block` for partners and known-bad domains, `--yara` for your YARA rules
  (`pip install 'phishhawk[yara]'`), `--fail-on` for pipelines,
  `--trusted-authserv` to name your mail server, `--max-size`, and `.mbox`
  input.
- **Reports** show the mail path (every Received hop, with delays), QR codes,
  calendar invitations, payment and callback details, YARA matches and forged
  authentication results. Indicators now include IPv6 addresses, crypto wallets
  and phone numbers; MISP gets the sending IP as `ip-src`.
- [`docs/report.schema.json`](docs/report.schema.json), a JSON Schema for the
  JSON report; [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md); a release
  workflow that builds, checks and publishes the package when a release is
  published; `eval/fetch_fresh.py` for the new held-out sets.
- 403 tests, including Hypothesis property tests, a test for every finding of
  the security review, type checking with mypy, and a coverage gate (89%).

### Changed

- **Evaluation on more and fresher real mail.** Besides the 5,714 held-out
  phishing_pot emails, four sets never looked at while developing: 2,279
  phishing emails from 2005 to 2007 (57.7% flagged; 1.2.0: 54.7%), 4,279 Enron
  emails (0.2% false positives, as before), 136 mail-library edge cases (11.0%;
  1.2.0: 9.6%, two more) and five `.msg` files. Every year from 2022 to 2026
  improved. See [eval/README.md](eval/README.md).
- Two low-severity checks were removed because they fired more often on
  legitimate mail than on phishing: a Return-Path that differs from the sender
  (59% of legitimate mail, 16% of phishing) and a message with no links.
- A message keeps at most 1,000 distinct links; a flood past that is a medium
  signal (it replaces the 1.x check that stopped at 5,000 hosts).
- A `javascript:` link is medium, a `data:text/html` link high. A TLD swap of a
  brand that is an ordinary word, and a brand word in the subdomain of an
  otherwise unremarkable site, are low.
- With `--no-unwrap`, the covering note is analysed without opening the email
  attached to it, as documented. Otherwise, emails attached below the three
  unwrapped layers, or beside the one unwrapped, are opened and checked.

### Security

The full list, with each fix and its test, is in
[docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md).

- Control characters from a message no longer reach the terminal; right-to-left
  overrides are shown as `<U+202E>`. The Markdown note escapes Markdown and HTML
  and defangs bare URLs. No report shows a live attacker link, including those
  inside QR codes, shortcuts, remote templates and calendar invitations.
- A phish that carries a harmless attached message is no longer analysed as the
  attachment alone. Only the receiving server's `Authentication-Results` are
  believed; a pass forged further down is flagged.
- Named pipes, device files and oversized messages are skipped instead of
  hanging a batch. The lookup cache is private to its owner. `--urlscan-submit`
  replaces your recipients' addresses before submitting a URL.
- A header can no longer turn a verdict into an error: charset names that make
  Python's email package raise (a NUL byte, `idna`, `undefined`), address
  headers with thousands of colons, and MIME nested a thousand levels deep are
  all handled. Headers built to stall the parser (a `To:` of 50,000 quotes took
  49 s) are kept as text.
- Memory and time bombs are defused: disk images and `.msg` files whose entries
  share the same bytes (9.6 GB and 7.2 GB before), Office files of parts that
  each inflate to 8 MB, a 7z header asking for a 4 GB dictionary, quadratic
  regular expressions, and a 1.4 MB "link" of NUL bytes.
- Four evasions by structure are closed: a message that is only
  `message/rfc822`, an email attached deeper than the unwrapping, a second
  attached email behind a harmless one, and a multipart part without a boundary.

### Fixed

- Lookalikes that spell a domain into the name (`paypal-com.top`,
  `www-paypal.com`, `paypalcom.top`) or split it with a hyphen (`micros-oft.com`)
  are found; MFA, SSO, VPN and Microsoft 365 words count in combosquats.
- A malformed header such as a broken `Message-Id` no longer erases the SPF,
  DKIM and DMARC results; `Authentication-Results` sent as base64 encoded words
  (Microsoft 365) are decoded.
- A quoted From address (`"service@brand.de"`) keeps no stray quote in its
  domain.
- The slowest real messages are faster: a 50,000-link message takes 3 s instead
  of 31 s, PDF images with PNG predictors go through Pillow (2 s to 0.45 s), and
  the address search no longer crawls through base64 bodies (1.7 s to 0.3 s).
- `scan --help` had a garbled example.

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

[Unreleased]: https://github.com/vinitrami-Soc/phishhawk/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v2.1.0
[2.0.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v2.0.0
[1.2.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.2.0
[1.1.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.1.0
[1.0.1]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.0.1
[1.0.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.0.0
