# Changelog

All notable changes to PhishHawk are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/): the command line, the exit codes and
the JSON and STIX output are the public interface.

## [Unreleased]

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

[Unreleased]: https://github.com/vinitrami-Soc/phishhawk/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.0.1
[1.0.0]: https://github.com/vinitrami-Soc/phishhawk/releases/tag/v1.0.0
