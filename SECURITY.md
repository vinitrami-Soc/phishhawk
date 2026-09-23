# Security policy

PhishHawk reads hostile input by design, so bugs in how it handles that input
matter. Thank you for reporting them responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Earlier prototypes (`phishtriage`, the single-file extractor) | No |

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/vinitrami-Soc/phishhawk/security/advisories/new).

Include:

- what an attacker can do, and under what conditions;
- a minimal reproducer. Build the message synthetically where possible, and never
  send live malware;
- the PhishHawk version (`phishhawk -V`), Python version and operating system.

You should get an acknowledgement within 7 days. Once the issue is confirmed, a
fix will be prepared in a private advisory and released as quickly as the
severity warrants, and you will be credited unless you prefer not to be.

## In scope

- Code execution, file writes or network access triggered by a crafted email or
  attachment.
- Denial of service: a message that makes parsing take far longer than
  linear time, or exhausts memory despite the archive and PDF caps.
- Script execution, network requests or clickable malicious links in the HTML
  report, despite its Content-Security-Policy and escaping.
- Formula injection through the CSV export.
- Data leaks: protected domains, message bodies, attachments or recipient
  addresses sent to a third-party service.
- Leaking API keys through output, reports, logs or the cache.

## Out of scope

- A phishing email that PhishHawk does not detect, or a false positive. These
  are detection-quality issues: please open a
  [detection report](https://github.com/vinitrami-Soc/phishhawk/issues/new/choose) instead.
- Vulnerabilities in VirusTotal, urlscan.io, RDAP servers or AbuseIPDB.
- Issues that need an attacker who can already change your PhishHawk
  installation, configuration or environment variables.

## Hardening tips for users

- Keep API keys in environment variables, not on the command line.
- Analyse untrusted mail inside the Docker image, which runs as a non-root user
  and supports `--network none` with a read-only mount.
- Use `--offline` for mail that must not leave your organisation.
