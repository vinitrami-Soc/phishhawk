# Automated Phishing IOC Extractor

A single-file Python tool that takes a reported phishing email (`.eml`) and does
the first ten minutes of L1 triage automatically: pull the sender and header
facts, every URL, every attachment hash, run them past VirusTotal and
urlscan.io, and print a verdict you can paste straight into the ticket.

No dependencies beyond `requests`, and even that is only needed when you turn
enrichment on — `--offline` runs on a stock Python 3.9+ install (developed and
tested on 3.11).

```
$ export VT_API_KEY=...            # free key; without one the heuristics still run
$ python phishing_ioc_extractor.py samples/sample_phish.eml
...
  6 URLs found, 1 flagged as malicious by VirusTotal.
  1 attachment found, 1 flagged as malicious by VirusTotal.
  Verdict: MALICIOUS  (risk score 37)
  Next step: escalate to L2, block the sender domain and URLs, hunt for other recipients
```

## What it extracts

| Area | Pulled out of the message |
|---|---|
| Sender | display name, From, Reply-To, Return-Path and the domain of each |
| Authentication | SPF / DKIM / DMARC from `Authentication-Results`, with `Received-SPF` fallback |
| Routing | originating public IP from the `Received` chain (private hops are skipped), hop count |
| URLs | plain-text body, HTML `href`, `src`/`action`/`background`, `meta refresh`, and `List-Unsubscribe` |
| Attachments | filename, MIME type, size, MD5, SHA1, SHA256 |
| Body | email addresses referenced in the content |

Defanged input (`hxxps://evil[.]com`) is refanged before parsing, and everything
printed back out is defanged again so the report is safe to paste anywhere.

## Detection without an API key

The API lookups are the bonus round. Most of what closes a phishing ticket comes
from the message itself, so these heuristics run every time, offline:

- **Reply-To / Return-Path mismatch** against the From domain
- **Brand impersonation** — display name says "Microsoft" but the domain does not
- **Link text vs href mismatch** — the anchor shows `login.microsoftonline.com`,
  the `href` goes somewhere else. The single highest-signal check in the tool
- **Raw-IP URLs**, **punycode hosts** (homograph attacks), **`@` userinfo tricks**
- **URL shorteners** and **high-abuse TLDs** (`.top`, `.xyz`, `.zip`, …)
- **Credential-themed paths** (`/login`, `/verify`, `/o365/…`)
- **Risky attachments** — `.html`, `.hta`, `.js`, `.iso`, `.lnk`, macro-enabled
  Office formats — plus **double extensions** (`invoice.pdf.html`) and
  RTL-override filename tricks
- **Failed SPF/DKIM/DMARC** and urgency wording in the subject

Each signal carries a severity; the weighted total becomes the risk score and
the verdict (`NO STRONG INDICATORS` → `SUSPICIOUS` → `LIKELY PHISHING` →
`MALICIOUS`). Any VirusTotal malicious hit overrides the score and forces
`MALICIOUS`.

## Install

```bash
git clone https://github.com/vinitrami-Soc/vinitrami-Soc.github.io.git
cd vinitrami-Soc.github.io/phishing-ioc-extractor
pip install -r requirements.txt        # only needed for VT / urlscan lookups
```

## Usage

```bash
# Offline — header, URL and hash extraction only, no network at all
python phishing_ioc_extractor.py suspicious.eml --offline

# With VirusTotal (free API key: https://www.virustotal.com/gui/my-apikey)
export VT_API_KEY=your_key_here
python phishing_ioc_extractor.py suspicious.eml

# Batch triage a folder of reported mail, one summary block each
python phishing_ioc_extractor.py reported/*.eml --quiet

# Machine-readable output for a SOAR playbook or a ticket attachment
python phishing_ioc_extractor.py suspicious.eml --json report.json
```

### Options worth knowing

| Flag | Effect |
|---|---|
| `--offline` | no network calls whatsoever |
| `--vt-key KEY` / `$VT_API_KEY` | VirusTotal key (also reads `$VIRUSTOTAL_API_KEY`) |
| `--vt-rate N` | VT lookups per minute, default `4` — the free tier ceiling |
| `--no-virustotal` / `--no-urlscan` | disable one source, keep the other |
| `--urlscan-key KEY` / `$URLSCAN_API_KEY` | urlscan.io key (only needed to submit) |
| `--urlscan-submit` | actively submit URLs as **unlisted** scans |
| `--quiet` | summary block only, good for batch runs |
| `--verbose` | print every heuristic signal, not just the first 15 |
| `--json PATH` | full structured report |

Exit codes: `0` nothing notable, `1` suspicious, `2` malicious, `3` error — so
it drops straight into a shell pipeline or a cron job.

## API behaviour, and what leaves your machine

This matters in a SOC, so it is explicit:

- **VirusTotal** is **lookup-only**. URLs are queried by their base64url ID and
  attachments by SHA256 — the file itself is **never uploaded**, so nothing
  confidential leaves the box. A `not_found` result simply means nobody has ever
  submitted that indicator.
- **urlscan.io search** is read-only and sends only the **hostname**. It runs by
  default because it needs no key; `--no-urlscan` or `--offline` turns it off.
- **`--urlscan-submit` is the one action that publishes.** It sends the full URL
  to urlscan.io to be scanned. It is off by default, needs an API key, and uses
  `visibility: unlisted`. Do not point it at a URL containing a token or a
  customer identifier.
- The free VirusTotal tier allows 4 lookups/minute, so the client paces itself
  with a sliding window and caches every result — a mail with the same URL
  twenty times costs one lookup. HTTP 429, 401 and 404 are all handled as data,
  not crashes: the report says "rate limited" or "no record" and carries on.

## Sample output

```
========================================================================
  PHISHING IOC EXTRACTION REPORT
========================================================================
File       : samples/sample_phish.eml
Subject    : Action required: unusual sign-in activity on your account

-- SENDER --------------------------------------------------------------
Display name : Microsoft Account Team
From         : security-alert@micros0ft-verify-support[.]top
Reply-To     : recovery[.]desk@mail-secure-recovery[.]xyz
Originating  : 185[.]243[.]115[.]22  (2 Received hop(s))
Auth         : spf=fail  dkim=none  dmarc=fail

-- URLS (6) ------------------------------------------------------------
 ![1] hxxps://micros0ft-verify-support[.]top/o365/login?id=8841
      host: micros0ft-verify-support[.]top   seen in: body-text, html-href
      ! high-abuse TLD .top
      ! credential-themed path (login)
      ! link text shows login[.]microsoftonline[.]com but href goes to micros0ft-verify-support[.]top
      VT: 7/74 malicious, 2 suspicious  (last scan 2026-09-16 04:20 UTC)  [MALICIOUS]
      urlscan: 12 prior scan(s), 9 with malicious verdicts
 ![2] hxxps://bit[.]ly/3xQvErT
      host: bit[.]ly   seen in: body-text, html-href
      ! URL shortener
      VT: 0/72 malicious  [clean]

-- ATTACHMENTS (1) -----------------------------------------------------
  Voicemail_Transcript.pdf.html   text/html   443 B
      MD5    : 3d856321ec38c3f4a939aa7808eba61b
      SHA256 : a0c7bd13598a8b2e9701a37a60c048038cff3a5293504d77d1708045727690cf
      ! high-risk extension .html
      ! double extension
      VT: 8/63 malicious  [MALICIOUS]

-- SUMMARY -------------------------------------------------------------
  6 URLs found, 1 flagged as malicious by VirusTotal.
  1 attachment found, 1 flagged as malicious by VirusTotal.
  Verdict: MALICIOUS  (risk score 37)
  Next step: escalate to L2, block the sender domain and URLs, hunt for other recipients
========================================================================
```

The VirusTotal and urlscan lines above show what a keyed run looks like; without
a key those lines read `VT: not queried` and the verdict falls back to the
heuristic score (`LIKELY PHISHING` for this sample).

## Samples and tests

`samples/` holds two inert fixtures — `sample_phish.eml` (spoofed Microsoft
alert, failing SPF/DKIM/DMARC, mismatched anchor, shortener, raw-IP link and a
`.pdf.html` attachment) and `sample_benign.eml` (a clean invoice notice, used to
check the tool does not cry wolf). Both are generated by
`samples/make_samples.py`; the fake domains resolve nowhere and the attachment
contains no script or form.

```bash
python -m unittest discover -s tests -v
```

27 tests, all offline — the VirusTotal and urlscan clients are exercised through
fake sessions, so the suite never touches the network and never needs a key.

## Limitations

- Attachments are hashed, not opened. A `.zip` or `.docm` is flagged on its
  extension; the tool does not unpack archives or extract macros.
- `registrable_domain()` approximates the public suffix list from a small table
  of common multi-label TLDs — enough for triage, not for billing logic.
- VirusTotal results reflect what has already been submitted. A brand-new
  phishing URL will legitimately come back `not_found`; that is a data point
  (fresh infrastructure), not a clean bill of health.
- No sandbox detonation and no DNS/WHOIS enrichment yet — the obvious next step.

## Why this project

Phishing triage is the highest-volume ticket type on an L1 queue, and almost all
of it is mechanical: copy the headers, defang the links, hash the attachment,
check reputation, write the same summary. Automating that leaves the analyst
doing the part that actually needs judgement.

Built alongside my MSc dissertation on phishing detection.
