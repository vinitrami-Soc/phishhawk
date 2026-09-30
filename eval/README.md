# Evaluating PhishHawk

Detection numbers mean little without saying what they were measured on. All
runs below are **offline** (no reputation lookups), so they measure the parser
and heuristics alone. With VirusTotal, RDAP and AbuseIPDB enabled the
detection rate can only go up.

"Flagged" means a verdict of `SUSPICIOUS` or worse, the point at which a
human should look. "Strict" means `LIKELY PHISHING` or worse.

## Results

| Data set | Emails | Flagged recall | Strict recall | False-positive rate |
|---|---|---|---|---|
| Real phishing, **held out**, 2022 to 2026 (phishing_pot at `49f6377`, seed 2027) | 5,714 | **78.5%** | 28.1% | n/a |
| Real phishing, tuning part of the same split | 2,500 | 78.5% | 26.7% | n/a |
| Real phishing, earlier **held-out** sample (phishing_pot, seed 7) | 200 | 72.5% | 25.0% | n/a |
| Real phishing, earlier tuning sample (phishing_pot, seed 42) | 200 | 82.0% | 24.0% | n/a |
| Real legitimate mail, **held out**: SpamAssassin `easy_ham_2` | 1,400 | n/a | n/a | **0.7%** (10/1,400) |
| Real legitimate mail, **held out**: SpamAssassin `hard_ham`, seeded half | 125 | n/a | n/a | 23.2% (29/125) |
| Real legitimate mail, tuning set: `easy_ham` + the other half of `hard_ham` | 2,625 | n/a | n/a | 1.4% (36/2,625) |
| Legitimate edge-case mail (CPython `test_email` corpus) | 48 | n/a | n/a | 0% (0/48) |
| Synthetic labelled corpus (`make_corpus.py`, seed 7) | 102 phish + 65 legit | 100% | 59.8% | 0.0% |

*n/a* means the measure does not apply: a set of only phishing has no legitimate
mail to flag by mistake, and a set of only legitimate mail has no phishing to catch.

PhishHawk 1.2.0 scored 75.4% (25.8% strict) on the 5,714 held-out emails,
75.2% on the 2,500 tuning emails, 70.5% on the earlier held-out sample and
80.0% on the earlier tuning sample, with exactly the same false positives as
now. Before the first real-mail evaluation, the code scored 70.0% on the
earlier held-out phishing, 75.0% on the earlier tuning phishing and 12.5%
false positives on the CPython corpus, and its worst-case parse took 60
seconds. Before the legitimate-mail evaluation, PhishHawk 1.1.0 flagged
**23.3%** of `easy_ham_2` (326/1,400) and **55.2%** of the held-out
`hard_ham` (69/125). The slowest of all 12,979 messages now takes 1.4 seconds.

## The 2026 evaluation: every phishing_pot email

The first evaluation used two samples of 200. For 1.3.0 the whole
[phishing_pot](https://github.com/rf-peixoto/phishing_pot) corpus was used,
pinned at commit `49f6377`: 8,614 emails, almost all sent between 2022 and
2026. The 400 of the first evaluation were set aside; the other 8,214 were
shuffled with `random.Random(2027)` and cut into 2,500 for tuning and 5,714
held out. The sample numbers of each part are in
[splits/phishing_pot_2026.json](splits/phishing_pot_2026.json), so the split
can be rebuilt exactly.

New detections were developed against the tuning part only: crypto-wallet
lures (seed phrases, "validate your wallet", airdrops), casino "free spins"
lures in five languages, Ledger as a brand, typosquats split by hyphens
(`micros-oft`) and MFA or remote-access words in combosquats. Each was checked
against the legitimate tuning mail as it went in; one (`casino` as a lure
word) was dropped for a false positive. The held-out part was then scored
once, with 1.2.0 and with the new code:

| Year sent | Emails | 1.2.0 | Now |
|---|---|---|---|
| 2022 | 146 | 65.1% | 67.8% |
| 2023 | 1,425 | 72.6% | 74.2% |
| 2024 | 1,431 | 83.3% | 85.8% |
| 2025 | 1,338 | 74.9% | 79.5% |
| 2026 | 1,307 | 71.0% | 74.6% |
| **All 5,714** | 5,714 | 75.4% | **78.5%** |

The year is read from the `Date:` header; 67 emails have none that parses or
one outside 2022 to 2026, and are counted only in the total. Message by
message, 172 held-out emails are flagged now that were not, none that were
are lost, and in every legitimate set exactly the same messages are flagged
as with 1.2.0.

**QR codes.** Two held-out emails carry a QR code, one as a `data:` image in
the HTML and one inside a PDF, and both are decoded; one tuning email has a
code whose payload is not a link. Quishing is rarer in this honeypot than in
the reports, so the QR detections are tested on their own in
[tests/test_qr.py](../tests/test_qr.py): eleven hiding places, hostile images
and PDFs written by real software.

**Parser bugs.** Scanning 12,979 real messages found two that no synthetic
test had: a malformed `Message-Id` header made Python's `email` library raise
while listing headers, which erased the SPF, DKIM and DMARC results; and
Microsoft 365 sends some `Authentication-Results` headers as base64 encoded
words, so headers are now read raw and decoded one at a time. Both have
tests in `tests/test_security.py`.

**Spam is not phishing.** For information, 31.3% of SpamAssassin's 2002 spam
is flagged. PhishHawk looks for credential theft, malware and impersonation,
not for unsolicited offers, so this number is expected to stay low.

## How to read these numbers

* **The held-out number is the honest one.** Detections were developed while
  looking at the tuning part only. The held-out part, disjoint from it, was
  scored once at the end. On 200-email samples the gap between the two was
  large (82% vs 72.5%); with 2,500 and 5,714 emails it is gone (78.5% both),
  which says the small samples were noisy rather than that tuning overfitted.
* **phishing_pot is a honeypot**, so its "phishing" label includes a lot of
  generic spam: casino offers, diet pills, loan consolidation, crypto
  "mining balance" lures. A sample of the held-out misses is mostly that.
  PhishHawk targets credential theft, malware delivery, impersonation and
  BEC, where it does much better than the headline figure.
* **Many honeypot samples are forwards** (`Fwd:`, `ENC:`) whose original
  headers the collector replaced with `phishing@pot`. That removes the
  sender and authentication evidence PhishHawk relies on.
* **The synthetic corpus is a regression gate, not a benchmark.** It was
  written by the same person as the detectors, so 100% is by construction.
  Its value is the 65 legitimate messages that look risky (genuine "unusual
  sign-in" alerts, newsletters with bounce domains, password resets,
  Safe-Links-wrapped internal mail, Drive shares, Hindi text with zero-width
  joiners). None may be flagged. CI fails if recall drops below 95% or false
  positives rise above 2%.
* **48 test messages were not a false-positive benchmark.** The CPython corpus
  is MIME edge cases; its 2.1% hid a 23% false-positive rate on ordinary mail.
  The SpamAssassin ham (below) is the benchmark now.
* **`hard_ham` is legitimate mail chosen because it looks like spam**:
  commercial newsletters, offers, mailing-list digests. It is the hardest
  legitimate mail there is for a phishing detector, and about one in four is
  still flagged.
* **The SpamAssassin mail is from 2002.** It has no DKIM, DMARC or
  `Authentication-Results`, so it cannot test those checks; it does test
  everything else, and mailing lists, newsletters and click trackers have not
  changed much. No public corpus of recent legitimate mail exists: to measure
  false positives on today's newsletters and SaaS notifications, run your own
  mail through `run_eval.py --benign`, which reads `.mbox` exports and prints
  only totals.

## False positives on real legitimate mail

The [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)
has 4,150 real legitimate emails with full headers. `fetch_spamassassin.py`
splits them before anything is looked at:

| Set | Messages | Used for |
|---|---|---|
| `tune/easy`: `easy_ham` | 2,500 | Finding and fixing the causes of false positives |
| `tune/hard`: half of `hard_ham` (seed 2026) | 125 | Same |
| `holdout/easy`: `easy_ham_2`, collected later | 1,400 | Scored once, at the end |
| `holdout/hard`: the other half of `hard_ham` | 125 | Scored once, at the end |

On the tuning set, 1.1.0 flagged 644 of 2,625 messages. Six rules caused
almost all of it; each fix was checked against the phishing tuning sample so
that recall was not traded away silently:

| Cause on legitimate mail | Fix |
|---|---|
| A mailing list sets Reply-To to its own address, which was scored as high-severity reply diversion (77% of the false positives) | List mail (`List-Post`, `Mailing-List`, `X-Mailing-List`, `X-BeenThere`, `Precedence: list`) whose Reply-To is the list's own domain scores low; other list mail medium. `List-Id` and `Precedence: bulk` do not count: the bulk services phishers rent set them |
| Newsletters show their site and link through a click tracker, scored as a high link mismatch, once per link | High only when the text shows a brand, government, free-mail or your own domain, or the destination is suspect; otherwise medium, once per destination |
| An email address in link text ("sent to you@...") read as a claimed website | Ignored |
| Any name inside another read as a combosquat: `linuxmafia.com` as your own `linux.ie`, `shagmail.com` as Gmail, `yahoogroups.com` as Yahoo | A combosquat must add only lure or business words, digits or a short code (`outlooksecure`, `paypal-billing`, `example-corp-payroll`) |
| A brand's country site (`yahoo.co.uk`) and a brand word in a subdomain (`outlook.4team.biz`) | Country sites of a brand are its own; a brand subdomain is high only with its whole domain spelled out, a high-abuse TLD, free hosting or a credential word |
| No `Authentication-Results` header scored as a weak signal | Not scored: the header is missing from exported and older mail, phishing or not |

After the fixes the tuning set dropped to 36 of 2,625. Phishing recall on the
tuning sample went from 81% to 80%: one lost message had been flagged only
because `storage.googleapis.com` was wrongly called a Google lookalike, the
other is a prize spam sent through a genuine newsletter service.

The held-out sets were then scored once: 10 of 1,400 everyday messages and
29 of 125 spam-like ones flagged, 39 of 1,525 in all.

## What the evaluation changed

Running real mail through the tool found problems that no hand-written test
had:

| Found | Fix |
|---|---|
| A 100 KB base64 image in an HTML body made the address regex quadratic: one message took **60 s** | Bounded quantifiers on every regex that sees message bodies; visible text taken from the HTML parser instead of regex tag-stripping |
| Three weak signals (no auth header, bounce domain, no links) added up to `SUSPICIOUS` on ordinary mail | Low-severity signals now contribute at most 3 points; `SUSPICIOUS` needs a high signal or a score of 4 |
| `T h e  I d e n t i t y  o f  y o u r  w a l l e t` letter-spacing to dodge keyword filters | Lure phrases also match with whitespace squeezed out; the spacing itself is a signal |
| Phish reported with a normal Forward rather than as an attachment | The original `From:` is recovered from the forwarded header block, in several languages |
| `Trust-Wallet` in a display name slipping past a `trustwallet` brand check | Brand checks ignore punctuation and spaces |
| Links through `google.com/amp/s/`, Bing `/ck/a` and Microsoft Safe Links | Gateways (Safe Links, Proofpoint, Barracuda) are unwrapped; open redirects on trusted domains are decoded and flagged |
| Links inside compressed PDF object streams were invisible | Flate streams are inflated, with a 20 MB output cap against PDF bombs |

## Reproduce

```bash
python eval/run_eval.py --synthetic                  # the regression gate, about 1 second
python eval/fetch_phishing_pot.py /tmp/pot           # partial clone + the two seeded samples
python eval/run_eval.py --phish /tmp/pot/holdout
python eval/fetch_phishing_pot.py /tmp/pot --full    # the 2026 split, every message (about an hour)
python eval/run_eval.py --phish /tmp/pot/pot2026/holdout
python eval/fetch_spamassassin.py /tmp/ham           # 4,150 legitimate emails, split as above
python eval/run_eval.py --benign /tmp/ham/holdout/easy --benign /tmp/ham/holdout/hard
python eval/run_eval.py --phish DIR --benign DIR     # your own labelled mail
python eval/run_eval.py --benign ~/Takeout/Inbox.mbox  # your own mail as an .mbox export
```

Add `--json` for machine-readable results. To check false positives against
your own organisation's mail, export a few hundred legitimate messages as `.eml`
files or one `.mbox` and pass it with `--benign`. Only totals are printed;
nothing leaves the machine.

## Data sources

* **phishing_pot** by rf-peixoto, real phishing collected by honeypots,
  licensed CC BY-NC 4.0, at commit `49f6377`. It is used here for
  non-commercial evaluation only; no samples are redistributed in this
  repository, only their numbers in `splits/`.
* **SpamAssassin public corpus** (Apache SpamAssassin project), the
  `easy_ham`, `easy_ham_2` and `hard_ham` folders of 2003-02-28: real
  legitimate mail from 2002. `fetch_spamassassin.py` downloads it from
  spamassassin.apache.org, or from the `@stdlib/datasets-spam-assassin` npm
  package (Apache-2.0), which ships the same files; every file is checked
  against the MD5 in its name (one, `hard_ham/00230`, does not match in the npm
  copy; the official download could not be checked from where this ran). No messages are redistributed in this repository.
* **CPython `Lib/test/test_email/data`**, the Python standard library's email
  test messages (PSF licence), used as legitimate and edge-case MIME.
* **`make_corpus.py`**, synthetic, generated deterministically.
