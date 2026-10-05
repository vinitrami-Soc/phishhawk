# Evaluating PhishHawk

Detection numbers mean little without saying what they were measured on. All
runs below are **offline** (no reputation lookups), so they measure the parser
and heuristics alone. With VirusTotal, RDAP and AbuseIPDB enabled the
detection rate can only go up.

"Flagged" means a verdict of `SUSPICIOUS` or worse, the point at which a
human should look. "Strict" means `LIKELY PHISHING` or worse.

## Results (PhishHawk 2.1.0)

| Data set | Emails | Flagged recall | Strict recall | False-positive rate |
|---|---|---|---|---|
| Real phishing, **held out**, 2022 to 2026 (phishing_pot at `49f6377`, seed 2027) | 5,714 | **81.3%** | **46.9%** | n/a |
| Real phishing, **held out**, 2005 to 2007 (Nazario's corpus) | 2,279 | 56.9% | 29.7% | n/a |
| Real phishing, earlier **held-out** sample (phishing_pot, seed 7) | 200 | 76.5% | 43.5% | n/a |
| Real phishing, tuning part of the 2022 to 2026 split | 2,500 | 82.2% | 46.6% | n/a |
| Real phishing, earlier tuning sample (phishing_pot, seed 42) | 200 | 83.0% | 37.5% | n/a |
| Real legitimate mail, **held out**: SpamAssassin `easy_ham_2` | 1,400 | n/a | n/a | **0.5%** (7/1,400) |
| Real legitimate mail, **held out**: SpamAssassin `hard_ham`, seeded half | 125 | n/a | n/a | 13.6% (17/125) |
| Real legitimate mail, **held out**: Enron | 4,279 | n/a | n/a | **0.2%** (10/4,279) |
| Legitimate edge cases, studied (see below): four mail libraries' test messages | 136 | n/a | n/a | 8.8% (12/136) |
| Outlook `.msg` files, **held out** | 5 | n/a | n/a | 0% (0/5) |
| Real legitimate mail, tuning set: `easy_ham` + the other half of `hard_ham` | 2,625 | n/a | n/a | 0.9% (23/2,625) |
| Legitimate edge-case mail (CPython `test_email` corpus) | 48 | n/a | n/a | 0% (0/48) |
| Synthetic labelled corpus (`make_corpus.py`, seed 7) | 102 phish + 65 legit | 100% | 71.6% | 0.0% |

*n/a* means the measure does not apply: a set of only phishing has no legitimate
mail to flag by mistake, and a set of only legitimate mail has no phishing to catch.

Every set was also scored with the released 2.0.0, on the same messages:

| Data set | 2.0.0 | 2.1.0 |
|---|---|---|
| Phishing 2022 to 2026, held out (5,714) | 79.9% flagged, 30.5% strict | **81.3%** flagged, **46.9%** strict |
| Phishing 2005 to 2007, held out (2,279) | 57.7%, 26.7% strict | 56.9%, 29.7% strict |
| Earlier held-out phishing sample (200) | 76.0%, 28.0% strict | 76.5%, 43.5% strict |
| Everyday legitimate mail, held out (1,400) | 0.5% false positives | 0.5% |
| Spam-like legitimate mail, held out (125) | 17.6% | 13.6% |
| Enron, held out (4,279) | 0.2% | 0.2% |
| Mail-library edge cases, studied (136) | 11.0% | 8.8% |
| All held-out legitimate mail (5,945) | 0.9% (54) | 0.8% (46) |
| Called likely phishing among those 5,945 | 5 | 6 |
| Median time per message, all 19,511 scored messages | 6 ms | 6 ms |
| Slowest message | 1.1 s | 0.9 s |

Earlier releases: 1.2.0 flagged 75.4% of the held-out 2022 to 2026 phishing and
1.0% of the held-out legitimate mail it could read; see the 2.0 section below.
Before 1.2.0, the first real-mail evaluation found a parse that took 60
seconds, and 1.1.0 flagged 23.3% of everyday legitimate mail; see the sections
further down.

## The 2.1 evaluation

2.1 changed how a verdict is reached rather than adding many checks: a
high-severity signal backed by a medium or high one about another part of the
message is now likely phishing, as are medium signals about three parts with a
score of 8, and weak findings of one kind count once. It also fixed the false
positives 2.0's own evaluation had found, added 53 brands and lure phrases in
two more languages, and two new sender checks. All of it was developed against
the tuning sets only (the 2,700 tuning phishing emails, the 2,625 tuning
legitimate emails and the CPython corpus), and then the held-out sets were
scored once, with the final code, after a security review had been acted on.

One exception, stated up front: the **136 mail-library edge cases are no
longer a clean held-out set**. 2.0's evaluation published its two false
positives (a Russian display name typed with one Latin letter, and a subject in
mis-declared Big5), and 2.1 fixes both on purpose. Its 11.0% → 8.8% is shown,
but it is not evidence that the changes generalise. The other held-out sets
were not looked at between 2.0's evaluation and this one.

| Year sent | Emails | Flagged, 2.0.0 → 2.1.0 | Strict, 2.0.0 → 2.1.0 |
|---|---|---|---|
| 2022 | 146 | 69.2% → 69.9% | 34.2% → 54.8% |
| 2023 | 1,425 | 75.9% → 76.0% | 31.4% → 41.4% |
| 2024 | 1,431 | 86.7% → 86.7% | 32.8% → 43.7% |
| 2025 | 1,338 | 80.7% → 82.6% | 32.1% → 50.5% |
| 2026 | 1,307 | 76.5% → 80.6% | 24.9% → 52.4% |
| **All 5,714** | 5,714 | 79.9% → **81.3%** | 30.5% → **46.9%** |

Message by message, of the 5,714: 96 are flagged now that were not, and 15 are
no longer flagged. Of those 15, nine lost nothing but a second weak finding of
the same kind (two sign-in paths now add one point, not two), three are senders
on a brand's own country domain (`paypal.de`-style), which 2.1 no longer calls
an impersonation without failed authentication, and three had a sign-in word
only in an image's address.

**One held-out set got slightly worse.** Of Nazario's 2,279 phishing emails
from 2005 to 2007, 21 are no longer flagged and one newly is (57.7% → 56.9%).
Sixteen of the 21 lost only their second weak finding of one kind; five are
forged eBay and PayPal senders on the brands' own country domains (`ebay.ca`,
`paypal.us`), and 2005 mail carries no authentication results that could show
the forgery. Strict recall on the same set still rose, 26.7% → 29.7%. Weak
findings counting once is also what cut false positives on spam-like
legitimate mail (17.6% → 13.6%), so the trade was kept.

**Legitimate mail called likely phishing**: six of the 5,945 held-out emails
(2.0: five). The new one is an issue of a 2002 newsletter that sets Reply-To to
another company and spells its name in spaced letters (`M E D I A U N S P U N`):
a high signal and an evasion signal, which 2.1 now adds up. The other five link
to raw IP addresses, forge `google.com` in a DMARC report sample, or are an
advance-fee test fixture.

**Every message, every format.** All 19,917 real messages were run again
through triage and all seven report formats with the final code, the JSON
checked against the schema: no errors and no schema violations. The median
message takes 6 ms and the slowest 0.96 s.

## The 2.0 evaluation

2.0 added most of what PhishHawk reads (Outlook `.msg`, RAR, 7z, ISO and FAT,
Office, PDF, RTF, OneNote, shortcuts, calendar invitations) and several new
kinds of detection (hidden text, look-alike characters and mixed alphabets,
forged brand senders, downloads of runnable files, crypto wallets, business
email compromise from a lookalike of your own domain). All of it was
developed against the tuning sets only: the 2,700 tuning phishing emails, the
2,625 tuning legitimate emails and the CPython corpus, plus 167 synthetic
messages. Each change was checked against the legitimate tuning mail as it
went in, and two old low-severity checks were removed because they fired more
often on legitimate mail than on phishing (a Return-Path that differs from the
sender: 59% of legitimate mail, 16% of phishing; no links at all: 7.4% and 6.0%).

The held-out sets were then scored once, at the end:

* **phishing_pot's held-out part** (5,714 emails). It had been scored once
  before, at the end of an earlier round that was never released; those
  results were not used to develop 2.0.
* **Four sets nobody had looked at**, fetched for 2.0 and set aside before any
  work started: 2,279 phishing emails from 2005 to 2007 (Jose Nazario's
  corpus), 4,279 Enron business emails from 2000 to 2002, 136 legitimate
  edge-case messages from the test suites of four mail libraries, and five
  Outlook `.msg` files. `fetch_fresh.py` rebuilds them exactly.

| Year sent | Emails | 1.2.0 | 2.0.0 |
|---|---|---|---|
| 2022 | 146 | 65.1% | 69.2% |
| 2023 | 1,425 | 72.6% | 75.9% |
| 2024 | 1,431 | 83.3% | 86.7% |
| 2025 | 1,338 | 74.9% | 80.7% |
| 2026 | 1,307 | 71.0% | 76.5% |
| **All 5,714** | 5,714 | 75.4% | **79.9%** |

Message by message: of the 5,714, 282 are flagged now that were not and 30
are not flagged that were; of Nazario's 2,279, 94 and 25. On legitimate mail,
three fewer everyday messages and seven fewer spam-like ones are flagged, Enron
is unchanged, and two more mail-library messages are flagged:

* a Russian display name typed with one Latin letter (`Атиковa`), which the
  new mixed-alphabet check reads as a look-alike trick (high);
* a subject in mis-declared Big5 that decodes to characters read as invisible,
  plus a sibling Yahoo domain in another country read as a TLD swap of the
  recipient's own (two mediums).

Both are test fixtures written to exercise a parser rather than everyday mail.
They are reported as found; the held-out sets were not used to tune them away.

**Every message, every format.** All 19,917 real messages (every set above,
plus the 400 earlier-sample phishing emails, the CPython corpus and the bundled
samples) were run through triage and all seven report formats, with the JSON
checked against [the published schema](../docs/report.schema.json): no errors
and no schema violations. Three phishing emails took 1.5 to 2 seconds, which
led to two speed fixes (predictor images in PDFs, and the address search in
base64 bodies); after them, a rescan of all 19,511 scored messages gave the same
verdict for every one, and the slowest takes 1.1 s.

## The 2026 evaluation: every phishing_pot email

The first evaluation used two samples of 200. Since the 2.0 cycle the whole
[phishing_pot](https://github.com/rf-peixoto/phishing_pot) corpus was used,
pinned at commit `49f6377`: 8,614 emails, almost all sent between 2022 and
2026. The 400 of the first evaluation were set aside; the other 8,214 were
shuffled with `random.Random(2027)` and cut into 2,500 for tuning and 5,714
held out. The sample numbers of each part are in
[splits/phishing_pot_2026.json](splits/phishing_pot_2026.json), so the split
can be rebuilt exactly.

The first detections developed against the tuning part were crypto-wallet
lures (seed phrases, "validate your wallet", airdrops), casino "free spins"
lures in five languages, Ledger as a brand, typosquats split by hyphens
(`micros-oft`) and MFA or remote-access words in combosquats. Each was checked
against the legitimate tuning mail as it went in; one (`casino` as a lure
word) was dropped for a false positive. The year is read from the `Date:`
header; 67 held-out emails have none that parses or one outside 2022 to 2026,
and are counted only in the total.

**QR codes.** Two held-out emails carry a QR code, one as a `data:` image in
the HTML and one inside a PDF, and both are decoded; one tuning email has a
code whose payload is not a link. Quishing is rarer in this honeypot than in
the reports, so the QR detections are tested on their own in
[tests/test_qr.py](../tests/test_qr.py): eleven hiding places, hostile images
and PDFs written by real software.

**Parser bugs.** Scanning real messages found two that no synthetic
test had: a malformed `Message-Id` header made Python's `email` library raise
while listing headers, which erased the SPF, DKIM and DMARC results; and
Microsoft 365 sends some `Authentication-Results` headers as base64 encoded
words, so headers are now read raw and decoded one at a time. Both have
tests in `tests/test_security.py`.

**Spam is not phishing.** For information, 32.1% of SpamAssassin's 2002 spam
(1,896 messages) is flagged by 2.0, and 31.2% by 1.2.0. PhishHawk looks for credential theft, malware and impersonation,
not for unsolicited offers, so this number is expected to stay low.

## How to read these numbers

* **The held-out number is the honest one.** Detections were developed while
  looking at the tuning part only. The held-out part, disjoint from it, was
  scored once at the end. On 200-email samples the gap between the two was
  large (81.5% vs 76%); with 2,500 and 5,714 emails it is half a point (80.4%
  vs 79.9%), which says the small samples were noisy rather than that tuning
  overfitted.
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
  legitimate mail there is for a phishing detector, and about one in six is
  still flagged.
* **Nazario's phishing is from 2005 to 2007**: bank and PayPal credential
  phishing with no modern authentication headers and plenty of plain-text
  lures that name no brand. It shows how the detections carry over to an older
  generation of phishing, and it is where PhishHawk does worst.
* **The SpamAssassin mail is from 2002, Enron's from 2000 to 2002.** It has no DKIM, DMARC or
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
python eval/fetch_fresh.py /tmp/fresh                # the four 2.0 held-out sets, checked by sha256
python eval/run_eval.py --phish /tmp/fresh/nazario --benign /tmp/fresh/enron --benign /tmp/fresh/fixtures
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
* **Nazario's phishing corpus and the Enron corpus**, as mirrored in the
  `code/resources` mailboxes of
  [diegoocampoh/MachineLearningPhishing](https://github.com/diegoocampoh/MachineLearningPhishing)
  at `2ac0fa5`. Jose Nazario collected the phishing from 2005 to 2007 and
  published it for research; the Enron mail was released publicly during the
  FERC investigation. Used for evaluation only.
* **Mail-library test messages** from [mikel/mail](https://github.com/mikel/mail)
  (MIT), [mailgun/talon](https://github.com/mailgun/talon) (Apache-2.0),
  [nodemailer/mailparser](https://github.com/nodemailer/mailparser) and
  [domainaware/parsedmarc](https://github.com/domainaware/parsedmarc)
  (Apache-2.0), and Outlook files from
  [TeamMsgExtractor/msg-extractor](https://github.com/TeamMsgExtractor/msg-extractor)
  (GPL-3.0), each pinned to a commit in `splits/fresh_2026.json`.
  `fetch_fresh.py` downloads them from their own repositories; none are
  redistributed here.
* **CPython `Lib/test/test_email/data`**, the Python standard library's email
  test messages (PSF licence), used as legitimate and edge-case MIME.
* **`make_corpus.py`**, synthetic, generated deterministically.
