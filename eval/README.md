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
| Real phishing, **held-out** sample (phishing_pot, seed 7) | 200 | **71.0%** | 30.5% | — |
| Real phishing, tuning sample (phishing_pot, seed 42) | 200 | 81.0% | 26.5% | — |
| Legitimate edge-case mail (CPython `test_email` corpus) | 48 | — | — | **2.1%** (1/48) |
| Synthetic labelled corpus (`make_corpus.py`, seed 7) | 102 phish + 65 legit | 100% | 59.8% | 0.0% |

Before this evaluation, the same code scored 70.0% on the held-out set, 75.0% on
the tuning set and 12.5% false positives on the CPython corpus. The worst-case
parse time was 60 seconds; it is now under half a second.

## How to read these numbers

* **The held-out number is the honest one.** Detections were developed while
  looking at the tuning sample only. The held-out sample, disjoint from it,
  was scored once at the end. The gap between the two (81% vs 71%) is the
  expected optimism of measuring on data you tuned against.
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
* **The one CPython false positive** is a message from `example.net` to
  `example.com`, a TLD swap of the recipient's domain. It is flagged medium,
  because that is exactly what BEC looks like.

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
python eval/run_eval.py --phish DIR --benign DIR     # your own labelled mail
```

Add `--json` for machine-readable results. To check false positives against
your own organisation's mail, export a few hundred legitimate messages as `.eml`
and pass the folder with `--benign`.

## Data sources

* **phishing_pot** by rf-peixoto, real phishing collected by honeypots,
  licensed CC BY-NC 4.0. It is used here for non-commercial evaluation
  only; no samples are redistributed in this repository.
* **CPython `Lib/test/test_email/data`**, the Python standard library's email
  test messages (PSF licence), used as legitimate and edge-case MIME.
* **`make_corpus.py`**, synthetic, generated deterministically.
