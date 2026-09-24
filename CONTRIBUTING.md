# Contributing to PhishHawk

Thanks for helping. Missed phish, false positives, new detections, docs fixes
and bug reports are all welcome.

## Ground rules

- **Never attach or commit a real email.** Real phishing contains other
  people's addresses and sometimes live malware, and real legitimate mail is
  private. Describe the message, or rebuild the pattern with the synthetic
  helpers below, using reserved names such as `example.com`, `example.net` or
  `.test` domains.
- **No live malware** anywhere in the repository, including tests. An
  attachment only needs the right magic bytes, name or structure to exercise a
  check; it never needs a working payload.
- **Every new check needs a test for what it catches and a test for what it
  must not catch.** False positives cost analysts more than a missed low signal.
- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Set up

```bash
git clone https://github.com/vinitrami-Soc/phishhawk.git && cd phishhawk
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest                                            # 168 tests, offline, a few seconds
ruff check src tests samples eval tools phishhawk
```

Tests never touch the network: enrichment tests use fake HTTP sessions.

## Reporting a missed phish or a false positive

Open a [detection report](https://github.com/vinitrami-Soc/phishhawk/issues/new/choose).
The most useful details are:

- the verdict you got, and the one you expected;
- the `phishhawk scan --verbose` output, with personal data removed;
- what gives the message away to a human (sender, link, attachment, wording).

## Adding or changing a detection

1. **Find the right place.** Signals are raised in
   `src/phishhawk/heuristics.py`, grouped by area (`_sender`, `_lookalikes`,
   `_urls`, `_attachments`, `_html_attachment`, `_body`, `_language`, and
   `apply_enrichment` for reputation results). Lists of brands, lure phrases,
   TLDs, shorteners and file types live in `knowledge.py` and `hosting.py`.
2. **Pick a severity honestly.**
   - *High*: rarely seen in legitimate mail and strong on its own (a homoglyph
     domain, a double extension, a credential form in an attachment).
   - *Medium*: suspicious, but legitimate mail does it sometimes (a shortener,
     `DKIM=none`).
   - *Low*: context only. Low signals add at most 3 points in total, so they can
     never produce a verdict by themselves.
3. **Tag the ATT&CK technique** the signal is evidence of. If it is a technique
   PhishHawk does not list yet, add it to `TECHNIQUES` and `EVIDENCE` in
   `src/phishhawk/attack.py`.
4. **Write the tests** in `tests/test_detection.py` (or the matching
   `test_*.py`). `build_eml()` from `tests/conftest.py` builds a message in a line:

   ```python
   def test_brand_hidden_by_punctuation_in_display_name():
       a = triage_bytes(build_eml(sender='"Trust-Wallet" <alerts@alquiaga.example>'))
       assert has(a, "display name claims 'trustwallet'")
   ```

   Add a second test with a legitimate message that looks similar and must
   **not** raise the signal.
5. **Add it to the synthetic corpus** if it is a new kind of phish or a new
   kind of tricky legitimate mail: add a scenario method to `eval/make_corpus.py`
   and call it from `build()`.
6. **Run the evaluation gate**:

   ```bash
   python eval/run_eval.py --synthetic
   ```

   CI fails if synthetic recall drops below 95% or false positives rise above 2%.
   If you have the phishing_pot sample (`python eval/fetch_phishing_pot.py`),
   check the tuning set too, and do not tune against the held-out set.
7. **Document it** in [docs/DETECTIONS.md](docs/DETECTIONS.md), and add a line
   under *Unreleased* in [CHANGELOG.md](CHANGELOG.md).

## Code style

- Python 3.10+, standard library first. The only runtime dependency is
  `requests`; a new one needs a very good reason.
- `ruff check` must pass; the configuration is in `pyproject.toml`.
- Anything that reads message content must stay linear-time: bound every
  regex quantifier and cap every decompression. `tests/test_detection.py` has
  timing tests for this; add one if you touch parsing.
- Never execute, render or write attachment content to disk.
- Anything shown to a person must be defanged; anything sent to a third party
  must go through the protected-domain and brand checks in `enrich/`.

## Regenerating the images

The images in `docs/images/` are drawn by scripts, never by hand:

```bash
pip install -e ".[assets]"
python tools/make_logo.py      # logo PNG and the terminal banner art
python tools/make_demo.py      # banner.svg and demo.svg, recorded from real runs
python tools/make_charts.py    # evaluation charts, from eval/results.json
python tools/make_report_shots.py   # report-light/dark/print.png; needs `playwright install chromium`
```

## Pull requests

- One change per pull request, with a short description of what and why.
- Tests, lint and the evaluation gate must pass; CI runs them on Python 3.10 to 3.13.
- The pull request template has a checklist; please fill it in.
