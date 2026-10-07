# PhishHawk v3 M1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An analyst logs in to a self-hosted PhishHawk web app, submits one reported message, sees the verdict and the full report, and downloads all six formats, with encrypted storage, retention, hold and deletion, a verifiable audit log and a Docker Compose deployment (milestone M1 of the v3 design).

**Architecture:** A new `phishhawk.server` package behind a `server` extra, in the same repository (design approach A). It reaches the engine only through `phishhawk.analysis.analyze()`. FastAPI serves a JSON API under `/api/v1`, server-rendered pages (the backup and admin interface) and, at `/app/`, the owner's own frontend built in Google AI Studio; a worker process claims jobs from a database table and analyses each message in a child process with memory and CPU limits. Tier 1 (raw message, full report, exports) is sealed with AES-256-GCM on disk; tier 2 (verdict, indicators, hashes, campaign traits) lives in SQLite.

**Tech Stack:** Python 3.10 to 3.13; FastAPI, uvicorn, Jinja2, SQLAlchemy 2, Alembic, pydantic-settings, argon2-cffi, cryptography (AESGCM), python-multipart; pytest with Starlette's TestClient (httpx2); Playwright with headless Chromium for one browser test; Docker Compose.

**Spec:** [docs/superpowers/specs/2026-10-06-phishhawk-v3-web-design.md](../specs/2026-10-06-phishhawk-v3-web-design.md), section 11, M1.

## Global Constraints

Every task's requirements include these. Quotes are from the spec.

- Python: "Python 3.10 to 3.13, as now."
- Dependencies: "The base install keeps its single dependency (`requests`)." New dependencies go only in the `server` extra: "fastapi, uvicorn, jinja2, sqlalchemy, alembic, argon2-cffi, cryptography, python-multipart, pydantic-settings". The floors in task 2 were tested against the oldest allowed version of each.
- Engine: "The CLI and engine do not change, except one additive function in `campaign.py`". Task 1 also moves report rendering from `cli.py` into `report/bundle.py`; the CLI's output stays byte for byte the same, and the existing tests prove it.
- Boundary: "The server depends on the engine only through `phishhawk.analysis`."
- Read-only: PhishHawk "never deletes, moves or quarantines mail and never stores credentials that could" (D4).
- Defaults: `RETENTION_DAYS` 30, `MAX_UPLOAD_MB` 25, `MAX_BATCH_MESSAGES` 500, `CAMPAIGN_WINDOW_DAYS` 90; "Every provider off on a fresh install" (D3); session idle timeout eight hours.
- Data: "Plain message bytes are only ever in worker memory; they are never written to disk in clear." "Without `ENCRYPTION_KEY` the server refuses to start. With the wrong key it refuses to decrypt and deletes nothing."
- Tests: "The existing 690 tests stay green at every step." Each task ends with the whole suite passing, `ruff check src tests samples eval tools phishhawk` clean (line length 115) and `mypy` clean, both with and without the server extra installed.
- Performance: "a bundled sample from submit to verdict in under 5 s offline on the CI runner."
- Secrets in tests: none as literals; CI's gitleaks scans every commit. Make keys at run time with `new_key()` or `secrets.token_hex()`.
- Commits: one per task, author `Vinit Rami <274839285+vinitrami-Soc@users.noreply.github.com>`, no co-author trailers. Pull requests use `.github/pull_request_template.md`.
- Copy: plain words, no emoji. The UI uses the spec's names: "Delete now", "Hold", "Release hold", "Delete completely", "Re-analyze", "Offline".

## How this plan was checked

Before writing it, the whole milestone was built and tested as a prototype; every code block below is that code. Then the plan itself was replayed, task by task, on a fresh clone of `main` (7a50cfa). Each task's tests were run before its code and failed on the missing code (each task quotes the first error); with the code they passed, the whole suite stayed green, ruff and mypy stayed clean, every diff applied with `git apply` and every commit left a clean tree. The suite grew from 690 tests to 801 passed, 1 skipped. At the end, with the server extra: 801 passed, 1 skipped, coverage 90%; without it: 693 passed, 1 skipped, coverage 90% (the server's code left out, as in CI's base job). The Docker image and Compose stack were built from the same code and passed the smoke check, the audit log check and a clean stop, with a frontend build mounted and served at `/app/`.

Along the way the prototype found and fixed: a worker left running after SIGTERM (uvicorn raises the signal again after shutdown), a read-only API token that could download raw messages, SQLAlchemy 2.0 not mapping `list[Any]` columns, white text on the dark-mode button at 2.26:1 contrast, a favicon 404 that showed as a console error, and test literals the secret scan would have failed on. Each has a test. The replay found one more: `tools/make_openapi.py` did not create `docs/api/` on a fresh checkout; it does now.

## Before you start

- Work on a branch from `main`. `python -m pip install -e ".[dev]"` gives the current toolchain; task 2 adds the server extra.
- Run tests with `python -m pytest`. The repository sets `-q` and `pythonpath = ["src"]`.
- Server tests live in `tests/server/` and import their helpers from `tests/server/serverkit.py`; the shared helpers in `tests/conftest.py` are imported as `from conftest import ...`.
- A file that exists already is shown as a diff (apply it with `git apply` or by hand); a new file is shown whole.
- If a step's output differs from what the plan expects, stop and find out why before going on.
- One existing test, `tests/test_security.py::test_a_link_flood_is_fast_and_flagged`, allows 5 seconds and takes about 5 under `coverage run` on a slow machine; it fails that way on `main` too. If it alone fails, run it again on its own before suspecting your change. Nothing in this plan touches the code it times.

## Decisions the spec left open, settled here

1. **`frame-src 'self'`** is added to the app's CSP (spec 7.3 lists the rest verbatim). With `default-src 'none'` the analysis page could not frame the sandboxed report.
2. **The submission page refreshes itself** every 2 seconds (`<meta http-equiv="refresh">`) instead of polling from JavaScript. It works without JavaScript and needs nothing more in the CSP.
3. **A message on hold cannot be deleted**, by "Delete now" or "Delete completely", until an admin releases it (409). Hold exists to keep incident evidence (spec 5.3).
4. **SQLite only in M1.** `PHISHHAWK_DATABASE_URL` exists, but Postgres and several workers are built and tested in M2. SQLite's busy timeout (30 s) does the waiting the spec calls "retried with backoff".
5. **Session IDs are an HMAC under `SECRET_KEY`**, so `SECRET_KEY` "signs sessions" as spec 5.2 says and a new value logs everyone out. CSRF tokens are random per session.
6. **`POST /submissions` and re-analyze answer with the submission** (the shape of `GET /submissions/{id}`); batch IDs come with M2.
7. **The owner's own frontend** (decided after the spec): the main UI is built in Google AI Studio and served by this server at `/app/`, on the same origin as the API, so the cookie stays `SameSite=Strict`, no CORS is needed and the app's CSP covers it. `GET /api/v1/session` tells it who is logged in after a reload. The built-in pages stay as the backup and admin interface (task 13; the rules for that frontend are in docs/FRONTEND.md, task 18).

## Not in M1

Planned for later milestones, not forgotten: batch upload and combined exports, `correlate_records()` and the campaign pages (M2); IMAP, Graph and Gmail import (M3); Postgres and more than one worker; the queue's source, date and user filters (with batch and mailbox sources); JSON logs with a request ID (uvicorn's access log in M1 holds method, path and status only, never bodies or headers); the providers' "Test connection" button; the IntelPulse handoff (a later spec).

## File map

| Path | Responsibility |
|---|---|
| `src/phishhawk/analysis.py` | The facade: `analyze(raw, name, options)` returns the analysis, its JSON, every export, the tier-2 summary, the trait record and the outbound lookups. |
| `src/phishhawk/report/bundle.py` | Renders the six formats and the manifest in memory; shared by the CLI and the facade. |
| `src/phishhawk/campaign.py` | Gains `trait_record()`. |
| `src/phishhawk/cli.py` | Uses `bundle`; hands `phishhawk server ...` to the server's CLI. |
| `src/phishhawk/server/config.py` | `PHISHHAWK_*` settings and Docker secret files. |
| `src/phishhawk/server/crypto.py` | AES-256-GCM sealing bound to an ID. |
| `src/phishhawk/server/models.py`, `db.py`, `migrations/` | Tables, engine and sessions, Alembic migrations. |
| `src/phishhawk/server/store.py` | Sealed tier-1 files under `<data_dir>/blobs`. |
| `src/phishhawk/server/audit.py` | Hash-chained audit log and `verify()`. |
| `src/phishhawk/server/auth.py` | Users, sessions, API tokens, login throttle. |
| `src/phishhawk/server/appsettings.py` | Settings kept in the database; sealed provider keys; `AnalysisOptions`. |
| `src/phishhawk/server/jobs.py`, `limits.py` | Job queue; the resource-limited child process. |
| `src/phishhawk/server/intake.py`, `processing.py`, `retention.py`, `worker.py` | One message from upload to stored analysis; retention; the worker loop and its schedule. |
| `src/phishhawk/server/rotation.py` | Encryption key rotation. |
| `src/phishhawk/server/security.py`, `deps.py`, `views.py`, `routes/files.py`, `routes/api.py`, `app.py` | Headers and CSPs, request dependencies (DB, actor, CSRF), shared queries, file serving, the JSON API, the app factory. |
| `src/phishhawk/server/routes/pages.py`, `templates/`, `static/` | The built-in pages: the backup and admin interface. |
| `src/phishhawk/server/frontend.py` | Serves the owner's own frontend build at `/app/`. |
| `src/phishhawk/server/cli.py` | `phishhawk server run / worker / migrate / create-admin / rotate-key / audit verify`. |
| `tools/make_openapi.py`, `docs/api/openapi.json` | The API description and its generator. |
| `server.Dockerfile`, `compose.yaml`, `tools/server_smoke.py` | Image, Compose stack, outside-in smoke check. |
| `.github/workflows/ci.yml` | Base job without the extra; `server` job on 3.10 to 3.13; Compose job; browser test on 3.12. |
| `docs/SERVER.md`, `docs/FRONTEND.md` | The admin guide; the rules and API guide for your own frontend, with a starting prompt for Google AI Studio. |

## Pull requests

The spec asks for small PRs with the CLI working after each one. Group the tasks like this; each PR is green on its own.

| PR | Tasks | What it delivers |
|---|---|---|
| PR 1 | 1 | Engine facade. |
| PR 2 | 2, 3, 4 | Server package, settings, encryption, database, blob store; the CI job for the extra. |
| PR 3 | 5, 6, 7, 8 | Audit log, users and tokens, stored settings, jobs and limits. |
| PR 4 | 9, 10 | Intake, worker, retention, key rotation. |
| PR 5 | 11 | The JSON API. |
| PR 6 | 12, 13 | The pages; your own frontend at `/app/` and `GET /api/v1/session`. |
| PR 7 | 14, 15 | `phishhawk server`, the OpenAPI document. |
| PR 8 | 16, 17, 18 | Docker and Compose, the browser test, the documentation. |

## Tasks

### Task 1: Engine facade: one call from raw bytes to every report format

*PR 1.*

The web app must reach the engine through one function, so the engine stays the CLI's and the server never imports its internals. This task moves report rendering out of `cli.py` into `report/bundle.py` (the CLI's output does not change), adds `campaign.trait_record()` (the campaign traits of one message as plain JSON, kept after the message is deleted) and adds `analysis.analyze()`, which returns the analysis, its JSON, all six exports and the manifest, the tier-2 summary, the trait record and every outbound lookup it made.

**Files:**

- Create: `src/phishhawk/report/bundle.py`
- Create: `src/phishhawk/analysis.py`
- Modify: `src/phishhawk/cli.py`
- Modify: `src/phishhawk/campaign.py`
- Test: `tests/test_analysis_facade.py` (new)

**Interfaces:**

- Consumes:
  - `phishhawk.cache` (main): `class Cache`
  - `phishhawk.enrich.base` (main): `new_session() -> Any`
  - `phishhawk.enrich` (main): `AbuseIPDB`; `Rdap`; `UrlScan`; `VirusTotal`; `class Enricher`
  - `phishhawk.models` (main): `class Analysis`
  - `phishhawk.pipeline` (main): `class Options`; `triage_bytes(data: bytes, path: str='<memory>', options: Options | None=None, enricher: Enricher | None=None, progress: Callable[[str], None] | None=None) -> Analysis`
  - `phishhawk.report.common` (main): `report_id(analysis: Analysis) -> str`; `safe_report_name(analyses: list[Analysis], kind: str, day: str) -> str`; `to_dict(analysis: Analysis) -> dict[str, Any]`
  - `phishhawk.report.csvout` (main): `render(analyses: list[Analysis]) -> str`
  - `phishhawk.report.html` (main): `render(analyses: list[Analysis], exports: list[dict] | None=None) -> str`
  - `phishhawk.report.markdown` (main): `render(a: Analysis) -> str`
  - `phishhawk.report.misp` (main): `build(analyses: list[Analysis], tlp: str='amber') -> dict[str, Any] | list[dict[str, Any]]`
  - `phishhawk.report.stix` (main): `build_bundle(analyses: list[Analysis]) -> dict[str, Any]`
  - `phishhawk` (main): `__version__`
- Produces:
  - `phishhawk.report.bundle`: `REPORT_TYPES`; `BEFORE_HTML`; `class RenderedFile`: `name: str`; `kind: str`; `content: bytes`; `property sha256() -> str`; `entry() -> dict[str, Any]`; `render(kind: str, analyses: list[Analysis], tlp: str='amber') -> str`; `manifest(analyses: list[Analysis], files: list[dict[str, Any]]) -> dict[str, Any]`; `render_bundle(analyses: list[Analysis], tlp: str='amber', day: str | None=None) -> list[RenderedFile]`
  - `phishhawk.campaign`: `trait_record(a: Analysis) -> dict[str, Any]`
  - `phishhawk.analysis`: `PROVIDERS`; `class AnalysisOptions`: `providers: frozenset[str]`; `keys: dict[str, str]`; `protected: list[str]`; `allow_domains: list[str]`; `block_domains: list[str]`; `trusted_authserv: list[str]`; `cache_path: str | None`; `timeout: float`; `tlp: str`; `class AnalysisResult`: `analysis: Analysis`; `data: dict[str, Any]`; `files: list[RenderedFile]`; `summary: dict[str, Any]`; `traits: dict[str, Any]`; `lookups: list[dict[str, str]]`; `analyze(raw: bytes, name: str='<upload>', options: AnalysisOptions | None=None) -> AnalysisResult`

**Notes:**

- `render_bundle()` renders JSON, STIX, MISP, Markdown and CSV first, then the HTML report (which lists those five as files beside it), then the manifest (which lists all six). File names come from `safe_report_name()`, so nothing from the message reaches a file name.
- The CLI keeps writing files itself; it now asks `bundle.render()` and `bundle.manifest()` for the content. The existing CLI and export tests prove its output is unchanged.
- `_Recorder` wraps each provider's HTTP session and records provider, method, URL and query parameters. API keys travel in headers, so they are never recorded.
- The summary deliberately leaves out recipients, the subject and body text (spec 5.1, tier 2).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_analysis_facade.py`:

```python
"""The engine as one call: what the web app gets back for one message."""

import hashlib
import json

from phishhawk import analysis
from phishhawk.analysis import AnalysisOptions, analyze

from conftest import FakeResponse, FakeSession, sample


def _raw(name):
    with open(sample(name), "rb") as handle:
        return handle.read()


def test_offline_analysis_returns_every_format_the_record_and_no_lookups():
    raw = _raw("sample_bec_smuggling.eml")
    result = analyze(raw, name="bec.eml")
    assert result.analysis.verdict == "LIKELY PHISHING"
    assert [f.kind for f in result.files] == ["json", "stix", "misp", "md", "csv", "html", "manifest"]
    manifest = json.loads(result.files[-1].content)
    assert [f["sha256"] for f in manifest["files"]] == [f.sha256 for f in result.files[:-1]]
    assert result.summary["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result.summary["report_id"].startswith("PH-") and result.summary["recipient_count"] == 1
    assert {"type": "domain", "value": "examp1e-corp.co.uk"} in result.summary["indicators"]
    assert "T1566.001" in result.summary["techniques"]
    assert result.traits["flagged"] and "sender" in result.traits["traits"]
    assert result.lookups == []
    # the record kept after deletion holds no recipient address or subject
    kept = json.dumps(result.summary)
    assert "vinit.rami" not in kept and result.analysis.subject not in kept


def test_every_request_to_a_provider_is_recorded_without_its_key(monkeypatch):
    monkeypatch.setattr(analysis, "new_session", lambda: FakeSession(lambda m, u, k: FakeResponse(404)))
    options = AnalysisOptions(providers=frozenset({"abuseipdb", "rdap"}), keys={"abuseipdb": "SECRET-KEY"})
    result = analyze(_raw("sample_bec_smuggling.eml"), options=options)
    providers = {entry["provider"] for entry in result.lookups}
    assert providers == {"abuseipdb", "rdap"}
    assert any("ipAddress=45.148.10.77" in entry["url"] for entry in result.lookups)
    assert "SECRET-KEY" not in json.dumps(result.lookups)
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/test_analysis_facade.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'analysis' from 'phishhawk'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/report/bundle.py`:

```python
"""Every report format for a set of analyses, rendered in memory, with the
manifest that lists them. The CLI writes these to files and the web app
stores them encrypted; one place decides what each format holds."""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .. import __version__
from ..models import Analysis
from . import csvout, html, markdown, misp, stix
from .common import report_id, safe_report_name, to_dict

REPORT_TYPES = {"json": "JSON report", "stix": "STIX 2.1 bundle", "misp": "MISP event", "md": "Markdown note",
                "csv": "CSV indicators", "html": "HTML report", "manifest": "Manifest"}
BEFORE_HTML = ("json", "stix", "misp", "md", "csv")  # the HTML report lists these, so they come first


@dataclass(frozen=True)
class RenderedFile:
    name: str
    kind: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def entry(self) -> dict[str, Any]:
        """How the manifest and the HTML report's Report files panel list it."""
        return {"name": self.name, "kind": self.kind, "type": REPORT_TYPES[self.kind],
                "size": len(self.content), "sha256": self.sha256}


def render(kind: str, analyses: list[Analysis], tlp: str = "amber") -> str:
    """One format other than HTML and the manifest, as text."""
    if kind == "json":
        payload: Any = to_dict(analyses[0]) if len(analyses) == 1 else {"reports": [to_dict(a) for a in analyses]}
        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if kind == "stix":
        return json.dumps(stix.build_bundle(analyses), indent=2) + "\n"
    if kind == "misp":
        return json.dumps(misp.build(analyses, tlp), indent=2, ensure_ascii=False) + "\n"
    if kind == "md":
        return "\n---\n\n".join(markdown.render(a) for a in analyses)
    if kind == "csv":
        return csvout.render(analyses)
    raise ValueError("no renderer for %r" % kind)


def manifest(analyses: list[Analysis], files: list[dict[str, Any]]) -> dict[str, Any]:
    """What a run wrote, so a copy passed along can be checked against it."""
    return {
        "manifest_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "tool": "phishhawk",
        "tool_version": __version__,
        "messages": [{"report_id": report_id(a), "path": a.path, "sha256": a.evidence.get("sha256", ""),
                      "size": a.evidence.get("size", 0)} for a in analyses],
        "files": [{key: f[key] for key in ("name", "kind", "type", "size", "sha256")} for f in files],
    }


def render_bundle(analyses: list[Analysis], tlp: str = "amber", day: str | None = None) -> list[RenderedFile]:
    """All six formats and the manifest, named from hashes alone. The HTML
    report lists the other five beside it; the manifest lists all six."""
    day = day or datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    files = [RenderedFile(safe_report_name(analyses, kind, day), kind, render(kind, analyses, tlp).encode("utf-8"))
             for kind in BEFORE_HTML]
    page = html.render(analyses, [dict(f.entry(), beside=True) for f in files])
    files.append(RenderedFile(safe_report_name(analyses, "html", day), "html", page.encode("utf-8")))
    listing = json.dumps(manifest(analyses, [f.entry() for f in files]), indent=2, ensure_ascii=False) + "\n"
    files.append(RenderedFile(safe_report_name(analyses, "manifest", day), "manifest", listing.encode("utf-8")))
    return files
```

Change `src/phishhawk/cli.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/cli.py
+++ b/src/phishhawk/cli.py
@@ -11,6 +11,7 @@
 import argparse
 import dataclasses
 import datetime
+import functools
 import getpass
 import hashlib
 import json
@@ -43,8 +44,8 @@
 from .enrich import AbuseIPDB, Enricher, Rdap, UrlScan, VirusTotal
 from .models import Analysis
 from .pipeline import Options, triage_bytes
-from .report import campaignout, console, csvout, html, markdown, misp, stix, sweepout
-from .report.common import printable, report_id, safe_report_name, to_dict
+from .report import bundle, campaignout, console, html, sweepout
+from .report.common import printable, safe_report_name, to_dict
 
 COMMANDS = ("scan", "imap", "graph", "gmail", "campaign", "sweep", "evidence", "doctor", "cache", "techniques",
             "help")
@@ -588,10 +589,6 @@
         handle.write(content)
 
 
-REPORT_TYPES = {"json": "JSON report", "stix": "STIX 2.1 bundle", "misp": "MISP event", "md": "Markdown note",
-                "csv": "CSV indicators", "html": "HTML report", "manifest": "Manifest"}
-
-
 def _report_path(path: str, analyses: list[Analysis], kind: str, day: str) -> str:
     """A folder (an existing one, or any path ending in a separator) gets a file
     name built from hashes alone, so nothing from the message reaches the disk."""
@@ -601,19 +598,6 @@
         os.makedirs(path, exist_ok=True)
         return os.path.join(path, safe_report_name(analyses, kind, day))
     return path
-
-
-def _manifest(analyses: list[Analysis], written: list[dict]) -> dict:
-    """What a run wrote, so a copy passed along can be checked against it."""
-    return {
-        "manifest_version": 1,
-        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
-        "tool": "phishhawk",
-        "tool_version": __version__,
-        "messages": [{"report_id": report_id(a), "path": a.path, "sha256": a.evidence.get("sha256", ""),
-                      "size": a.evidence.get("size", 0)} for a in analyses],
-        "files": [{key: f[key] for key in ("name", "kind", "type", "size", "sha256")} for f in written],
-    }
 
 
 FAIL_ORDER = {"never": 99, "suspicious": 1, "likely": 2, "malicious": 3}
@@ -769,16 +753,10 @@
         print(console.render_batch_table(analyses, colour))
         print("")
 
-    renderers = {
-        "json": lambda: json.dumps(to_dict(analyses[0]) if len(analyses) == 1
-                                   else {"reports": [to_dict(a) for a in analyses]},
-                                   indent=2, ensure_ascii=False) + "\n",
-        "stix": lambda: json.dumps(stix.build_bundle(analyses), indent=2) + "\n",
-        "misp": lambda: json.dumps(misp.build(analyses, args.tlp), indent=2, ensure_ascii=False) + "\n",
-        "md": lambda: "\n---\n\n".join(markdown.render(a) for a in analyses),
-        "csv": lambda: csvout.render(analyses),
-        "manifest": lambda: json.dumps(_manifest(analyses, report_files), indent=2, ensure_ascii=False) + "\n",
-    }
+    renderers: dict[str, Callable[[], str]] = {
+        kind: functools.partial(bundle.render, kind, analyses, args.tlp) for kind in bundle.BEFORE_HTML}
+    renderers["manifest"] = lambda: json.dumps(bundle.manifest(analyses, report_files), indent=2,
+                                               ensure_ascii=False) + "\n"
     day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
     report_files: list[dict] = []
     for kind, path in outputs.items():
@@ -797,7 +775,7 @@
                 encoded = content.encode("utf-8")  # _write keeps line endings, so these are the bytes on disk
                 digest = hashlib.sha256(encoded).hexdigest()
                 report_files.append({"name": os.path.basename(path), "path": os.path.abspath(path), "kind": kind,
-                                     "type": REPORT_TYPES[kind], "size": len(encoded), "sha256": digest})
+                                     "type": bundle.REPORT_TYPES[kind], "size": len(encoded), "sha256": digest})
                 print(err("[i] %s report written to %s (%d bytes, sha256 %s)"
                           % (kind.upper(), path, len(encoded), digest), "dim"), file=sys.stderr)
         except OSError as exc:
```

Change `src/phishhawk/campaign.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/campaign.py
+++ b/src/phishhawk/campaign.py
@@ -209,6 +209,15 @@
     return {kind: values for kind, values in found.items() if values}, dict(under)
 
 
+def trait_record(a: Analysis) -> dict[str, Any]:
+    """What correlation needs from one message, as plain JSON, so a stored
+    record can still be correlated after the message itself is deleted."""
+    found, under = _traits(a)
+    return {"traits": {kind: sorted(values) for kind, values in found.items()},
+            "under": {base: sorted(hosts) for base, hosts in under.items()},
+            "flagged": a.verdict != "NO STRONG INDICATORS"}
+
+
 def _platforms(unders: list[dict[str, set[str]]]) -> list[dict[str, Any]]:
     holders: dict[str, int] = defaultdict(int)
     hosts: dict[str, set[str]] = defaultdict(set)
```

Create `src/phishhawk/analysis.py`:

```python
"""The engine as one call, for the web app and anything else that is not the
CLI: raw message bytes in; the analysis, every report format, the record that
is kept after the message is deleted, and what was sent to which provider out."""

from __future__ import annotations

import email.utils
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from . import __version__, campaign
from .cache import Cache
from .enrich import AbuseIPDB, Enricher, Rdap, UrlScan, VirusTotal
from .enrich.base import new_session
from .models import Analysis
from .pipeline import Options, triage_bytes
from .report.bundle import RenderedFile, render_bundle
from .report.common import report_id, to_dict

PROVIDERS = ("virustotal", "urlscan", "rdap", "abuseipdb")


@dataclass
class AnalysisOptions:
    providers: frozenset[str] = frozenset()  # the enabled ones; empty means offline
    keys: dict[str, str] = field(default_factory=dict)  # provider name -> API key
    protected: list[str] = field(default_factory=list)
    allow_domains: list[str] = field(default_factory=list)
    block_domains: list[str] = field(default_factory=list)
    trusted_authserv: list[str] = field(default_factory=list)
    cache_path: str | None = None
    timeout: float = 20
    tlp: str = "amber"


@dataclass
class AnalysisResult:
    analysis: Analysis
    data: dict[str, Any]  # to_dict(): the full JSON report
    files: list[RenderedFile]  # six formats and the manifest
    summary: dict[str, Any]  # the record kept after the message is deleted
    traits: dict[str, Any]  # campaign.trait_record()
    lookups: list[dict[str, str]]  # every request sent to a provider


class _Recorder:
    """A provider's HTTP session that notes every request it sends: the
    provider, the method and the URL with its query. API keys travel in
    headers and are never noted."""

    def __init__(self, inner: Any, provider: str, log: list[dict[str, str]]) -> None:
        self._inner, self._provider, self._log = inner, provider, log

    def _note(self, method: str, url: str, params: Any) -> None:
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        self._log.append({"provider": self._provider, "method": method, "url": url})

    def get(self, url: str, **kwargs: Any) -> Any:
        self._note("GET", url, kwargs.get("params"))
        return self._inner.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        self._note("POST", url, kwargs.get("params"))
        return self._inner.post(url, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _enricher(options: AnalysisOptions, cache: Cache | None, log: list[dict[str, str]]) -> Enricher | None:
    enabled, keys = options.providers, options.keys
    if not enabled:
        return None
    common: dict[str, Any] = {"timeout": options.timeout, "cache": cache}

    def session(name: str) -> _Recorder:
        return _Recorder(new_session(), name, log)

    return Enricher(
        virustotal=VirusTotal(keys["virustotal"], session=session("virustotal"), **common)
        if "virustotal" in enabled and keys.get("virustotal") else None,
        urlscan=UrlScan(keys.get("urlscan", ""), session=session("urlscan"), **common)
        if "urlscan" in enabled else None,
        rdap=Rdap(session=session("rdap"), **common) if "rdap" in enabled else None,
        abuseipdb=AbuseIPDB(keys["abuseipdb"], session=session("abuseipdb"), **common)
        if "abuseipdb" in enabled and keys.get("abuseipdb") else None,
    )


def _summary(a: Analysis, data: dict[str, Any]) -> dict[str, Any]:
    try:
        recipients = {address.lower() for _, address in email.utils.getaddresses([a.to or ""]) if "@" in address}
    except Exception:  # a malformed To line names nobody
        recipients = set()
    return {
        "sha256": a.evidence.get("sha256", ""), "size": a.evidence.get("size", 0), "report_id": report_id(a),
        "verdict": a.verdict, "score": a.score, "engine_version": __version__,
        "sender": (a.from_address or "").lower(), "sender_domain": (a.from_domain or "").lower(),
        "recipient_count": len(recipients),
        "indicators": [{"type": ioc["type"], "value": ioc["value"]} for ioc in data["iocs"]],
        "techniques": [technique["id"] for technique in data["techniques"]],
    }


def analyze(raw: bytes, name: str = "<upload>", options: AnalysisOptions | None = None) -> AnalysisResult:
    options = options or AnalysisOptions()
    lookups: list[dict[str, str]] = []
    cache = Cache(options.cache_path) if options.cache_path and options.providers else None
    try:
        engine_options = Options(protected=list(options.protected), allow_domains=list(options.allow_domains),
                                 block_domains=list(options.block_domains),
                                 trusted_authserv=list(options.trusted_authserv))
        a = triage_bytes(raw, path=name, options=engine_options, enricher=_enricher(options, cache, lookups))
    finally:
        if cache is not None:
            cache.close()
    data = to_dict(a)
    return AnalysisResult(a, data, render_bundle([a], tlp=options.tlp), _summary(a, data),
                          campaign.trait_record(a), lookups)
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/test_analysis_facade.py
```
Expected: 2 passed.

```bash
python -m pytest  # the whole suite: the CLI's output is unchanged
```
Expected: 692 passed, 1 skipped.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/analysis.py src/phishhawk/campaign.py src/phishhawk/cli.py src/phishhawk/report/bundle.py tests/test_analysis_facade.py
git commit -m "Add the engine facade: one call from raw bytes to every report format"
```

### Task 2: Server package, settings and encryption

*PR 2.*

Start `phishhawk.server` behind a new `server` extra, with the two pieces everything else stands on: settings read from `PHISHHAWK_*` variables or Docker secret files, and AES-256-GCM sealing that binds each value to its ID. CI gains a job that installs the extra; the existing job keeps working without it.

**Files:**

- Create: `src/phishhawk/server/__init__.py`
- Create: `src/phishhawk/server/config.py`
- Create: `src/phishhawk/server/crypto.py`
- Modify: `pyproject.toml`
- Modify: `.github/workflows/ci.yml`
- Test: `tests/server/__init__.py` (new)
- Test: `tests/server/conftest.py` (new)
- Test: `tests/server/test_config.py` (new)
- Test: `tests/server/test_crypto.py` (new)
- Test: `tests/conftest.py` (changed)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:
  - `phishhawk.server.config`: `SECRETS_DIR`; `class ServerSettings(BaseSettings)`: `data_dir: Path`; `database_url: str`; `secret_key: SecretStr`; `encryption_key: SecretStr`; `retention_days: int`; `max_upload_mb: int`; `max_batch_messages: int`; `campaign_window_days: int`; `host: str`; `port: int`; `tls_cert: str`; `tls_key: str`; `session_idle_minutes: int`; `analysis_memory_mb: int`; `analysis_cpu_seconds: int`; `cookie_secure: bool`; `property db_url() -> str`; `load_settings() -> ServerSettings`
  - `phishhawk.server.crypto`: `MAGIC`; `class DecryptError(Exception)`; `new_key() -> str`; `class Box`: `__init__(key: bytes) -> None`; `from_b64(text: str) -> Box`; `seal(data: bytes, bound_to: str) -> bytes`; `open(sealed: bytes, bound_to: str) -> bytes`

**Notes:**

- pydantic-settings reads `/run/secrets/phishhawk_<name>` when that folder exists. A variable wins over a file. The two keys have no defaults, so a missing key fails at start-up.
- A sealed value is `PHB1` + 12-byte nonce + ciphertext and tag. The ID is the associated data: a value copied onto another record does not open.
- `tests/conftest.py` stops collecting `tests/server` when FastAPI is missing, so the base install's 690 tests run exactly as before.
- The base CI job now reports coverage without `phishhawk/server` (its tests do not run there); the new `server` job runs everything, with coverage, on Python 3.10 to 3.13. pip-audit now covers the extra.
- `httpx2` joins the dev extra: Starlette's TestClient prefers it and warns about `httpx`.
- Tests make keys at run time with `new_key()`, never as literals, so the secret scan stays clean.

- [ ] **Step 1: Prepare**

Change `pyproject.toml` (apply with `git apply`, or edit by hand):

```diff
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -26,7 +26,10 @@
 
 [project.optional-dependencies]
 dev = ["pytest>=7.4", "ruff>=0.6", "mypy>=1.10", "types-requests", "coverage>=7.4", "stix2>=3.0", "segno>=1.5",
-       "zxing-cpp>=2.2", "Pillow>=10.0", "jsonschema>=4.18", "hypothesis>=6.80"]
+       "zxing-cpp>=2.2", "Pillow>=10.0", "jsonschema>=4.18", "hypothesis>=6.80", "httpx2>=2.13"]
+# the web app: phishhawk server (docs/SERVER.md)
+server = ["fastapi>=0.142", "uvicorn>=0.30", "jinja2>=3.1.6", "sqlalchemy>=2.0.30", "alembic>=1.13",
+          "argon2-cffi>=23.1", "cryptography>=44.0.1", "python-multipart>=0.0.18", "pydantic-settings>=2.4"]
 # decode QR codes in images, PDFs and drawn tables (quishing)
 qr = ["zxing-cpp>=2.2", "Pillow>=10.0"]
 # run your own YARA rules over messages and every file inside them
@@ -52,6 +55,7 @@
 [tool.setuptools.package-data]
 # the HTML report embeds these fonts; licences travel with them
 "phishhawk.report" = ["fonts/*.woff2", "fonts/*.txt", "fonts/*.md"]
+"phishhawk.server" = ["templates/*.html", "static/*", "migrations/script.py.mako"]
 
 [tool.pytest.ini_options]
 testpaths = ["tests"]
```
Run:

```bash
python -m pip install -e ".[dev,server]"
```

- [ ] **Step 2: Write the failing tests**

Change `tests/conftest.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/conftest.py
+++ b/tests/conftest.py
@@ -1,7 +1,11 @@
 """Shared fixtures. Everything is offline: API clients get fake sessions."""
 
+import importlib.util
 import os
 from email.message import EmailMessage
+
+# The web app's tests need the [server] extra; without it they are not collected.
+collect_ignore = [] if importlib.util.find_spec("fastapi") else ["server"]
 
 SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
 
```

Create `tests/server/__init__.py`:

```python

```

Create `tests/server/conftest.py`:

```python
"""Fixtures for the web app's tests, all in a temporary directory."""

import pytest

from phishhawk.server.config import ServerSettings
from phishhawk.server.crypto import Box, new_key


@pytest.fixture
def settings(tmp_path):
    return ServerSettings(data_dir=tmp_path, secret_key=new_key(),
                          encryption_key=new_key(), cookie_secure=False)


@pytest.fixture
def box(settings):
    return Box.from_b64(settings.encryption_key.get_secret_value())
```

Create `tests/server/test_config.py`:

```python
"""Settings come from PHISHHAWK_* variables and Docker secret files; the
keys have no defaults."""

import pytest
from pydantic import ValidationError

from phishhawk.server import config
from phishhawk.server.crypto import new_key


@pytest.fixture
def secrets_dir(monkeypatch, tmp_path):
    for name in ("PHISHHAWK_SECRET_KEY", "PHISHHAWK_ENCRYPTION_KEY", "PHISHHAWK_RETENTION_DAYS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "SECRETS_DIR", str(tmp_path))
    return tmp_path


def test_settings_come_from_the_environment_with_defaults_for_the_rest(secrets_dir, monkeypatch):
    key = new_key()
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", "s" * 32)
    monkeypatch.setenv("PHISHHAWK_ENCRYPTION_KEY", key)
    monkeypatch.setenv("PHISHHAWK_RETENTION_DAYS", "7")
    settings = config.load_settings()
    assert settings.encryption_key.get_secret_value() == key and settings.retention_days == 7
    assert settings.max_upload_mb == 25 and settings.host == "127.0.0.1" and settings.cookie_secure
    assert settings.db_url == "sqlite:///%s" % (settings.data_dir / "phishhawk.sqlite3")
    assert key not in repr(settings)


def test_docker_secret_files_are_read_and_a_variable_wins_over_a_file(secrets_dir, monkeypatch):
    key = new_key()
    (secrets_dir / "phishhawk_secret_key").write_text("from-the-file\n")
    (secrets_dir / "phishhawk_encryption_key").write_text(key + "\n")
    assert config.load_settings().encryption_key.get_secret_value() == key
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", "from-the-variable")
    assert config.load_settings().secret_key.get_secret_value() == "from-the-variable"


def test_the_keys_have_no_defaults(secrets_dir):
    with pytest.raises(ValidationError) as caught:
        config.load_settings()
    assert {error["loc"][0] for error in caught.value.errors()} == {"secret_key", "encryption_key"}
```

Create `tests/server/test_crypto.py`:

```python
"""AES-256-GCM sealing: a fresh nonce every time, and keys checked."""

import pytest

from phishhawk.server.crypto import Box, DecryptError, new_key


def test_a_sealed_value_opens_only_with_its_key_and_its_id(box):
    sealed = box.seal(b"evidence", "a" * 32)
    assert box.open(sealed, "a" * 32) == b"evidence"
    for other_box, bound_to, value in ((box, "b" * 32, sealed), (Box.from_b64(new_key()), "a" * 32, sealed),
                                       (box, "a" * 32, b"not a sealed value at all, just bytes")):
        with pytest.raises(DecryptError):
            other_box.open(value, bound_to)


def test_each_seal_uses_a_fresh_nonce(box):
    first, second = box.seal(b"same", "a" * 32), box.seal(b"same", "a" * 32)
    assert first != second and first[4:16] != second[4:16]


def test_a_bad_key_or_blob_id_is_refused():
    with pytest.raises(ValueError):
        Box.from_b64("too-short")
    with pytest.raises(ValueError):
        Box(b"x" * 16)
```

- [ ] **Step 3: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_config.py tests/server/test_crypto.py
```

Expected: FAIL. The first error is `ModuleNotFoundError: No module named 'phishhawk.server'`.

- [ ] **Step 4: Write the code**

Create `src/phishhawk/server/__init__.py`:

```python
"""PhishHawk's optional self-hosted web app. Install with
`pip install "phishhawk[server]"`; the engine and CLI never import it."""
```

Create `src/phishhawk/server/config.py`:

```python
"""Server settings, read from PHISHHAWK_* environment variables and, when it
exists, from Docker secret files in /run/secrets. Secrets are never defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

SECRETS_DIR = "/run/secrets"


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISHHAWK_", extra="ignore")

    data_dir: Path = Path("/var/lib/phishhawk")
    database_url: str = ""  # empty: SQLite at <data_dir>/phishhawk.sqlite3
    secret_key: SecretStr  # keys the session HMAC; a new value logs everyone out
    encryption_key: SecretStr  # 32 bytes, base64: encrypts every blob and stored secret
    retention_days: int = 30
    max_upload_mb: int = 25
    max_batch_messages: int = 500
    campaign_window_days: int = 90
    host: str = "127.0.0.1"
    port: int = 8000
    tls_cert: str = ""
    tls_key: str = ""
    session_idle_minutes: int = 480
    analysis_memory_mb: int = 2048
    analysis_cpu_seconds: int = 120
    cookie_secure: bool = True  # False only for plain-HTTP local testing

    @property
    def db_url(self) -> str:
        return self.database_url or "sqlite:///%s" % (self.data_dir / "phishhawk.sqlite3")


def load_settings() -> ServerSettings:
    """Settings from the environment and, when the folder exists, from Docker
    secret files; a variable wins over a file."""
    build: Any = ServerSettings  # the required fields come from outside, where mypy cannot see them
    settings: ServerSettings = build(_secrets_dir=SECRETS_DIR if os.path.isdir(SECRETS_DIR) else None)
    return settings
```

Create `src/phishhawk/server/crypto.py`:

```python
"""AES-256-GCM sealing for blobs and stored secrets. Each sealed value has a
fresh 96-bit nonce and is bound to its ID as associated data, so a value
copied onto another record does not decrypt."""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PHB1"


class DecryptError(Exception):
    """Wrong key, a value bound to another ID, or a damaged value."""


def new_key() -> str:
    """A fresh key in the form PHISHHAWK_ENCRYPTION_KEY expects."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


class Box:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("the encryption key must be 32 bytes")
        self._aead = AESGCM(key)

    @classmethod
    def from_b64(cls, text: str) -> Box:
        try:
            return cls(base64.b64decode(text.strip(), validate=True))
        except (binascii.Error, ValueError) as exc:
            raise ValueError("PHISHHAWK_ENCRYPTION_KEY must be 32 bytes in base64") from exc

    def seal(self, data: bytes, bound_to: str) -> bytes:
        nonce = os.urandom(12)
        return MAGIC + nonce + self._aead.encrypt(nonce, data, bound_to.encode("utf-8"))

    def open(self, sealed: bytes, bound_to: str) -> bytes:
        if not sealed.startswith(MAGIC) or len(sealed) < len(MAGIC) + 12 + 16:
            raise DecryptError("not a sealed value")
        nonce, body = sealed[4:16], sealed[16:]
        try:
            return self._aead.decrypt(nonce, body, bound_to.encode("utf-8"))
        except InvalidTag as exc:
            raise DecryptError("wrong key, wrong record, or damaged") from exc
```

Change `.github/workflows/ci.yml` (apply with `git apply`, or edit by hand):

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -33,9 +33,10 @@
       - name: Optional YARA support (skipped by the tests if it will not install)
         run: python -m pip install yara-python || echo "yara-python unavailable; YARA tests will skip"
       - name: Unit tests, evaluation gate and coverage
+        # the web app's tests skip without its extra; the server job covers them
         run: |
           coverage run -m pytest
-          coverage report
+          coverage report --omit='*/phishhawk/server/*'
       - name: Smoke-test every command
         # Exit code 1 means "suspicious": expected, since most samples are phishing.
         run: |
@@ -68,7 +69,7 @@
       - name: Known vulnerabilities in everything PhishHawk installs (pip-audit)
         run: |
           python -m venv "$RUNNER_TEMP/runtime"
-          "$RUNNER_TEMP/runtime/bin/pip" install ".[qr]"
+          "$RUNNER_TEMP/runtime/bin/pip" install ".[qr,server]"
           "$RUNNER_TEMP/runtime/bin/pip" freeze --exclude-editable | grep -v '^phishhawk' > "$RUNNER_TEMP/runtime.txt"
           cat "$RUNNER_TEMP/runtime.txt"
           python -m pip install pip-audit
@@ -83,6 +84,29 @@
           echo "$SHA256  $RUNNER_TEMP/gitleaks.tgz" | sha256sum -c -
           tar -xzf "$RUNNER_TEMP/gitleaks.tgz" -C "$RUNNER_TEMP" gitleaks
           "$RUNNER_TEMP/gitleaks" detect --source . --redact --no-banner --verbose
+
+  server:
+    name: web app (python ${{ matrix.python }})
+    runs-on: ubuntu-latest
+    strategy:
+      fail-fast: false
+      matrix:
+        python: ["3.10", "3.11", "3.12", "3.13"]
+    steps:
+      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
+      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
+        with:
+          python-version: ${{ matrix.python }}
+          cache: pip
+          cache-dependency-path: pyproject.toml
+      - name: Install with the web app's dependencies
+        run: python -m pip install -e ".[dev,server]"
+      - name: Type check
+        run: mypy
+      - name: Every test, the web app's included, and coverage
+        run: |
+          coverage run -m pytest
+          coverage report
 
   installer:
     runs-on: ubuntu-latest
```

- [ ] **Step 5: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_config.py tests/server/test_crypto.py
```
Expected: 6 passed.

```bash
python -m pytest
```
Expected: 698 passed, 1 skipped.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml pyproject.toml src/phishhawk/server/__init__.py src/phishhawk/server/config.py src/phishhawk/server/crypto.py tests/conftest.py tests/server/__init__.py tests/server/conftest.py tests/server/test_config.py tests/server/test_crypto.py
git commit -m "Start the web app package: settings, encryption and a CI job for the server extra"
```

### Task 3: Database models and migrations

*PR 2.*

Every table M1 needs, as SQLAlchemy 2 models, with the first Alembic migration and a test that the two agree. SQLite runs in WAL mode and every transaction starts with `BEGIN IMMEDIATE`, so writers queue instead of failing halfway.

**Files:**

- Create: `src/phishhawk/server/models.py`
- Create: `src/phishhawk/server/db.py`
- Create: `src/phishhawk/server/migrations/env.py`
- Create: `src/phishhawk/server/migrations/script.py.mako`
- Create: `src/phishhawk/server/migrations/versions/0001_initial_schema.py`
- Test: `tests/server/test_migrations.py` (new)
- Test: `tests/server/test_db.py` (new)
- Test: `tests/server/conftest.py` (changed)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:
  - `phishhawk.server.models`: `utcnow() -> dt.datetime`; `class UTCDateTime(TypeDecorator[dt.datetime])`: `process_bind_param(value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None`; `process_result_value(value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None`; `class Base(DeclarativeBase)`; `class User(Base)`: `id: Mapped[int]`; `username: Mapped[str]`; `password_hash: Mapped[str]`; `role: Mapped[str]`; `disabled: Mapped[bool]`; `created_at: Mapped[dt.datetime]`; `last_login_at: Mapped[dt.datetime | None]`; `class Session(Base)`: `id: Mapped[str]`; `user_id: Mapped[int]`; `csrf_token: Mapped[str]`; `created_at: Mapped[dt.datetime]`; `last_seen_at: Mapped[dt.datetime]`; `class ApiToken(Base)`: `id: Mapped[int]`; `user_id: Mapped[int]`; `name: Mapped[str]`; `token_hash: Mapped[str]`; `scope: Mapped[str]`; `created_at: Mapped[dt.datetime]`; `last_used_at: Mapped[dt.datetime | None]`; `revoked_at: Mapped[dt.datetime | None]`; `class Message(Base)`: `id: Mapped[int]`; `sha256: Mapped[str]`; `size: Mapped[int]`; `raw_blob: Mapped[str | None]`; `first_seen_at: Mapped[dt.datetime]`; `tier1_deleted_at: Mapped[dt.datetime | None]`; `deletion_reason: Mapped[str]`; `hold: Mapped[bool]`; `sender: Mapped[str]`; `sender_domain: Mapped[str]`; `recipient_count: Mapped[int]`; `class Submission(Base)`: `id: Mapped[int]`; `message_id: Mapped[int]`; `user_id: Mapped[int | None]`; `source: Mapped[str]`; `offline: Mapped[bool]`; `status: Mapped[str]`; `error: Mapped[str]`; `submitted_at: Mapped[dt.datetime]`; `class Analysis(Base)`: `id: Mapped[int]`; `message_id: Mapped[int]`; `submission_id: Mapped[int]`; `engine_version: Mapped[str]`; `report_id: Mapped[str]`; `verdict: Mapped[str]`; `score: Mapped[int]`; `providers: Mapped[list[Any]]`; `lookups: Mapped[list[Any]]`; `techniques: Mapped[list[Any]]`; `traits: Mapped[dict[str, Any]]`; `files: Mapped[list[Any]]`; `data_blob: Mapped[str | None]`; `created_at: Mapped[dt.datetime]`; `class Indicator(Base)`: `id: Mapped[int]`; `analysis_id: Mapped[int]`; `type: Mapped[str]`; `value: Mapped[str]`; `class Job(Base)`: `id: Mapped[int]`; `kind: Mapped[str]`; `payload: Mapped[dict[str, Any]]`; `status: Mapped[str]`; `attempts: Mapped[int]`; `error: Mapped[str]`; `created_at: Mapped[dt.datetime]`; `started_at: Mapped[dt.datetime | None]`; `heartbeat_at: Mapped[dt.datetime | None]`; `finished_at: Mapped[dt.datetime | None]`; `class Setting(Base)`: `key: Mapped[str]`; `value: Mapped[Any]`; `class AuditRecord(Base)`: `id: Mapped[int]`; `at: Mapped[dt.datetime]`; `actor: Mapped[str]`; `action: Mapped[str]`; `object_type: Mapped[str]`; `object_id: Mapped[str]`; `details: Mapped[dict[str, Any]]`; `prev_hash: Mapped[str]`; `hash: Mapped[str]`; `class AuditHead(Base)`: `id: Mapped[int]`; `hash: Mapped[str]`; `count: Mapped[int]`
  - `phishhawk.server.db`: `make_engine(url: str) -> Engine`; `make_sessionmaker(engine: Engine) -> sessionmaker[Session]`; `transaction(factory: sessionmaker[Session]) -> Iterator[Session]`; `alembic_config(url: str) -> Config`; `migrate(url: str) -> None`
  - `phishhawk.server.migrations.versions.0001_initial_schema`: `upgrade() -> None`; `downgrade() -> None`

**Notes:**

- `isolation_level=None` plus a `begin` event that issues `BEGIN IMMEDIATE`: the audit chain and job claiming both rely on one writer at a time.
- `UTCDateTime` stores timezone-aware UTC and hands back aware datetimes; SQLite would otherwise return naive ones and the audit hashes would not match on reading.
- JSON columns name `JSON` explicitly: SQLAlchemy 2.0 cannot map `list[Any]` from an annotation.
- `submissions` has no `analysis_id`; an analysis points at its submission. That avoids a circular foreign key that Postgres cannot create in one migration.
- The migration was generated with `alembic revision --autogenerate` (config from `db.alembic_config()`) and the `UTCDateTime` type replaced by `sa.DateTime(timezone=True)`. `test_migrations.py` fails whenever a model changes without a migration.
- Messages hold tier 1 only as blob IDs (`raw_blob`, `data_blob`, `files[].blob`); the blobs live in the encrypted store (task 4).

- [ ] **Step 1: Write the failing tests**

Change `tests/server/conftest.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/conftest.py
+++ b/tests/server/conftest.py
@@ -4,6 +4,7 @@
 
 from phishhawk.server.config import ServerSettings
 from phishhawk.server.crypto import Box, new_key
+from phishhawk.server.db import make_engine, make_sessionmaker, migrate
 
 
 @pytest.fixture
@@ -13,5 +14,11 @@
 
 
 @pytest.fixture
+def db(settings):
+    migrate(settings.db_url)
+    return make_sessionmaker(make_engine(settings.db_url))
+
+
+@pytest.fixture
 def box(settings):
     return Box.from_b64(settings.encryption_key.get_secret_value())
```

Create `tests/server/test_migrations.py`:

```python
"""The migrations build exactly the tables the models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from phishhawk.server.db import make_engine, migrate
from phishhawk.server.models import Base


def test_the_migrations_match_the_models(settings):
    migrate(settings.db_url)
    with make_engine(settings.db_url).connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
```

Create `tests/server/test_db.py`:

```python
"""SQLite runs in WAL mode with foreign keys on, and a transaction commits
everything or nothing."""

import pytest
from sqlalchemy import select, text

from phishhawk.server.db import make_engine, transaction
from phishhawk.server.models import Setting


def test_sqlite_uses_wal_and_enforces_foreign_keys(settings, db):
    with make_engine(settings.db_url).connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_a_transaction_commits_on_success_and_rolls_back_on_error(db):
    with transaction(db) as s:
        s.add(Setting(key="kept", value=1))
    with pytest.raises(RuntimeError), transaction(db) as s:
        s.add(Setting(key="lost", value=2))
        s.flush()
        raise RuntimeError("stop")
    with transaction(db) as s:
        assert [row.key for row in s.scalars(select(Setting))] == ["kept"]
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_migrations.py tests/server/test_db.py
```

Expected: FAIL. The first error is `ModuleNotFoundError: No module named 'phishhawk.server.db'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/models.py`:

```python
"""Database tables. Tier-2 data only: message content lives in encrypted
blobs (store.py), referred to here by blob ID."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Dialect, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class UTCDateTime(TypeDecorator[dt.datetime]):
    """Always an aware UTC datetime in Python, whatever the database keeps
    (SQLite keeps none)."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None:
        return value.astimezone(dt.timezone.utc) if value is not None and value.tzinfo else value

    def process_result_value(self, value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None:
        return value.replace(tzinfo=dt.timezone.utc) if value is not None and value.tzinfo is None else value


class Base(DeclarativeBase):
    type_annotation_map = {dt.datetime: UTCDateTime()}


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # "admin" or "analyst"
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 of the cookie value
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scope: Mapped[str] = mapped_column(String(16))  # "read" or "submit"
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    size: Mapped[int] = mapped_column(Integer)
    raw_blob: Mapped[str | None] = mapped_column(String(32))  # None once tier 1 is deleted
    first_seen_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    tier1_deleted_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    deletion_reason: Mapped[str] = mapped_column(String(16), default="")  # "retention" or "manual"
    hold: Mapped[bool] = mapped_column(Boolean, default=False)
    sender: Mapped[str] = mapped_column(String(320), default="")
    sender_domain: Mapped[str] = mapped_column(String(255), default="")
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)


class Submission(Base):
    __tablename__ = "submissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(16))  # "upload", "paste" (M2: "batch", M3: "mailbox")
    offline: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    error: Mapped[str] = mapped_column(Text, default="")
    submitted_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    submission_id: Mapped[int] = mapped_column(ForeignKey("submissions.id", ondelete="CASCADE"))
    engine_version: Mapped[str] = mapped_column(String(32))
    report_id: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[str] = mapped_column(String(32))
    score: Mapped[int] = mapped_column(Integer)
    providers: Mapped[list[Any]] = mapped_column(JSON, default=list)  # provider names asked
    lookups: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{"provider", "method", "url"}]
    techniques: Mapped[list[Any]] = mapped_column(JSON, default=list)
    traits: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # campaign record, subject and name as HMAC
    files: Mapped[list[Any]] = mapped_column(JSON, default=list)  # manifest entries plus "blob"
    data_blob: Mapped[str | None] = mapped_column(String(32))  # full JSON report (tier 1)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (Index("ix_indicators_value", "value"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_status", "status", "id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)  # secrets: base64 of a sealed value


class AuditRecord(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))  # a username, "system" or "token:<name>"
    action: Mapped[str] = mapped_column(String(48))
    object_type: Mapped[str] = mapped_column(String(32), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditHead(Base):
    """One row: the newest record's hash, so a cut-off tail is noticed too."""
    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(primary_key=True)
    hash: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer)
```

Create `src/phishhawk/server/db.py`:

```python
"""Engine, sessions and migrations. SQLite runs every transaction as BEGIN
IMMEDIATE, so the web and worker processes never interleave writes (the
audit chain depends on it); Postgres locks the audit head row instead."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def make_engine(url: str) -> Engine:
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _sqlite_connect(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None  # let us issue BEGIN ourselves
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _sqlite_begin(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session, session.begin():
        yield session


def alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(files("phishhawk.server") / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def migrate(url: str) -> None:
    """Bring the database to the newest schema."""
    command.upgrade(alembic_config(url), "head")
```

Create `src/phishhawk/server/migrations/env.py`:

```python
from alembic import context
from sqlalchemy import engine_from_config, pool

from phishhawk.server.models import Base

config = context.config
connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.",
                                 poolclass=pool.NullPool)
with connectable.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata,
                      render_as_batch=connection.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()
```

Create `src/phishhawk/server/migrations/script.py.mako`:

```mako
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = None
depends_on = None


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
```

Create `src/phishhawk/server/migrations/versions/0001_initial_schema.py`:

```python
"""initial schema

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "audit_head",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=48), nullable=False),
        sa.Column("object_type", sa.String(length=32), nullable=False),
        sa.Column("object_id", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("jobs", schema=None) as batch_op:
        batch_op.create_index("ix_jobs_status", ["status", "id"], unique=False)

    op.create_table(
        "messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("raw_blob", sa.String(length=32), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tier1_deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deletion_reason", sa.String(length=16), nullable=False),
        sa.Column("hold", sa.Boolean(), nullable=False),
        sa.Column("sender", sa.String(length=320), nullable=False),
        sa.Column("sender_domain", sa.String(length=255), nullable=False),
        sa.Column("recipient_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256"),
    )
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "submissions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("offline", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "analyses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=False),
        sa.Column("submission_id", sa.Integer(), nullable=False),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("report_id", sa.String(length=32), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("providers", sa.JSON(), nullable=False),
        sa.Column("lookups", sa.JSON(), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=False),
        sa.Column("traits", sa.JSON(), nullable=False),
        sa.Column("files", sa.JSON(), nullable=False),
        sa.Column("data_blob", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["submission_id"], ["submissions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("indicators", schema=None) as batch_op:
        batch_op.create_index("ix_indicators_value", ["value"], unique=False)

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("indicators", schema=None) as batch_op:
        batch_op.drop_index("ix_indicators_value")

    op.drop_table("indicators")
    op.drop_table("analyses")
    op.drop_table("submissions")
    op.drop_table("sessions")
    op.drop_table("api_tokens")
    op.drop_table("users")
    op.drop_table("settings")
    op.drop_table("messages")
    with op.batch_alter_table("jobs", schema=None) as batch_op:
        batch_op.drop_index("ix_jobs_status")

    op.drop_table("jobs")
    op.drop_table("audit_log")
    op.drop_table("audit_head")
    # ### end Alembic commands ###
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_migrations.py tests/server/test_db.py
```
Expected: 3 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/db.py src/phishhawk/server/migrations/env.py src/phishhawk/server/migrations/script.py.mako src/phishhawk/server/migrations/versions/0001_initial_schema.py src/phishhawk/server/models.py tests/server/conftest.py tests/server/test_db.py tests/server/test_migrations.py
git commit -m "Add the web app's database models and first migration"
```

### Task 4: Encrypted blob store

*PR 2.*

Tier 1 (the raw message, the full JSON report and the exports) is kept as sealed files under `<data_dir>/blobs`, named by random IDs and never written in clear.

**Files:**

- Create: `src/phishhawk/server/store.py`
- Test: `tests/server/test_store.py` (new)
- Test: `tests/server/conftest.py` (changed)

**Interfaces:**

- Consumes:
  - `phishhawk.server.crypto` (task 2): `class Box`; `class DecryptError(Exception)`
- Produces:
  - `phishhawk.server.store`: `class BlobStore`: `__init__(root: Path, box: Box) -> None`; `put(data: bytes) -> str`; `get(blob_id: str) -> bytes`; `delete(blob_id: str | None) -> None`; `reseal(blob_id: str, new_box: Box) -> bool`

**Notes:**

- Files are written to a temporary name with mode 0600, then renamed into place.
- A blob ID must be 32 lowercase hex characters; anything else is refused before it touches a path.
- `reseal()` returns False for a blob that already opens under the new key, which is what lets key rotation (task 10) be run again after a crash.

- [ ] **Step 1: Write the failing tests**

Change `tests/server/conftest.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/conftest.py
+++ b/tests/server/conftest.py
@@ -5,6 +5,7 @@
 from phishhawk.server.config import ServerSettings
 from phishhawk.server.crypto import Box, new_key
 from phishhawk.server.db import make_engine, make_sessionmaker, migrate
+from phishhawk.server.store import BlobStore
 
 
 @pytest.fixture
@@ -22,3 +23,8 @@
 @pytest.fixture
 def box(settings):
     return Box.from_b64(settings.encryption_key.get_secret_value())
+
+
+@pytest.fixture
+def store(settings, box):
+    return BlobStore(settings.data_dir / "blobs", box)
```

Create `tests/server/test_store.py`:

```python
"""Tier-1 data is sealed with AES-256-GCM, bound to its blob ID."""

import os
import stat

import pytest

from phishhawk.server.crypto import Box, DecryptError, new_key


def test_a_blob_round_trips_and_is_not_stored_in_clear(store):
    blob_id = store.put(b"Subject: payroll\r\n\r\nsecret body")
    assert store.get(blob_id) == b"Subject: payroll\r\n\r\nsecret body"
    on_disk = store._path(blob_id).read_bytes()
    assert b"payroll" not in on_disk and b"secret body" not in on_disk
    assert stat.S_IMODE(os.stat(store._path(blob_id)).st_mode) == 0o600


def test_a_blob_copied_onto_another_id_does_not_open(store):
    one, two = store.put(b"one"), store.put(b"two")
    store._path(two).write_bytes(store._path(one).read_bytes())
    with pytest.raises(DecryptError):
        store.get(two)


def test_the_wrong_key_does_not_open_a_blob(store, settings):
    blob_id = store.put(b"evidence")
    other = Box.from_b64(new_key())
    with pytest.raises(DecryptError):
        other.open(store._path(blob_id).read_bytes(), blob_id)


def test_reseal_moves_a_blob_to_a_new_key(store):
    blob_id = store.put(b"evidence")
    new_box = Box.from_b64(new_key())
    store.reseal(blob_id, new_box)
    assert new_box.open(store._path(blob_id).read_bytes(), blob_id) == b"evidence"


def test_blob_ids_cannot_reach_outside_the_store(store):
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_store.py
```

Expected: FAIL. The first error is `ModuleNotFoundError: No module named 'phishhawk.server.store'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/store.py`:

```python
"""Encrypted blob store: tier-1 data (raw messages, full JSON reports and
exports) as sealed files under <data_dir>/blobs, named by random IDs."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .crypto import Box, DecryptError


class BlobStore:
    def __init__(self, root: Path, box: Box) -> None:
        self.root = root
        self.box = box

    def _path(self, blob_id: str) -> Path:
        if len(blob_id) != 32 or not all(c in "0123456789abcdef" for c in blob_id):
            raise ValueError("not a blob ID")
        return self.root / blob_id[:2] / blob_id

    def put(self, data: bytes) -> str:
        blob_id = secrets.token_hex(16)
        path = self._path(blob_id)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.box.seal(data, blob_id))
        os.replace(temp, path)
        return blob_id

    def get(self, blob_id: str) -> bytes:
        return self.box.open(self._path(blob_id).read_bytes(), blob_id)

    def delete(self, blob_id: str | None) -> None:
        if blob_id:
            self._path(blob_id).unlink(missing_ok=True)

    def reseal(self, blob_id: str, new_box: Box) -> bool:
        """Re-encrypt one blob under a new key (key rotation). False when it
        already opens under the new key, so a rotation can be run again."""
        path = self._path(blob_id)
        sealed = path.read_bytes()
        try:
            new_box.open(sealed, blob_id)
            return False
        except DecryptError:
            pass
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(new_box.seal(self.box.open(sealed, blob_id), blob_id))
        os.replace(temp, path)
        return True
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_store.py
```
Expected: 5 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/store.py tests/server/conftest.py tests/server/test_store.py
git commit -m "Add the encrypted blob store for tier-1 data"
```

### Task 5: Hash-chained audit log

*PR 3.*

Every action is appended to `audit_log` with the hash of the record before it; `audit_head` keeps the newest hash and the count, so an edited, removed, reordered or cut-off record is reported by `verify()`.

**Files:**

- Create: `src/phishhawk/server/audit.py`
- Test: `tests/server/test_audit.py` (new)

**Interfaces:**

- Consumes:
  - `phishhawk.server.models` (task 3): `class AuditHead(Base)`; `class AuditRecord(Base)`; `utcnow() -> dt.datetime`
- Produces:
  - `phishhawk.server.audit`: `GENESIS`; `record(db: Session, actor: str, action: str, object_type: str='', object_id: object='', details: dict[str, Any] | None=None) -> AuditRecord`; `verify(db: Session) -> list[str]`

**Notes:**

- `record()` writes inside the caller's transaction, so an action and its audit record commit together.
- Timestamps are stored to the second, in UTC, and hashed in one canonical JSON form.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_audit.py`:

```python
"""The audit log is hash-chained: edits, removals, reordering and a cut-off
tail are all reported by verify()."""

from sqlalchemy import delete, select, update

from phishhawk.server import audit
from phishhawk.server.db import transaction
from phishhawk.server.models import AuditHead, AuditRecord


def _three(db):
    with transaction(db) as s:
        audit.record(s, "admin", "login")
        audit.record(s, "admin", "submit", "submission", 1, {"source": "upload"})
        audit.record(s, "system", "analyze", "analysis", 1, {"providers": []})


def test_an_untouched_log_verifies(db):
    _three(db)
    with transaction(db) as s:
        assert audit.verify(s) == []
        assert s.scalars(select(AuditHead)).one().count == 3


def test_an_edited_record_is_reported(db):
    _three(db)
    with transaction(db) as s:
        s.execute(update(AuditRecord).where(AuditRecord.id == 2).values(actor="someone-else"))
    with transaction(db) as s:
        assert audit.verify(s) == ["record 2 was changed"]


def test_a_removed_record_is_reported(db):
    _three(db)
    with transaction(db) as s:
        s.execute(delete(AuditRecord).where(AuditRecord.id == 2))
    with transaction(db) as s:
        assert "record 3 does not follow the one before it" in audit.verify(s)


def test_a_cut_off_tail_is_reported(db):
    _three(db)
    with transaction(db) as s:
        s.execute(delete(AuditRecord).where(AuditRecord.id == 3))
    with transaction(db) as s:
        assert audit.verify(s) == ["the newest records are missing (3 recorded, 2 found)"]


def test_reordered_records_are_reported(db):
    _three(db)
    with transaction(db) as s:
        for old, new in ((2, 99), (3, 2), (99, 3)):
            s.execute(update(AuditRecord).where(AuditRecord.id == old).values(id=new))
    with transaction(db) as s:
        assert "record 2 does not follow the one before it" in audit.verify(s)
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_audit.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'audit' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/audit.py`:

```python
"""Append-only audit log. Each record's hash covers the previous record's
hash, and the audit_head row keeps the newest hash and the count, so an
edited, removed, reordered or cut-off record is reported by verify()."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditHead, AuditRecord, utcnow

GENESIS = "0" * 64


def _stamp(at: dt.datetime) -> str:
    """UTC, without an offset: SQLite hands datetimes back without one."""
    if at.tzinfo is not None:
        at = at.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return at.isoformat()


def _digest(prev_hash: str, record: AuditRecord) -> str:
    body = {"at": _stamp(record.at), "actor": record.actor, "action": record.action,
            "object_type": record.object_type, "object_id": record.object_id, "details": record.details}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def record(db: Session, actor: str, action: str, object_type: str = "", object_id: object = "",
           details: dict[str, Any] | None = None) -> AuditRecord:
    """Append one record inside the caller's transaction."""
    head = db.scalars(select(AuditHead).with_for_update()).first()
    if head is None:
        head = AuditHead(id=1, hash=GENESIS, count=0)
        db.add(head)
    entry = AuditRecord(at=utcnow().replace(microsecond=0), actor=actor, action=action, object_type=object_type,
                        object_id=str(object_id), details=details or {}, prev_hash=head.hash)
    entry.hash = _digest(head.hash, entry)
    db.add(entry)
    head.hash, head.count = entry.hash, head.count + 1
    db.flush()
    return entry


def verify(db: Session) -> list[str]:
    """Problems found, or an empty list when the log is intact."""
    problems: list[str] = []
    prev, count = GENESIS, 0
    for entry in db.scalars(select(AuditRecord).order_by(AuditRecord.id)):
        count += 1
        if entry.prev_hash != prev:
            problems.append("record %d does not follow the one before it" % entry.id)
        if entry.hash != _digest(entry.prev_hash, entry):
            problems.append("record %d was changed" % entry.id)
        prev = entry.hash
    head = db.scalars(select(AuditHead)).first()
    if head is not None and (head.hash != prev or head.count != count):
        problems.append("the newest records are missing (%d recorded, %d found)" % (head.count, count))
    return problems
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_audit.py
```
Expected: 5 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/audit.py tests/server/test_audit.py
git commit -m "Add the hash-chained audit log and its verification"
```

### Task 6: Users, sessions, API tokens and the login throttle

*PR 3.*

Local accounts with two roles (admin, analyst), argon2id passwords, server-side sessions keyed by an HMAC under `SECRET_KEY`, API tokens scoped to `read` or `submit`, and a throttle that slows repeated wrong passwords.

**Files:**

- Create: `src/phishhawk/server/auth.py`
- Test: `tests/server/test_auth.py` (new)

**Interfaces:**

- Consumes:
  - `phishhawk.server.models` (task 3): `class ApiToken(Base)`; `class Session(Base)`; `class User(Base)`; `utcnow() -> dt.datetime`
- Produces:
  - `phishhawk.server.auth`: `ROLES`; `TOKEN_SCOPES`; `USERNAME_RE`; `MIN_PASSWORD`; `class AuthError(ValueError)`; `class Actor`: `user_id: int`; `username: str`; `role: str`; `via: str`; `scope: str`; `csrf: str`; `label: str`; `property is_admin() -> bool`; `digest(token: str) -> str`; `session_id(secret: str, cookie: str) -> str`; `create_user(db: DbSession, username: str, password: str, role: str) -> User`; `set_password(user: User, password: str) -> None`; `check_login(db: DbSession, username: str, password: str) -> User | None`; `open_session(db: DbSession, user: User, secret: str) -> tuple[str, Session]`; `find_session(db: DbSession, cookie: str, secret: str, idle_minutes: int) -> Actor | None`; `close_session(db: DbSession, cookie: str, secret: str) -> None`; `create_token(db: DbSession, user: User, name: str, scope: str) -> str`; `find_token(db: DbSession, token: str) -> Actor | None`; `class LoginThrottle`: `__init__(clock: object=time.monotonic) -> None`; `wait(*keys: str) -> float`; `failed(*keys: str) -> None`; `succeeded(*keys: str) -> None`

**Notes:**

- Only hashes are stored: the session ID is HMAC-SHA256(SECRET_KEY, cookie) and a token is stored as its SHA-256. A copy of the database logs nobody in; a new `SECRET_KEY` ends every session.
- `check_login()` hashes a password even for an unknown user, so timing does not reveal usernames.
- `Actor.is_admin` is true only for a logged-in admin session: an API token never has admin powers.
- After three failures for a user or an address, each further try waits twice as long, up to 300 s.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_auth.py`:

```python
"""Users, sessions, API tokens and the login throttle."""

import datetime as dt

import pytest
from sqlalchemy import select

from phishhawk.server import auth
from phishhawk.server.crypto import new_key
from phishhawk.server.db import transaction
from phishhawk.server.models import ApiToken, Session, User

PASSWORD = "correct horse battery"
SECRET = new_key()  # made at run time: no key-like literals for the secret scanner


def _user(db, name="alice", role="analyst"):
    with transaction(db) as s:
        return auth.create_user(s, name, PASSWORD, role).id


def test_passwords_are_argon2_and_checked(db):
    _user(db)
    with transaction(db) as s:
        assert s.scalars(select(User)).one().password_hash.startswith("$argon2id$")
        assert auth.check_login(s, "alice", PASSWORD).username == "alice"
        assert auth.check_login(s, "alice", "wrong password!") is None
        assert auth.check_login(s, "nobody", PASSWORD) is None


@pytest.mark.parametrize("name, password, role", [("A", PASSWORD, "analyst"), ("bob", "short", "analyst"),
                                                  ("bob", PASSWORD, "root")])
def test_bad_usernames_passwords_and_roles_are_refused(db, name, password, role):
    with transaction(db) as s, pytest.raises(auth.AuthError):
        auth.create_user(s, name, password, role)


def test_a_session_cookie_is_stored_only_as_its_hash_and_expires_when_idle(db):
    user_id = _user(db)
    with transaction(db) as s:
        cookie, session = auth.open_session(s, s.get(User, user_id), SECRET)
        assert session.id == auth.session_id(SECRET, cookie) and cookie not in session.id
    with transaction(db) as s:
        actor = auth.find_session(s, cookie, SECRET, idle_minutes=480)
        assert actor.username == "alice" and actor.via == "session" and actor.csrf
    with transaction(db) as s:
        s.scalars(select(Session)).one().last_seen_at -= dt.timedelta(hours=9)
    with transaction(db) as s:
        assert auth.find_session(s, cookie, SECRET, idle_minutes=480) is None
        assert s.scalars(select(Session)).first() is None  # an expired session is removed


def test_a_new_secret_key_ends_every_session(db):
    user_id = _user(db)
    with transaction(db) as s:
        cookie, _ = auth.open_session(s, s.get(User, user_id), SECRET)
    with transaction(db) as s:
        assert auth.find_session(s, cookie, new_key(), 480) is None


def test_a_disabled_user_loses_their_session(db):
    user_id = _user(db)
    with transaction(db) as s:
        cookie, _ = auth.open_session(s, s.get(User, user_id), SECRET)
        s.get(User, user_id).disabled = True
    with transaction(db) as s:
        assert auth.find_session(s, cookie, SECRET, 480) is None


def test_api_tokens_are_shown_once_stored_hashed_scoped_and_revocable(db):
    user_id = _user(db, "bot", "analyst")
    with transaction(db) as s:
        token = auth.create_token(s, s.get(User, user_id), "intelpulse", "read")
    assert token.startswith("phk_")
    with transaction(db) as s:
        row = s.scalars(select(ApiToken)).one()
        assert row.token_hash == auth.digest(token)
        actor = auth.find_token(s, token)
        assert (actor.via, actor.scope, actor.label) == ("token", "read", "token:intelpulse")
        row.revoked_at = row.created_at
    with transaction(db) as s:
        assert auth.find_token(s, token) is None


def test_the_throttle_doubles_the_wait_after_three_failures():
    now = [100.0]
    throttle = auth.LoginThrottle(clock=lambda: now[0])
    for _ in range(3):
        assert throttle.wait("user:alice") == 0
        throttle.failed("user:alice", "ip:10.0.0.1")
    assert throttle.wait("user:alice") == 1.0 and throttle.wait("ip:10.0.0.1") == 1.0
    now[0] += 1.0
    throttle.failed("user:alice")
    assert throttle.wait("user:alice") == 2.0
    throttle.succeeded("user:alice")
    assert throttle.wait("user:alice") == 0
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_auth.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'auth' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/auth.py`:

```python
"""Local users, sessions, API tokens and the login throttle. Passwords are
argon2id; session cookies and API tokens are random and only a hash of each
is stored (an HMAC under SECRET_KEY for sessions, SHA-256 for tokens), so a
copy of the database logs nobody in."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from .models import ApiToken, Session, User, utcnow

ROLES = ("admin", "analyst")
TOKEN_SCOPES = ("read", "submit")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MIN_PASSWORD = 12
_hasher = PasswordHasher()


class AuthError(ValueError):
    """A username, password, role or scope that is not acceptable."""


@dataclass(frozen=True)
class Actor:
    user_id: int
    username: str
    role: str
    via: str  # "session" or "token"
    scope: str  # "full" for a session, else the token's scope
    csrf: str = ""
    label: str = ""  # how the audit log names this actor

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" and self.via == "session"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_id(secret: str, cookie: str) -> str:
    """Sessions are keyed by an HMAC under SECRET_KEY, so a new key ends them all."""
    return hmac.new(secret.encode("utf-8"), cookie.encode("utf-8"), hashlib.sha256).hexdigest()


def create_user(db: DbSession, username: str, password: str, role: str) -> User:
    if not USERNAME_RE.match(username):
        raise AuthError("usernames are 3 to 64 lowercase letters, digits, dots, dashes or underscores")
    if len(password) < MIN_PASSWORD:
        raise AuthError("passwords need at least %d characters" % MIN_PASSWORD)
    if role not in ROLES:
        raise AuthError("role must be admin or analyst")
    if db.scalars(select(User).where(User.username == username)).first() is not None:
        raise AuthError("that username is taken")
    user = User(username=username, password_hash=_hasher.hash(password), role=role)
    db.add(user)
    db.flush()
    return user


def set_password(user: User, password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError("passwords need at least %d characters" % MIN_PASSWORD)
    user.password_hash = _hasher.hash(password)


def check_login(db: DbSession, username: str, password: str) -> User | None:
    user = db.scalars(select(User).where(User.username == username)).first()
    if user is None or user.disabled:
        _hasher.hash(password)  # the same work either way, so timing does not reveal usernames
        return None
    try:
        _hasher.verify(user.password_hash, password)
    except (VerificationError, InvalidHashError):
        return None
    return user


def open_session(db: DbSession, user: User, secret: str) -> tuple[str, Session]:
    cookie = secrets.token_urlsafe(32)
    session = Session(id=session_id(secret, cookie), user_id=user.id, csrf_token=secrets.token_urlsafe(32))
    db.add(session)
    user.last_login_at = utcnow()
    return cookie, session


def find_session(db: DbSession, cookie: str, secret: str, idle_minutes: int) -> Actor | None:
    session = db.get(Session, session_id(secret, cookie))
    if session is None:
        return None
    user = db.get(User, session.user_id)
    now = utcnow()
    if user is None or user.disabled or now - session.last_seen_at > dt.timedelta(minutes=idle_minutes):
        db.delete(session)
        return None
    session.last_seen_at = now
    return Actor(user.id, user.username, user.role, "session", "full", session.csrf_token, user.username)


def close_session(db: DbSession, cookie: str, secret: str) -> None:
    db.execute(delete(Session).where(Session.id == session_id(secret, cookie)))


def create_token(db: DbSession, user: User, name: str, scope: str) -> str:
    if scope not in TOKEN_SCOPES:
        raise AuthError("scope must be read or submit")
    if not 1 <= len(name) <= 64:
        raise AuthError("a token needs a name of 1 to 64 characters")
    token = "phk_" + secrets.token_urlsafe(32)
    db.add(ApiToken(user_id=user.id, name=name, token_hash=digest(token), scope=scope))
    db.flush()
    return token


def find_token(db: DbSession, token: str) -> Actor | None:
    row = db.scalars(select(ApiToken).where(ApiToken.token_hash == digest(token))).first()
    if row is None or row.revoked_at is not None:
        return None
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    row.last_used_at = utcnow()
    return Actor(user.id, user.username, user.role, "token", row.scope, "", "token:%s" % row.name)


class LoginThrottle:
    """After three failures for a username or an address, each new attempt
    waits twice as long as the last (1 s, 2 s, 4 s ... up to 5 minutes)."""

    def __init__(self, clock: object = time.monotonic) -> None:
        self._clock = clock
        self._failures: dict[str, tuple[int, float]] = {}

    def wait(self, *keys: str) -> float:
        now = self._clock()  # type: ignore[operator]
        return max([0.0] + [until - now for count, until in (self._failures.get(k, (0, 0.0)) for k in keys)])

    def failed(self, *keys: str) -> None:
        now = self._clock()  # type: ignore[operator]
        for key in keys:
            count = self._failures.get(key, (0, 0.0))[0] + 1
            delay = 0.0 if count < 3 else min(2.0 ** (count - 3), 300.0)
            self._failures[key] = (count, now + delay)

    def succeeded(self, *keys: str) -> None:
        for key in keys:
            self._failures.pop(key, None)
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_auth.py
```
Expected: 9 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/auth.py tests/server/test_auth.py
git commit -m "Add users, sessions, scoped API tokens and the login throttle"
```

### Task 7: Settings kept in the database, and the analysis options

*PR 3.*

What an admin changes on the Settings page: enabled providers and their API keys (sealed), protected, allowed and blocked domains, trusted authentication servers, and the limits that override the environment. This module also turns them into the facade's `AnalysisOptions`, and makes the campaign trait key once.

**Files:**

- Create: `src/phishhawk/server/appsettings.py`
- Test: `tests/server/test_appsettings.py` (new)

**Interfaces:**

- Consumes:
  - `phishhawk.analysis` (task 1): `PROVIDERS`; `class AnalysisOptions`
  - `phishhawk.server.config` (task 2): `class ServerSettings(BaseSettings)`
  - `phishhawk.server.crypto` (task 2): `class Box`
  - `phishhawk.server.models` (task 3): `class Setting(Base)`
- Produces:
  - `phishhawk.server.appsettings`: `LISTS`; `LIMITS`; `KEYED`; `PROVIDERS_ALL`; `get_value(db: Session, key: str, default: Any=None) -> Any`; `set_value(db: Session, key: str, value: Any) -> None`; `get_secret(db: Session, box: Box, name: str) -> str`; `set_secret(db: Session, box: Box, name: str, value: str) -> None`; `limit(db: Session, settings: ServerSettings, name: str) -> int`; `trait_key(db: Session, box: Box) -> bytes`; `analysis_options(db: Session, box: Box, settings: ServerSettings, offline: bool) -> AnalysisOptions`; `public_view(db: Session, box: Box, settings: ServerSettings) -> dict[str, Any]`

**Notes:**

- A fresh installation enables no provider: nothing leaves the machine until an admin turns one on.
- An analyst's "offline" tick empties the provider set for that message whatever is enabled.
- Each secret is sealed and bound to `setting:<name>`; the Settings page only ever sees the last four characters.
- The trait key is 32 random bytes made on first use and never replaced (spec 5.2).

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_appsettings.py`:

```python
"""Admin settings: providers, sealed keys, limits that override the
environment, and the trait key that never changes."""

from phishhawk.server import appsettings
from phishhawk.server.db import transaction
from phishhawk.server.models import Setting


def test_a_fresh_install_is_offline(db, box, settings):
    with transaction(db) as s:
        options = appsettings.analysis_options(s, box, settings, offline=False)
    assert options.providers == frozenset() and options.keys == {}


def test_enabled_providers_and_keys_reach_the_analysis_unless_offline(db, box, settings):
    with transaction(db) as s:
        appsettings.set_value(s, "providers", ["virustotal", "rdap", "not-a-provider"])
        appsettings.set_secret(s, box, "key:virustotal", "vt-key-1234")
    with transaction(db) as s:
        options = appsettings.analysis_options(s, box, settings, offline=False)
        assert options.providers == frozenset({"virustotal", "rdap"})
        assert options.keys == {"virustotal": "vt-key-1234"}
        assert appsettings.analysis_options(s, box, settings, offline=True).providers == frozenset()


def test_keys_are_sealed_and_shown_masked(db, box, settings):
    with transaction(db) as s:
        appsettings.set_secret(s, box, "key:abuseipdb", "abuse-secret-9876")
    with transaction(db) as s:
        assert "abuse-secret" not in str(s.get(Setting, "secret:key:abuseipdb").value)
        assert appsettings.public_view(s, box, settings)["keys"]["abuseipdb"] == "...9876"


def test_a_limit_set_by_an_admin_wins_over_the_environment(db, settings):
    with transaction(db) as s:
        assert appsettings.limit(s, settings, "retention_days") == 30
        appsettings.set_value(s, "retention_days", 7)
        assert appsettings.limit(s, settings, "retention_days") == 7


def test_the_trait_key_is_made_once_and_kept(db, box):
    with transaction(db) as s:
        first = appsettings.trait_key(s, box)
    with transaction(db) as s:
        assert appsettings.trait_key(s, box) == first and len(first) == 32
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_appsettings.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'appsettings' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/appsettings.py`:

```python
"""Settings an admin changes in the web app: providers and their keys,
domains, and the limits whose defaults come from the environment. Keys and
the trait key are sealed with the encryption key."""

from __future__ import annotations

import base64
import os
from typing import Any

from sqlalchemy.orm import Session

from ..analysis import PROVIDERS, AnalysisOptions
from .config import ServerSettings
from .crypto import Box
from .models import Setting

LISTS = ("providers", "protected_domains", "allow_domains", "block_domains", "trusted_authserv")
LIMITS = ("retention_days", "max_upload_mb", "max_batch_messages", "campaign_window_days")
KEYED = ("virustotal", "urlscan", "abuseipdb")  # RDAP needs no key
PROVIDERS_ALL = PROVIDERS


def get_value(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(Setting, key)
    return default if row is None else row.value


def set_value(db: Session, key: str, value: Any) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def get_secret(db: Session, box: Box, name: str) -> str:
    sealed = get_value(db, "secret:" + name)
    return box.open(base64.b64decode(sealed), "setting:" + name).decode("utf-8") if sealed else ""


def set_secret(db: Session, box: Box, name: str, value: str) -> None:
    sealed = box.seal(value.encode("utf-8"), "setting:" + name) if value else None
    set_value(db, "secret:" + name, base64.b64encode(sealed).decode("ascii") if sealed else None)


def limit(db: Session, settings: ServerSettings, name: str) -> int:
    value = get_value(db, name)
    return int(value) if value is not None else int(getattr(settings, name))


def trait_key(db: Session, box: Box) -> bytes:
    """Made once and never changed (see the spec, section 5.2)."""
    existing = get_secret(db, box, "trait_key")
    if existing:
        return base64.b64decode(existing)
    key = os.urandom(32)
    set_secret(db, box, "trait_key", base64.b64encode(key).decode("ascii"))
    return key


def analysis_options(db: Session, box: Box, settings: ServerSettings, offline: bool) -> AnalysisOptions:
    enabled = frozenset(p for p in get_value(db, "providers", []) if p in PROVIDERS)
    return AnalysisOptions(
        providers=frozenset() if offline else enabled,
        keys={name: get_secret(db, box, "key:" + name) for name in KEYED if name in enabled},
        protected=list(get_value(db, "protected_domains", [])),
        allow_domains=list(get_value(db, "allow_domains", [])),
        block_domains=list(get_value(db, "block_domains", [])),
        trusted_authserv=list(get_value(db, "trusted_authserv", [])),
        cache_path=str(settings.data_dir / "lookups.sqlite3"),
    )


def public_view(db: Session, box: Box, settings: ServerSettings) -> dict[str, Any]:
    """Everything the Settings page shows; keys only as their last four characters."""
    view: dict[str, Any] = {name: list(get_value(db, name, [])) for name in LISTS}
    view.update({name: limit(db, settings, name) for name in LIMITS})
    view["keys"] = {}
    for name in KEYED:
        key = get_secret(db, box, "key:" + name)
        view["keys"][name] = ("..." + key[-4:]) if key else ""
    return view
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_appsettings.py
```
Expected: 5 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/appsettings.py tests/server/test_appsettings.py
git commit -m "Add stored settings, sealed provider keys and the analysis options"
```

### Task 8: Job queue and resource limits

*PR 3.*

A job table the worker claims from, with heartbeats and requeueing when a worker stops; and a child process with memory and CPU limits in which one message is analysed, so a hostile message cannot take the server down.

**Files:**

- Create: `src/phishhawk/server/jobs.py`
- Create: `src/phishhawk/server/limits.py`
- Test: `tests/server/test_jobs.py` (new)
- Test: `tests/server/test_limits.py` (new)

**Interfaces:**

- Consumes:
  - `phishhawk.server.models` (task 3): `class Job(Base)`; `utcnow() -> dt.datetime`
- Produces:
  - `phishhawk.server.jobs`: `KINDS`; `MAX_ATTEMPTS`; `enqueue(db: Session, kind: str, payload: dict[str, Any] | None=None) -> Job`; `claim(db: Session) -> Job | None`; `heartbeat(db: Session, job_id: int) -> None`; `finish(db: Session, job_id: int, error: str='') -> None`; `requeue_stale(db: Session, stale_after: dt.timedelta) -> int`; `pending(db: Session, kind: str) -> bool`; `last_finished(db: Session, kind: str) -> dt.datetime | None`
  - `phishhawk.server.limits`: `MB`; `class LimitExceeded(Exception)`; `class ChildFailed(Exception)`; `run_limited(fn: Callable[..., Any], args: tuple[Any, ...], memory_mb: int, cpu_seconds: int, on_wait: Callable[[], None] | None=None) -> Any`

**Notes:**

- `claim()` uses `FOR UPDATE SKIP LOCKED` (ignored by SQLite, which serialises writers anyway), so the same code is ready for Postgres.
- A running job whose heartbeat is older than the limit goes back to the queue; after three attempts it fails with a reason.
- `run_limited()` uses the `spawn` start method, sets `RLIMIT_AS` and `RLIMIT_CPU` in the child, and returns the result through a pipe. Wall-clock limit: CPU seconds x 2 + 10.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_jobs.py`:

```python
"""The job table: claim order, one claim per job, stale requeue."""

import datetime as dt

from phishhawk.server import jobs
from phishhawk.server.db import transaction
from phishhawk.server.models import Job


def test_jobs_are_claimed_oldest_first_and_only_once(db):
    with transaction(db) as s:
        first = jobs.enqueue(s, "analyze", {"submission_id": 1}).id
        jobs.enqueue(s, "analyze", {"submission_id": 2})
    with transaction(db) as s:
        job = jobs.claim(s)
        assert (job.id, job.status, job.attempts) == (first, "running", 1)
    with transaction(db) as s:
        assert jobs.claim(s).payload == {"submission_id": 2}
    with transaction(db) as s:
        assert jobs.claim(s) is None


def test_a_job_whose_worker_stopped_is_requeued_then_failed(db):
    with transaction(db) as s:
        job_id = jobs.enqueue(s, "retention_sweep").id
    for attempt in range(1, 4):
        with transaction(db) as s:
            assert jobs.claim(s).id == job_id
            s.get(Job, job_id).heartbeat_at -= dt.timedelta(minutes=5)
        with transaction(db) as s:
            assert jobs.requeue_stale(s, dt.timedelta(minutes=2)) == 1
            assert s.get(Job, job_id).status == ("failed" if attempt == 3 else "queued")


def test_finish_records_success_or_the_error(db):
    with transaction(db) as s:
        ok, bad = jobs.enqueue(s, "analyze").id, jobs.enqueue(s, "analyze").id
        jobs.finish(s, ok)
        jobs.finish(s, bad, "boom")
    with transaction(db) as s:
        assert s.get(Job, ok).status == "done" and s.get(Job, bad).status == "failed"
        assert s.get(Job, bad).error == "boom"
```

Create `tests/server/test_limits.py`:

```python
"""The analysis child process: results come back, and limits hold."""

import time

import pytest

from phishhawk.server.limits import ChildFailed, LimitExceeded, run_limited


def _double(value):
    return value * 2


def _hog_memory():
    return len(bytearray(1024 * 1024 * 1024))


def _spin():
    while True:
        pass


def _raise():
    raise ValueError("a broken message")


def test_a_result_comes_back_from_the_child():
    assert run_limited(_double, (21,), memory_mb=512, cpu_seconds=10) == 42


def test_the_memory_limit_stops_the_child():
    with pytest.raises(LimitExceeded):
        run_limited(_hog_memory, (), memory_mb=256, cpu_seconds=10)


def test_the_cpu_limit_stops_the_child():
    started = time.monotonic()
    with pytest.raises(LimitExceeded):
        run_limited(_spin, (), memory_mb=512, cpu_seconds=1)
    assert time.monotonic() - started < 15


def test_an_exception_in_the_child_is_reported_not_raised_raw():
    with pytest.raises(ChildFailed, match="ValueError: a broken message"):
        run_limited(_raise, (), memory_mb=512, cpu_seconds=10)
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_jobs.py tests/server/test_limits.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'jobs' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/jobs.py`:

```python
"""The job queue: a table. A worker claims the oldest queued job in one
transaction (SQLite: one writer at a time; Postgres: SKIP LOCKED)."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Job, utcnow

KINDS = ("analyze", "retention_sweep")  # M2 adds batch_finalize and campaign_rebuild, M3 mailbox_poll
MAX_ATTEMPTS = 3


def enqueue(db: Session, kind: str, payload: dict[str, Any] | None = None) -> Job:
    if kind not in KINDS:
        raise ValueError("unknown job kind %r" % kind)
    job = Job(kind=kind, payload=payload or {})
    db.add(job)
    db.flush()
    return job


def claim(db: Session) -> Job | None:
    job = db.scalars(select(Job).where(Job.status == "queued").order_by(Job.id).limit(1)
                     .with_for_update(skip_locked=True)).first()
    if job is not None:
        job.status, job.attempts = "running", job.attempts + 1
        job.started_at = job.heartbeat_at = utcnow()
    return job


def heartbeat(db: Session, job_id: int) -> None:
    job = db.get(Job, job_id)
    if job is not None:
        job.heartbeat_at = utcnow()


def finish(db: Session, job_id: int, error: str = "") -> None:
    job = db.get(Job, job_id)
    if job is not None:
        job.status = "failed" if error else "done"
        job.error, job.finished_at = error[:500], utcnow()


def requeue_stale(db: Session, stale_after: dt.timedelta) -> int:
    """Running jobs whose worker stopped sending heartbeats: back to the
    queue, or failed after MAX_ATTEMPTS."""
    cutoff, moved = utcnow() - stale_after, 0
    for job in db.scalars(select(Job).where(Job.status == "running", Job.heartbeat_at < cutoff)):
        if job.attempts >= MAX_ATTEMPTS:
            job.status, job.finished_at = "failed", utcnow()
            job.error = "the worker stopped %d times" % job.attempts
        else:
            job.status = "queued"
        moved += 1
    return moved


def pending(db: Session, kind: str) -> bool:
    return db.scalars(select(Job.id).where(Job.kind == kind, Job.status.in_(("queued", "running")))
                      .limit(1)).first() is not None


def last_finished(db: Session, kind: str) -> dt.datetime | None:
    return db.scalars(select(Job.finished_at).where(Job.kind == kind, Job.finished_at.is_not(None))
                      .order_by(Job.finished_at.desc()).limit(1)).first()
```

Create `src/phishhawk/server/limits.py`:

```python
"""Run one function in a child process with memory and CPU limits, so a
hostile message cannot take the worker (or the web app) down with it.
Linux and macOS only: it uses the resource module."""

from __future__ import annotations

import multiprocessing
from collections.abc import Callable
from typing import Any

MB = 1024 * 1024


class LimitExceeded(Exception):
    """The child hit its memory or CPU limit, or ran past the wall-clock limit."""


class ChildFailed(Exception):
    """The function raised in the child; the message is safe to show."""


def _child(conn: Any, fn: Callable[..., Any], args: tuple[Any, ...], memory_mb: int, cpu_seconds: int) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (memory_mb * MB, memory_mb * MB))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    try:
        conn.send(("ok", fn(*args)))
    except MemoryError:
        conn.send(("limit", "memory"))
    except BaseException as exc:  # anything the engine raises becomes a failed analysis
        conn.send(("error", "%s: %s" % (type(exc).__name__, str(exc)[:300])))
    finally:
        conn.close()


def run_limited(fn: Callable[..., Any], args: tuple[Any, ...], memory_mb: int, cpu_seconds: int,
                on_wait: Callable[[], None] | None = None) -> Any:
    """fn(*args) in a fresh process; on_wait is called every few seconds while
    waiting (the worker uses it to send its heartbeat)."""
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_child, args=(sender, fn, args, memory_mb, cpu_seconds), daemon=True)
    process.start()
    sender.close()
    waited, wall = 0.0, cpu_seconds * 2 + 10
    try:
        while not receiver.poll(5):
            waited += 5
            if on_wait is not None:
                on_wait()
            if waited >= wall or not process.is_alive() and not receiver.poll(0):
                raise LimitExceeded("time" if waited >= wall else "the analysis process stopped")
        try:
            status, value = receiver.recv()
        except EOFError as exc:  # killed by the CPU limit before it could answer
            raise LimitExceeded("cpu") from exc
    finally:
        if process.is_alive():
            process.kill()
        process.join(5)
        receiver.close()
    if status == "limit":
        raise LimitExceeded(value)
    if status == "error":
        raise ChildFailed(value)
    return value
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_jobs.py tests/server/test_limits.py
```
Expected: 7 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/jobs.py src/phishhawk/server/limits.py tests/server/test_jobs.py tests/server/test_limits.py
git commit -m "Add the job queue and the resource-limited analysis process"
```

### Task 9: Intake, the worker and retention

*PR 4.*

The path of one message: intake checks it, stores it sealed and queues a job; the worker analyses it in the limited child, stores tier 1 sealed and tier 2 in the database, and audits it; an hourly sweep deletes tier 1 after the retention period unless the message is on hold.

**Files:**

- Create: `src/phishhawk/server/intake.py`
- Create: `src/phishhawk/server/retention.py`
- Create: `src/phishhawk/server/processing.py`
- Create: `src/phishhawk/server/worker.py`
- Test: `tests/server/test_processing.py` (new)
- Test: `tests/server/test_worker.py` (new)
- Test: `tests/server/conftest.py` (changed)

**Interfaces:**

- Consumes:
  - `phishhawk.analysis` (task 1): `analyze(raw: bytes, name: str='<upload>', options: AnalysisOptions | None=None) -> AnalysisResult`; `class AnalysisOptions`
  - `phishhawk.server.appsettings` (task 7): `analysis_options(db: Session, box: Box, settings: ServerSettings, offline: bool) -> AnalysisOptions`; `limit(db: Session, settings: ServerSettings, name: str) -> int`; `trait_key(db: Session, box: Box) -> bytes`
  - `phishhawk.server.audit` (task 5): `record(db: Session, actor: str, action: str, object_type: str='', object_id: object='', details: dict[str, Any] | None=None) -> AuditRecord`
  - `phishhawk.server.config` (task 2): `class ServerSettings(BaseSettings)`
  - `phishhawk.server.crypto` (task 2): `class Box`
  - `phishhawk.server.db` (task 3): `transaction(factory: sessionmaker[Session]) -> Iterator[Session]`
  - `phishhawk.server.jobs` (task 8): `claim(db: Session) -> Job | None`; `enqueue(db: Session, kind: str, payload: dict[str, Any] | None=None) -> Job`; `finish(db: Session, job_id: int, error: str='') -> None`; `heartbeat(db: Session, job_id: int) -> None`; `last_finished(db: Session, kind: str) -> dt.datetime | None`; `pending(db: Session, kind: str) -> bool`; `requeue_stale(db: Session, stale_after: dt.timedelta) -> int`
  - `phishhawk.server.limits` (task 8): `class ChildFailed(Exception)`; `class LimitExceeded(Exception)`; `run_limited(fn: Callable[..., Any], args: tuple[Any, ...], memory_mb: int, cpu_seconds: int, on_wait: Callable[[], None] | None=None) -> Any`
  - `phishhawk.server.models` (task 3): `class Analysis(Base)`; `class Indicator(Base)`; `class Message(Base)`; `class Submission(Base)`; `utcnow() -> dt.datetime`
  - `phishhawk.server.store` (task 4): `class BlobStore`
- Produces:
  - `phishhawk.server.intake`: `OLE_MAGIC`; `HEADER_RE`; `class IntakeError(ValueError)`: `__init__(status: int, message: str) -> None`; `kind_of(raw: bytes) -> str`; `accept(db: Session, store: BlobStore, raw: bytes, *, source: str, user_id: int | None, actor: str, offline: bool, max_bytes: int) -> Submission`
  - `phishhawk.server.retention`: `delete_tier1(db: Session, store: BlobStore, message: Message, reason: str) -> None`; `delete_completely(db: Session, store: BlobStore, message: Message) -> str`; `sweep(db: Session, store: BlobStore, days: int, now: dt.datetime | None=None) -> int`
  - `phishhawk.server.processing`: `PROTECTED_TRAITS`; `class Services`: `settings: ServerSettings`; `sessions: sessionmaker[Session]`; `box: Box`; `store: BlobStore`; `child_analyze(raw: bytes, name: str, options: AnalysisOptions) -> dict[str, Any]`; `protect_traits(traits: dict[str, Any], key: bytes) -> dict[str, Any]`; `process_submission(services: Services, submission_id: int, heartbeat: Any=None) -> None`
  - `phishhawk.server.worker`: `STALE_AFTER`; `SWEEP_EVERY`; `schedule(services: Services) -> None`; `run_one(services: Services) -> bool`; `run_forever(services: Services, should_stop: Callable[[], bool]=lambda: False, idle: float=1.0) -> None`

**Notes:**

- Intake accepts .eml (RFC 5322 headers) and Outlook .msg (OLE2) only in M1; empty input is 400, other formats 415, too large 413. The same SHA-256 twice is one message with two submissions.
- Plain message bytes exist only in worker memory: intake seals them before writing, and the child gets them through the pipe.
- The subject and the sender's display name enter the trait record only as HMAC-SHA256 under the trait key (`protect_traits`).
- A failed analysis records a short, sanitised reason; the raw message stays for "Re-analyze".
- `worker.schedule()` requeues stale jobs and queues one `retention_sweep` an hour; `run_one()` never lets a failing handler stop the worker.

- [ ] **Step 1: Write the failing tests**

Change `tests/server/conftest.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/conftest.py
+++ b/tests/server/conftest.py
@@ -28,3 +28,10 @@
 @pytest.fixture
 def store(settings, box):
     return BlobStore(settings.data_dir / "blobs", box)
+
+
+@pytest.fixture
+def services(settings, db, box, store):
+    from phishhawk.server.processing import Services
+
+    return Services(settings, db, box, store)
```

Create `tests/server/test_processing.py`:

```python
"""A submission from upload to stored analysis, through the worker."""

import io
import json
import time
import zipfile

import pytest
from sqlalchemy import select

from phishhawk.server import audit, intake, retention, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import Analysis, Indicator, Job, Message, Submission

from conftest import build_eml, sample


def _raw(name="sample_bec_smuggling.eml"):
    with open(sample(name), "rb") as handle:
        return handle.read()


def _submit(services, raw=None, offline=True):
    with transaction(services.sessions) as s:
        return intake.accept(s, services.store, raw or _raw(), source="upload", user_id=None, actor="alice",
                             offline=offline, max_bytes=25 * 1024 * 1024).id


def test_intake_refuses_what_is_not_a_message(services):
    with transaction(services.sessions) as s:
        for raw, status in ((b"", 400), (b"%PDF-1.7\n", 415), (b"x" * 30, 415)):
            with pytest.raises(intake.IntakeError) as caught:
                intake.accept(s, services.store, raw, source="paste", user_id=None, actor="a", offline=True,
                              max_bytes=1000)
            assert caught.value.status == status
        with pytest.raises(intake.IntakeError) as caught:
            intake.accept(s, services.store, _raw(), source="upload", user_id=None, actor="a", offline=True,
                          max_bytes=100)
        assert caught.value.status == 413


def test_the_same_message_twice_is_one_message_with_two_submissions(services):
    _submit(services)
    _submit(services)
    with transaction(services.sessions) as s:
        assert len(s.scalars(select(Message)).all()) == 1
        assert len(s.scalars(select(Submission)).all()) == 2
        assert len(s.scalars(select(Job)).all()) == 2


def test_the_worker_analyses_a_submission_and_stores_both_tiers(services):
    submission_id = _submit(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        submission = s.get(Submission, submission_id)
        assert submission.status == "done", submission.error
        analysis = s.scalars(select(Analysis)).one()
        assert analysis.verdict == "LIKELY PHISHING" and analysis.report_id.startswith("PH-")
        assert [f["kind"] for f in analysis.files] == ["json", "stix", "misp", "md", "csv", "html", "manifest"]
        assert analysis.providers == [] and analysis.lookups == []
        report = json.loads(services.store.get(analysis.data_blob))
        assert report["verdict"] == "LIKELY PHISHING"
        html = services.store.get(next(f["blob"] for f in analysis.files if f["kind"] == "html"))
        assert b"<!doctype html>" in html
        assert s.scalars(select(Indicator).where(Indicator.value == "examp1e-corp.co.uk")).first() is not None
        message = s.get(Message, submission.message_id)
        assert message.sender == "it-servicedesk@examp1e-corp.co.uk" and message.recipient_count == 1
        # subject and display name are kept only as HMAC values
        traits = analysis.traits["traits"]
        assert all(len(v) == 64 for v in traits["subject"] + traits["display name"])
        assert "password expires" not in json.dumps(traits) and "IT Service Desk" not in json.dumps(traits)
        assert [r.action for r in s.scalars(select(audit.AuditRecord))] == ["submit", "analyze"]


def test_a_message_that_breaks_the_limits_fails_safely(services, monkeypatch):
    services.settings.analysis_memory_mb = 64  # far too little for the engine
    submission_id = _submit(services)
    worker.run_one(services)
    with transaction(services.sessions) as s:
        submission = s.get(Submission, submission_id)
        assert submission.status == "failed" and "limits" in submission.error
        assert s.scalars(select(Analysis)).first() is None


def test_retention_deletes_tier1_keeps_tier2_and_skips_held_messages(services):
    held_id, kept_id = _submit(services), _submit(services, _raw("sample_phish.eml"))
    worker.run_one(services)
    worker.run_one(services)
    with transaction(services.sessions) as s:
        for message in s.scalars(select(Message)):
            message.first_seen_at = message.first_seen_at.replace(year=2000)
        s.get(Message, s.get(Submission, held_id).message_id).hold = True
        raw_blob = s.get(Message, s.get(Submission, kept_id).message_id).raw_blob
    with transaction(services.sessions) as s:
        assert retention.sweep(s, services.store, days=30) == 1
    with transaction(services.sessions) as s:
        gone = s.get(Message, s.get(Submission, kept_id).message_id)
        assert gone.raw_blob is None and gone.deletion_reason == "retention"
        analysis = s.scalars(select(Analysis).where(Analysis.message_id == gone.id)).one()
        assert analysis.data_blob is None and all(f["blob"] is None for f in analysis.files)
        assert analysis.verdict == "LIKELY PHISHING" and analysis.traits  # tier 2 stays
        assert not services.store._path(raw_blob).exists()
        held = s.get(Message, s.get(Submission, held_id).message_id)
        assert held.raw_blob is not None and services.store._path(held.raw_blob).exists()


def test_delete_completely_removes_tier2_but_audit_keeps_the_hash(services):
    submission_id = _submit(services)
    worker.run_one(services)
    with transaction(services.sessions) as s:
        message = s.get(Message, s.get(Submission, submission_id).message_id)
        sha256 = retention.delete_completely(s, services.store, message)
        audit.record(s, "admin", "delete_completely", "message", message.id, {"sha256": sha256})
    with transaction(services.sessions) as s:
        assert s.scalars(select(Message)).first() is None
        assert s.scalars(select(Analysis)).first() is None and s.scalars(select(Indicator)).first() is None
        assert audit.verify(s) == []


def test_a_decompression_bomb_stays_inside_the_limits_and_the_worker_carries_on(services):
    """The engine's read budgets stop the unpacking long before the child's
    512 MB memory limit; the message is analysed and the next one is too."""
    services.settings.analysis_memory_mb = 512
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("invoice.pdf", b"\0" * (300 * 1024 * 1024))  # 300 MB of zeros, under 1 MB packed
    bomb = build_eml(subject="Invoice", attachments=[(packed.getvalue(), "application", "zip", "invoice.zip")])
    bomb_id, normal_id = _submit(services, bomb), _submit(services, _raw("sample_phish.eml"))
    started = time.monotonic()
    assert worker.run_one(services) and worker.run_one(services)
    assert time.monotonic() - started < 60
    with transaction(services.sessions) as s:
        bomb_status = s.get(Submission, bomb_id)
        assert bomb_status.status == "done", bomb_status.error
        assert s.get(Submission, normal_id).status == "done"
```

Create `tests/server/test_worker.py`:

```python
"""The worker's own schedule: the hourly retention sweep, requeueing jobs
whose worker stopped, and carrying on after a handler fails."""

import datetime as dt

from sqlalchemy import select

from phishhawk.server import intake, jobs, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import Analysis, AuditRecord, Job, Message

from conftest import sample


def _submit(services):
    with open(sample("sample_phish.eml"), "rb") as handle:
        raw = handle.read()
    with transaction(services.sessions) as s:
        return intake.accept(s, services.store, raw, source="upload", user_id=None, actor="alice", offline=True,
                             max_bytes=25 * 1024 * 1024).id


def _sweeps(services):
    with transaction(services.sessions) as s:
        return s.scalars(select(Job).where(Job.kind == "retention_sweep").order_by(Job.id)).all()


def test_the_retention_sweep_is_scheduled_once_then_hourly(services):
    worker.schedule(services)
    worker.schedule(services)
    assert len(_sweeps(services)) == 1  # not twice while one is queued
    assert worker.run_one(services)
    worker.schedule(services)
    assert len(_sweeps(services)) == 1  # finished less than an hour ago
    with transaction(services.sessions) as s:
        s.scalars(select(Job)).one().finished_at -= dt.timedelta(minutes=61)
    worker.schedule(services)
    assert len(_sweeps(services)) == 2


def test_the_sweep_deletes_tier1_after_the_retention_period_and_audits_the_count(services):
    _submit(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        s.scalars(select(Message)).one().first_seen_at -= dt.timedelta(days=31)
    worker.schedule(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        assert s.scalars(select(Message)).one().raw_blob is None
        assert s.scalars(select(Analysis)).one().verdict == "LIKELY PHISHING"  # tier 2 stays
        entry = s.scalars(select(AuditRecord).where(AuditRecord.action == "retention_sweep")).one()
        assert (entry.actor, entry.details) == ("system", {"deleted": 1, "days": 30})


def test_a_job_whose_worker_stopped_is_queued_again_by_the_schedule(services):
    _submit(services)
    with transaction(services.sessions) as s:
        job = jobs.claim(s)
        job.heartbeat_at -= dt.timedelta(minutes=5)
    worker.schedule(services)
    with transaction(services.sessions) as s:
        assert s.scalars(select(Job).where(Job.kind == "analyze")).one().status == "queued"


def test_a_failing_handler_fails_its_job_and_the_worker_carries_on(services, monkeypatch):
    def broken(*args):
        raise RuntimeError("boom")

    monkeypatch.setattr(worker, "process_submission", broken)
    _submit(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        job = s.scalars(select(Job)).one()
        assert (job.status, job.error) == ("failed", "RuntimeError: boom")
    assert not worker.run_one(services)
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_processing.py tests/server/test_worker.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'intake' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/intake.py`:

```python
"""Accepting a message: size and type checks, deduplication by SHA-256,
sealing the raw bytes, and queueing the analysis."""

from __future__ import annotations

import hashlib
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, jobs
from .models import Message, Submission
from .store import BlobStore

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # Outlook .msg
HEADER_RE = re.compile(rb"^[A-Za-z0-9-]{1,76}:[ \t]", re.M)


class IntakeError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def kind_of(raw: bytes) -> str:
    """'msg', 'eml', or '' for anything else (M2 adds .mbox and .zip)."""
    if raw.startswith(OLE_MAGIC):
        return "msg"
    head = raw[:4096].lstrip(b"\r\n")
    if HEADER_RE.match(head) and len(HEADER_RE.findall(head)) >= 2:
        return "eml"
    return ""


def accept(db: Session, store: BlobStore, raw: bytes, *, source: str, user_id: int | None, actor: str,
           offline: bool, max_bytes: int) -> Submission:
    if not raw:
        raise IntakeError(400, "the message is empty")
    if len(raw) > max_bytes:
        raise IntakeError(413, "the message is larger than %d MB" % (max_bytes // (1024 * 1024)))
    if not kind_of(raw):
        raise IntakeError(415, "this is not an .eml or .msg message")
    sha256 = hashlib.sha256(raw).hexdigest()
    message = db.scalars(select(Message).where(Message.sha256 == sha256)).first()
    if message is None:
        message = Message(sha256=sha256, size=len(raw), raw_blob=store.put(raw))
        db.add(message)
        db.flush()
    elif message.raw_blob is None:  # submitted again after its tier 1 was deleted
        message.raw_blob, message.tier1_deleted_at, message.deletion_reason = store.put(raw), None, ""
    submission = Submission(message_id=message.id, user_id=user_id, source=source, offline=offline)
    db.add(submission)
    db.flush()
    jobs.enqueue(db, "analyze", {"submission_id": submission.id})
    audit.record(db, actor, "submit", "submission", submission.id,
                 {"sha256": sha256, "source": source, "offline": offline})
    return submission
```

Create `src/phishhawk/server/retention.py`:

```python
"""Tier-1 deletion: by the hourly sweep after the retention period, by hand
("Delete now"), or with tier 2 as well ("Delete completely", admins only).
A message on hold is skipped by the sweep."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Analysis, Message, utcnow
from .store import BlobStore


def delete_tier1(db: Session, store: BlobStore, message: Message, reason: str) -> None:
    if message.tier1_deleted_at is not None:
        return
    store.delete(message.raw_blob)
    for analysis in db.scalars(select(Analysis).where(Analysis.message_id == message.id)):
        store.delete(analysis.data_blob)
        for entry in analysis.files:
            store.delete(entry.get("blob"))
        analysis.data_blob = None
        analysis.files = [dict(entry, blob=None) for entry in analysis.files]
    message.raw_blob = None
    message.tier1_deleted_at, message.deletion_reason = utcnow(), reason


def delete_completely(db: Session, store: BlobStore, message: Message) -> str:
    delete_tier1(db, store, message, "manual")
    sha256 = message.sha256
    db.delete(message)  # submissions, analyses and indicators go with it (ON DELETE CASCADE)
    return sha256


def sweep(db: Session, store: BlobStore, days: int, now: dt.datetime | None = None) -> int:
    cutoff = (now or utcnow()) - dt.timedelta(days=days)
    due = db.scalars(select(Message).where(Message.tier1_deleted_at.is_(None), Message.hold.is_(False),
                                           Message.first_seen_at < cutoff)).all()
    for message in due:
        delete_tier1(db, store, message, "retention")
    return len(due)
```

Create `src/phishhawk/server/processing.py`:

```python
"""What the worker does with one submission: decrypt the message in memory,
analyse it in a limited child process, then store tier 1 sealed and tier 2
in the database."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..analysis import AnalysisOptions, analyze
from . import appsettings, audit
from .config import ServerSettings
from .crypto import Box
from .db import transaction
from .limits import ChildFailed, LimitExceeded, run_limited
from .models import Analysis, Indicator, Message, Submission
from .store import BlobStore

PROTECTED_TRAITS = ("subject", "display name")  # kept only as HMAC values (spec 5.1)


@dataclass
class Services:
    """Everything a handler needs; the web app and the worker build the same one."""
    settings: ServerSettings
    sessions: sessionmaker[Session]
    box: Box
    store: BlobStore


def child_analyze(raw: bytes, name: str, options: AnalysisOptions) -> dict[str, Any]:
    """Runs in the child process; returns only plain data."""
    result = analyze(raw, name, options)
    return {"data": result.data, "files": [(f.name, f.kind, f.content, f.entry()) for f in result.files],
            "summary": result.summary, "traits": result.traits, "lookups": result.lookups,
            "providers": sorted(options.providers)}


def protect_traits(traits: dict[str, Any], key: bytes) -> dict[str, Any]:
    kept = {"traits": dict(traits["traits"]), "under": traits["under"], "flagged": traits["flagged"]}
    for kind in PROTECTED_TRAITS:
        if kind in kept["traits"]:
            kept["traits"][kind] = sorted(hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
                                          for value in kept["traits"][kind])
    return kept


def process_submission(services: Services, submission_id: int, heartbeat: Any = None) -> None:
    s = services
    with transaction(s.sessions) as db:
        submission = db.get(Submission, submission_id)
        if submission is None or submission.status not in ("queued", "running"):
            return
        message = db.get(Message, submission.message_id)
        if message is None or message.raw_blob is None:
            submission.status, submission.error = "failed", "the message was deleted before it was analysed"
            return
        raw = s.store.get(message.raw_blob)
        options = appsettings.analysis_options(db, s.box, s.settings, submission.offline)
        submission.status = "running"
    try:
        result = run_limited(child_analyze, (raw, "submission %d" % submission_id, options),
                             s.settings.analysis_memory_mb, s.settings.analysis_cpu_seconds, heartbeat)
    except (LimitExceeded, ChildFailed) as exc:
        reason = ("this message exceeded the analysis limits (%s)" % exc if isinstance(exc, LimitExceeded)
                  else "the message could not be analysed: %s" % exc)
        with transaction(s.sessions) as db:
            submission = db.get(Submission, submission_id)
            if submission is not None:
                submission.status, submission.error = "failed", reason
            audit.record(db, "system", "analyze_failed", "submission", submission_id, {"reason": reason})
        return
    data_blob = s.store.put(json.dumps(result["data"], ensure_ascii=False).encode("utf-8"))
    files = [dict(entry, blob=s.store.put(content)) for _, _, content, entry in result["files"]]
    summary = result["summary"]
    with transaction(s.sessions) as db:
        submission = db.get(Submission, submission_id)
        message = db.get(Message, submission.message_id) if submission is not None else None
        if submission is None or message is None:  # deleted while it was being analysed
            for blob in [data_blob] + [f["blob"] for f in files]:
                s.store.delete(blob)
            return
        analysis = Analysis(message_id=message.id, submission_id=submission.id,
                            engine_version=summary["engine_version"], report_id=summary["report_id"],
                            verdict=summary["verdict"], score=summary["score"], providers=result["providers"],
                            lookups=result["lookups"], techniques=summary["techniques"],
                            traits=protect_traits(result["traits"], appsettings.trait_key(db, s.box)),
                            files=files, data_blob=data_blob)
        db.add(analysis)
        db.flush()
        db.add_all(Indicator(analysis_id=analysis.id, type=i["type"], value=i["value"])
                   for i in summary["indicators"])
        message.sender, message.sender_domain = summary["sender"], summary["sender_domain"]
        message.recipient_count = summary["recipient_count"]
        submission.status, submission.error = "done", ""
        audit.record(db, "system", "analyze", "analysis", analysis.id,
                     {"submission": submission.id, "verdict": analysis.verdict,
                      "providers": result["providers"], "lookups": len(result["lookups"])})
```

Create `src/phishhawk/server/worker.py`:

```python
"""The worker process: requeues jobs whose worker died, schedules the hourly
retention sweep, and runs one job at a time."""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Callable

from . import appsettings, audit, jobs
from .db import transaction
from .models import utcnow
from .processing import Services, process_submission
from .retention import sweep

STALE_AFTER = dt.timedelta(minutes=2)
SWEEP_EVERY = dt.timedelta(hours=1)


def schedule(services: Services) -> None:
    with transaction(services.sessions) as db:
        jobs.requeue_stale(db, STALE_AFTER)
        last = jobs.last_finished(db, "retention_sweep")
        if not jobs.pending(db, "retention_sweep") and (last is None or utcnow() - last >= SWEEP_EVERY):
            jobs.enqueue(db, "retention_sweep")


def run_one(services: Services) -> bool:
    """Claim and run one job; False when the queue was empty."""
    with transaction(services.sessions) as db:
        job = jobs.claim(db)
        if job is None:
            return False
        job_id, kind, payload = job.id, job.kind, dict(job.payload)

    def beat() -> None:
        with transaction(services.sessions) as db:
            jobs.heartbeat(db, job_id)

    error = ""
    try:
        if kind == "analyze":
            process_submission(services, int(payload["submission_id"]), beat)
        elif kind == "retention_sweep":
            with transaction(services.sessions) as db:
                days = appsettings.limit(db, services.settings, "retention_days")
                count = sweep(db, services.store, days)
                audit.record(db, "system", "retention_sweep", details={"deleted": count, "days": days})
    except Exception as exc:  # a bug in a handler must not stop the worker
        error = "%s: %s" % (type(exc).__name__, exc)
    with transaction(services.sessions) as db:
        jobs.finish(db, job_id, error)
    return True


def run_forever(services: Services, should_stop: Callable[[], bool] = lambda: False, idle: float = 1.0) -> None:
    next_schedule = 0.0
    while not should_stop():
        if time.monotonic() >= next_schedule:
            schedule(services)
            next_schedule = time.monotonic() + 30
        if not run_one(services):
            time.sleep(idle)
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_processing.py tests/server/test_worker.py
```
Expected: 11 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/intake.py src/phishhawk/server/processing.py src/phishhawk/server/retention.py src/phishhawk/server/worker.py tests/server/conftest.py tests/server/test_processing.py tests/server/test_worker.py
git commit -m "Add intake, the analysis worker and retention"
```

### Task 10: Key rotation

*PR 4.*

Re-encrypt every stored blob and secret under a new key, then record the rotation. Safe to run again after a crash, and it deletes nothing if a value opens under neither key.

**Files:**

- Create: `src/phishhawk/server/rotation.py`
- Test: `tests/server/test_rotation.py` (new)

**Interfaces:**

- Consumes:
  - `phishhawk.server.audit` (task 5): `record(db: Session, actor: str, action: str, object_type: str='', object_id: object='', details: dict[str, Any] | None=None) -> AuditRecord`
  - `phishhawk.server.crypto` (task 2): `class Box`; `class DecryptError(Exception)`
  - `phishhawk.server.models` (task 3): `class Analysis(Base)`; `class Message(Base)`; `class Setting(Base)`
  - `phishhawk.server.store` (task 4): `class BlobStore`
- Produces:
  - `phishhawk.server.rotation`: `rotate(db: Session, store: BlobStore, new_box: Box, actor: str) -> dict[str, int]`

**Notes:**

- Run with the server stopped: a worker writing new blobs under the old key mid-rotation would leave them behind. The CLI task (14) and docs/SERVER.md say so.
- The trait key is re-encrypted like any secret, but its value stays the same (spec 5.2).

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_rotation.py`:

```python
"""Key rotation re-encrypts every tier-1 blob and every stored secret, and can
be run again after a crash."""

import pytest
from sqlalchemy import select

from phishhawk.server import appsettings, audit, intake, rotation, worker
from phishhawk.server.crypto import Box, DecryptError, new_key
from phishhawk.server.db import transaction
from phishhawk.server.models import Analysis, AuditRecord, Message
from phishhawk.server.store import BlobStore

from conftest import sample


def _analysed(services):
    with open(sample("sample_phish.eml"), "rb") as handle:
        raw = handle.read()
    with transaction(services.sessions) as s:
        intake.accept(s, services.store, raw, source="upload", user_id=None, actor="alice", offline=True,
                      max_bytes=25 * 1024 * 1024)
        appsettings.set_secret(s, services.box, "key:virustotal", "vt-key-1234")
        appsettings.trait_key(s, services.box)
    assert worker.run_one(services)


def _blob_ids(s):
    ids = [m.raw_blob for m in s.scalars(select(Message))]
    for analysis in s.scalars(select(Analysis)):
        ids += [analysis.data_blob] + [f["blob"] for f in analysis.files]
    return ids


def test_rotation_moves_every_blob_and_secret_to_the_new_key(services):
    _analysed(services)
    new_box = Box.from_b64(new_key())
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli") == {"blobs": 9, "secrets": 2}
    moved = BlobStore(services.store.root, new_box)
    with transaction(services.sessions) as s:
        for blob_id in _blob_ids(s):
            moved.get(blob_id)
            with pytest.raises(DecryptError):
                services.store.get(blob_id)
        assert appsettings.get_secret(s, new_box, "key:virustotal") == "vt-key-1234"
        with pytest.raises(DecryptError):
            appsettings.get_secret(s, services.box, "key:virustotal")
        entry = s.scalars(select(AuditRecord).where(AuditRecord.action == "rotate_key")).one()
        assert entry.actor == "cli" and entry.details == {"blobs": 9, "secrets": 2}
        assert audit.verify(s) == []


def test_rotation_run_again_after_a_crash_skips_what_already_moved(services):
    _analysed(services)
    new_box = Box.from_b64(new_key())
    with transaction(services.sessions) as s:
        first = _blob_ids(s)[0]
    services.store.reseal(first, new_box)  # the crash happened after one blob
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli") == {"blobs": 8, "secrets": 2}
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli") == {"blobs": 0, "secrets": 0}


def test_a_blob_neither_key_opens_stops_the_rotation_and_deletes_nothing(services):
    _analysed(services)
    with transaction(services.sessions) as s:
        damaged = _blob_ids(s)[0]
    services.store._path(damaged).write_bytes(b"PHB1" + b"\0" * 40)
    with transaction(services.sessions) as s, pytest.raises(DecryptError):
        rotation.rotate(s, services.store, Box.from_b64(new_key()), actor="cli")
    with transaction(services.sessions) as s:
        assert all(services.store._path(blob_id).exists() for blob_id in _blob_ids(s))
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_rotation.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'rotation' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/rotation.py`:

```python
"""Key rotation: every tier-1 blob and every stored secret re-encrypted under
a new key, then one audit record. Run it with the server stopped. What already
opens under the new key is left alone, so it can be run again after a crash;
a value that neither key opens stops it before anything is deleted."""

from __future__ import annotations

import base64

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .crypto import Box, DecryptError
from .models import Analysis, Message, Setting
from .store import BlobStore


def _blob_ids(db: Session) -> list[str]:
    ids = [m.raw_blob for m in db.scalars(select(Message)) if m.raw_blob]
    for analysis in db.scalars(select(Analysis)):
        ids += [analysis.data_blob] if analysis.data_blob else []
        ids += [f["blob"] for f in analysis.files if f.get("blob")]
    return ids


def _reseal_secret(row: Setting, old_box: Box, new_box: Box) -> bool:
    sealed, bound_to = base64.b64decode(row.value), "setting:" + row.key.removeprefix("secret:")
    try:
        new_box.open(sealed, bound_to)
        return False
    except DecryptError:
        pass
    row.value = base64.b64encode(new_box.seal(old_box.open(sealed, bound_to), bound_to)).decode("ascii")
    return True


def rotate(db: Session, store: BlobStore, new_box: Box, actor: str) -> dict[str, int]:
    blobs = sum(store.reseal(blob_id, new_box) for blob_id in _blob_ids(db))
    rows = db.scalars(select(Setting).where(Setting.key.startswith("secret:"))).all()
    secrets = sum(_reseal_secret(row, store.box, new_box) for row in rows if row.value)
    counts = {"blobs": blobs, "secrets": secrets}
    if blobs or secrets:
        audit.record(db, actor, "rotate_key", details=counts)
    return counts
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_rotation.py
```
Expected: 3 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/rotation.py tests/server/test_rotation.py
git commit -m "Add encryption key rotation that can be run again after a crash"
```

### Task 11: The JSON API

*PR 5.*

Everything the pages and other tools need, under `/api/v1`: sessions, submissions, analyses and their files, messages (raw download, delete, hold), settings, users, tokens and the audit log, plus `/healthz`. Every response carries the security headers; a role matrix test calls every route as anonymous, analyst, admin and both kinds of token.

**Files:**

- Create: `src/phishhawk/server/security.py`
- Create: `src/phishhawk/server/views.py`
- Create: `src/phishhawk/server/deps.py`
- Create: `src/phishhawk/server/routes/__init__.py`
- Create: `src/phishhawk/server/routes/files.py`
- Create: `src/phishhawk/server/routes/api.py`
- Create: `src/phishhawk/server/app.py`
- Test: `tests/server/serverkit.py` (new)
- Test: `tests/server/test_api.py` (new)
- Test: `tests/server/test_rbac.py` (new)
- Test: `tests/server/conftest.py` (changed)

**Interfaces:**

- Consumes:
  - `phishhawk.server.appsettings` (task 7): `KEYED`; `LIMITS`; `LISTS`; `limit(db: Session, settings: ServerSettings, name: str) -> int`; `public_view(db: Session, box: Box, settings: ServerSettings) -> dict[str, Any]`; `set_secret(db: Session, box: Box, name: str, value: str) -> None`; `set_value(db: Session, key: str, value: Any) -> None`
  - `phishhawk.server.audit` (task 5): `record(db: Session, actor: str, action: str, object_type: str='', object_id: object='', details: dict[str, Any] | None=None) -> AuditRecord`
  - `phishhawk.server.auth` (task 6): `ROLES`; `check_login(db: DbSession, username: str, password: str) -> User | None`; `class Actor`; `class AuthError(ValueError)`; `class LoginThrottle`; `close_session(db: DbSession, cookie: str, secret: str) -> None`; `create_token(db: DbSession, user: User, name: str, scope: str) -> str`; `create_user(db: DbSession, username: str, password: str, role: str) -> User`; `find_session(db: DbSession, cookie: str, secret: str, idle_minutes: int) -> Actor | None`; `find_token(db: DbSession, token: str) -> Actor | None`; `open_session(db: DbSession, user: User, secret: str) -> tuple[str, Session]`; `set_password(user: User, password: str) -> None`
  - `phishhawk.server.config` (task 2): `class ServerSettings(BaseSettings)`; `load_settings() -> ServerSettings`
  - `phishhawk.server.crypto` (task 2): `class Box`
  - `phishhawk.server.db` (task 3): `make_engine(url: str) -> Engine`; `make_sessionmaker(engine: Engine) -> sessionmaker[Session]`; `transaction(factory: sessionmaker[Session]) -> Iterator[Session]`
  - `phishhawk.server.intake` (task 9): `accept(db: Session, store: BlobStore, raw: bytes, *, source: str, user_id: int | None, actor: str, offline: bool, max_bytes: int) -> Submission`; `class IntakeError(ValueError)`
  - `phishhawk.server.jobs` (task 8): `enqueue(db: Session, kind: str, payload: dict[str, Any] | None=None) -> Job`
  - `phishhawk.server.models` (task 3): `class Analysis(Base)`; `class ApiToken(Base)`; `class AuditRecord(Base)`; `class Indicator(Base)`; `class Job(Base)`; `class Message(Base)`; `class Submission(Base)`; `class User(Base)`; `utcnow() -> dt.datetime`
  - `phishhawk.server.processing` (task 9): `class Services`
  - `phishhawk.server.retention` (task 9): `delete_completely(db: Session, store: BlobStore, message: Message) -> str`; `delete_tier1(db: Session, store: BlobStore, message: Message, reason: str) -> None`
  - `phishhawk.server.store` (task 4): `class BlobStore`
  - `phishhawk` (main): `__version__`
- Produces:
  - `phishhawk.server.security`: `APP_CSP`; `REPORT_CSP`; `BASE_HEADERS`; `HSTS`
  - `phishhawk.server.views`: `PAGE`; `report_data(store: BlobStore, analysis: Analysis) -> dict[str, Any] | None`; `summary(store: BlobStore, analysis: Analysis, message: Message, submission: Submission, with_report: bool=False, submitter: str | None=None) -> dict[str, Any]`; `find(db: Session, analysis_id: int) -> tuple[Analysis, Message, Submission] | None`; `listing(db: Session, store: BlobStore, q: str='', verdict: str='', offset: int=0) -> list[dict[str, Any]]`; `is_owner(db: Session, message_id: int, user_id: int) -> bool`; `usernames(db: Session) -> dict[int, str]`
  - `phishhawk.server.deps`: `COOKIE`; `SAFE_METHODS`; `services(request: Request) -> Services`; `secret(request: Request) -> str`; `get_db(request: Request) -> Iterator[Session]`; `DB = Annotated[Session, Depends(get_db, scope='function')]`; `optional_actor(request: Request, db: DB) -> Actor | None`; `require_actor(request: Request, current: Annotated[Actor | None, Depends(optional_actor)]) -> Actor`; `require_admin(current: Annotated[Actor, Depends(require_actor)]) -> Actor`; `CurrentActor = Annotated[Actor, Depends(require_actor)]`; `Admin = Annotated[Actor, Depends(require_admin)]`
  - `phishhawk.server.routes.files`: `MEDIA`; `serve_file(store: BlobStore, analysis: Analysis, name: str, download: bool) -> Response`
  - `phishhawk.server.routes.api`: `MB`; `class Login(BaseModel)`: `username: str`; `password: str`; `login_response(request: Request, db: DB, username: str, password: str) -> tuple[str, str] | JSONResponse`; `set_cookie(request: Request, response: Response, cookie: str) -> None`; `POST /api/v1/session` → `create_session`; `DELETE /api/v1/session` → `delete_session`; `POST /api/v1/submissions` → `submit`; `submission_view(db: DB, submission: Submission) -> dict[str, Any]`; `GET /api/v1/submissions/{submission_id}` → `get_submission`; `GET /api/v1/analyses` → `list_analyses`; `GET /api/v1/analyses/{analysis_id}` → `get_analysis`; `GET /api/v1/analyses/{analysis_id}/files/{name}` → `get_file`; `POST /api/v1/analyses/{analysis_id}/reanalyze` → `reanalyze`; `GET /api/v1/messages/{message_id}/raw` → `get_raw`; `DELETE /api/v1/messages/{message_id}` → `delete_message`; `POST /api/v1/messages/{message_id}/hold` → `hold`; `DELETE /api/v1/messages/{message_id}/hold` → `release`; `class SettingsPatch(BaseModel)`: `providers: list[str] | None`; `protected_domains: list[str] | None`; `allow_domains: list[str] | None`; `block_domains: list[str] | None`; `trusted_authserv: list[str] | None`; `retention_days: int | None`; `max_upload_mb: int | None`; `max_batch_messages: int | None`; `campaign_window_days: int | None`; `keys: dict[str, str] | None`; `GET /api/v1/settings` → `get_settings`; `PATCH /api/v1/settings` → `patch_settings`; `apply_settings(db: DB, s: Any, body: SettingsPatch) -> list[str]`; `class NewUser(BaseModel)`: `username: str`; `password: str`; `role: str`; `class UserPatch(BaseModel)`: `role: str | None`; `disabled: bool | None`; `password: str | None`; `GET /api/v1/users` → `list_users`; `POST /api/v1/users` → `create_user`; `PATCH /api/v1/users/{user_id}` → `patch_user`; `class NewToken(BaseModel)`: `name: str`; `scope: str`; `user_id: int`; `GET /api/v1/tokens` → `list_tokens`; `POST /api/v1/tokens` → `create_token`; `DELETE /api/v1/tokens/{token_id}` → `revoke_token`; `GET /api/v1/audit` → `list_audit`
  - `phishhawk.server.app`: `build_services(settings: ServerSettings) -> Services`; `create_app(settings: ServerSettings | None=None, services: Services | None=None) -> FastAPI`; `ERROR_CODES`

**Notes:**

- The database dependency uses `Depends(get_db, scope="function")`, so the transaction commits before the response is sent. A default yield dependency would commit after the client already has its 2xx.
- State-changing requests need the session's CSRF token, in `X-CSRF-Token` or a `csrf_token` form field. A `read` token gets 403 on any unsafe method.
- Raw message downloads and deletions need a logged-in session (owner or admin), never a token. A message on hold cannot be deleted (409) until an admin releases it.
- `POST /submissions` and `POST /analyses/{id}/reanalyze` answer with the same shape as `GET /submissions/{id}`.
- The HTML report is served inline with its own CSP (`sandbox`, no script, `frame-ancestors 'self'`); every other file, and the raw message, downloads as an attachment.

- [ ] **Step 1: Write the failing tests**

Change `tests/server/conftest.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/conftest.py
+++ b/tests/server/conftest.py
@@ -6,6 +6,8 @@
 from phishhawk.server.crypto import Box, new_key
 from phishhawk.server.db import make_engine, make_sessionmaker, migrate
 from phishhawk.server.store import BlobStore
+
+from .serverkit import PASSWORD, login
 
 
 @pytest.fixture
@@ -35,3 +37,38 @@
     from phishhawk.server.processing import Services
 
     return Services(settings, db, box, store)
+
+
+@pytest.fixture
+def app(services):
+    from phishhawk.server import auth
+    from phishhawk.server.app import create_app
+    from phishhawk.server.db import transaction
+
+    with transaction(services.sessions) as s:
+        auth.create_user(s, "admin", PASSWORD, "admin")
+        auth.create_user(s, "alice", PASSWORD, "analyst")
+        auth.create_user(s, "bob", PASSWORD, "analyst")
+    return create_app(services=services)
+
+
+@pytest.fixture
+def anon(app):
+    from fastapi.testclient import TestClient
+
+    return TestClient(app)
+
+
+@pytest.fixture
+def admin(app):
+    return login(app, "admin")
+
+
+@pytest.fixture
+def alice(app):
+    return login(app, "alice")
+
+
+@pytest.fixture
+def bob(app):
+    return login(app, "bob")
```

Create `tests/server/serverkit.py`:

```python
"""Helpers the server tests share."""

PASSWORD = "correct horse battery"


def login(app, username):
    """A client logged in as username, sending its CSRF token on every request."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post("/api/v1/session", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client
```

Create `tests/server/test_api.py`:

```python
"""The JSON API end to end: login, CSRF, submit, worker, view, download,
delete, and the headers on every response."""

from phishhawk.server import worker
from phishhawk.server.security import REPORT_CSP

from conftest import sample


def _raw(name="sample_bec_smuggling.eml"):
    with open(sample(name), "rb") as handle:
        return handle.read()


def _analysed(client, services, name="sample_bec_smuggling.eml"):
    response = client.post("/api/v1/submissions", files={"file": ("m.eml", _raw(name), "message/rfc822")},
                           data={"offline": "true"})
    assert response.status_code == 202, response.text
    assert set(response.json()) == {"id", "status", "error", "analysis_id", "submitted_at"}
    submission_id = response.json()["id"]
    assert worker.run_one(services)
    status = client.get("/api/v1/submissions/%d" % submission_id).json()
    assert status["status"] == "done", status
    return status["analysis_id"]


def test_every_response_has_the_security_headers(anon):
    for path in ("/healthz", "/api/v1/analyses"):
        headers = anon.get(path).headers
        assert "default-src 'none'" in headers["content-security-policy"], path
        assert "frame-ancestors 'none'" in headers["content-security-policy"], path
        assert headers["x-content-type-options"] == "nosniff" and headers["referrer-policy"] == "no-referrer"


def test_health_reports_the_queue(anon):
    body = anon.get("/healthz").json()
    assert body["status"] == "ok" and body["queue"] == 0


def test_login_sets_a_strict_http_only_cookie_and_wrong_passwords_are_audited(app, anon, admin):
    response = anon.post("/api/v1/session", json={"username": "alice", "password": "not the password"})
    assert response.status_code == 401
    good = anon.post("/api/v1/session", json={"username": "alice", "password": "correct horse battery"})
    cookie = good.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    actions = [r["action"] for r in admin.get("/api/v1/audit").json()]
    assert "login_failed" in actions


def test_a_state_change_without_the_csrf_token_is_refused(alice):
    token = alice.headers.pop("X-CSRF-Token")
    files = {"file": ("m.eml", _raw(), "message/rfc822")}
    assert alice.post("/api/v1/submissions", files=files).status_code == 403
    alice.headers["X-CSRF-Token"] = token
    assert alice.post("/api/v1/submissions", files=files).status_code == 202


def test_submit_analyse_view_and_download(alice, services):
    analysis_id = _analysed(alice, services)
    body = alice.get("/api/v1/analyses/%d" % analysis_id).json()
    assert body["verdict"] == "LIKELY PHISHING" and body["report"]["verdict"] == "LIKELY PHISHING"
    assert body["subject"].startswith("Urgent") and body["lookups"] == []
    assert body["submitted_by_name"] == "alice"  # a frontend shows who submitted it without the users list
    names = {f["kind"]: f["name"] for f in body["files"]}
    report = alice.get("/api/v1/analyses/%d/files/%s" % (analysis_id, names["html"]))
    assert report.status_code == 200 and report.headers["content-security-policy"] == REPORT_CSP
    csv = alice.get("/api/v1/analyses/%d/files/%s" % (analysis_id, names["csv"]))
    assert csv.headers["content-disposition"] == 'attachment; filename="%s"' % names["csv"]
    raw = alice.get("/api/v1/messages/%d/raw" % body["message_id"])
    assert raw.content == _raw() and raw.headers["content-disposition"].startswith("attachment")
    assert alice.get("/api/v1/analyses?q=examp1e-corp").json()[0]["id"] == analysis_id
    assert alice.get("/api/v1/analyses?q=%s" % body["report_id"]).json()[0]["id"] == analysis_id


def test_only_the_submitter_or_an_admin_deletes_and_only_an_admin_deletes_completely(alice, bob, admin, services):
    analysis_id = _analysed(alice, services)
    message_id = alice.get("/api/v1/analyses/%d" % analysis_id).json()["message_id"]
    assert bob.delete("/api/v1/messages/%d" % message_id).status_code == 403
    assert bob.get("/api/v1/messages/%d/raw" % message_id).status_code == 403
    assert alice.delete("/api/v1/messages/%d?scope=all" % message_id).status_code == 403
    assert alice.delete("/api/v1/messages/%d" % message_id).json() == {"deleted": "tier1"}
    body = alice.get("/api/v1/analyses/%d" % analysis_id).json()
    assert body["report"] is None and body["verdict"] == "LIKELY PHISHING" and body["subject"] is None
    html = next(f["name"] for f in body["files"] if f["kind"] == "html")
    assert alice.get("/api/v1/analyses/%d/files/%s" % (analysis_id, html)).status_code == 410
    assert admin.delete("/api/v1/messages/%d?scope=all" % message_id).json() == {"deleted": "all"}
    assert alice.get("/api/v1/analyses/%d" % analysis_id).status_code == 404


def test_repeated_wrong_passwords_are_throttled(anon):
    codes = [anon.post("/api/v1/session", json={"username": "alice", "password": "wrong password!"}).status_code
             for _ in range(4)]
    assert codes[:3] == [401, 401, 401] and codes[3] == 429
```

Create `tests/server/test_rbac.py`:

```python
"""Every route, called as anonymous, analyst, admin and with both kinds of
API token: the status says who may do what (spec 7.2)."""

import pytest

from phishhawk.server import worker

from .serverkit import login
from conftest import sample

# (method, path, (anonymous, analyst, admin, read token, submit token))
MATRIX = [
    ("GET", "/api/v1/analyses", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/analyses/{analysis}", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/submissions/{submission}", (401, 200, 200, 200, 200)),
    ("POST", "/api/v1/analyses/{analysis}/reanalyze", (401, 202, 202, 403, 202)),
    ("GET", "/api/v1/messages/{message}/raw", (401, 403, 200, 403, 403)),
    ("DELETE", "/api/v1/messages/{message}", (401, 403, 200, 403, 403)),
    ("POST", "/api/v1/messages/{message}/hold", (401, 403, 200, 403, 403)),
    ("DELETE", "/api/v1/messages/{message}/hold", (401, 403, 200, 403, 403)),
    ("GET", "/api/v1/settings", (401, 403, 200, 403, 403)),
    ("PATCH", "/api/v1/settings", (401, 403, 200, 403, 403)),
    ("GET", "/api/v1/users", (401, 403, 200, 403, 403)),
    ("POST", "/api/v1/users", (401, 403, 201, 403, 403)),
    ("GET", "/api/v1/tokens", (401, 403, 200, 403, 403)),
    ("GET", "/api/v1/audit", (401, 200, 200, 200, 200)),
]
BODIES = {("PATCH", "/api/v1/settings"): {"retention_days": 20},
          ("POST", "/api/v1/users"): {"username": "carol", "password": "another long password", "role": "analyst"}}


@pytest.fixture
def world(app, services, admin):
    """One analysed message submitted by the admin, and one token of each scope."""
    with open(sample("sample_phish.eml"), "rb") as handle:
        submitted = admin.post("/api/v1/submissions", files={"file": ("m.eml", handle.read(), "message/rfc822")},
                               data={"offline": "true"}).json()
    worker.run_one(services)
    analysis = admin.get("/api/v1/submissions/%d" % submitted["id"]).json()["analysis_id"]
    message = admin.get("/api/v1/analyses/%d" % analysis).json()["message_id"]
    users = {u["username"]: u["id"] for u in admin.get("/api/v1/users").json()}
    tokens = {scope: admin.post("/api/v1/tokens", json={"name": scope, "scope": scope,
                                                        "user_id": users["admin"]}).json()["token"]
              for scope in ("read", "submit")}
    return {"analysis": analysis, "message": message, "submission": submitted["id"], "tokens": tokens}


@pytest.mark.parametrize("method, path, expected", MATRIX)
def test_the_role_matrix(app, anon, world, method, path, expected):
    from fastapi.testclient import TestClient

    url = path.format(**world)
    callers = [anon, login(app, "alice"), login(app, "admin")]
    for scope in ("read", "submit"):
        client = TestClient(app)
        client.headers["Authorization"] = "Bearer " + world["tokens"][scope]
        callers.append(client)
    for caller, status in zip(callers, expected, strict=True):
        response = caller.request(method, url, json=BODIES.get((method, path)), follow_redirects=False)
        assert response.status_code == status, (caller.headers.get("authorization", "session"), url,
                                                response.status_code, response.text[:200])
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_api.py tests/server/test_rbac.py
```

Expected: FAIL. The first error is `ModuleNotFoundError: No module named 'phishhawk.server.security'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/security.py`:

```python
"""Response headers. Every page gets a strict policy; the stored HTML report
gets a sandbox on top of its own policy, so it runs in an opaque origin."""

from __future__ import annotations

APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
           "connect-src 'self'; frame-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
REPORT_CSP = ("sandbox allow-popups allow-popups-to-escape-sandbox allow-downloads; default-src 'none'; "
              "style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'; "
              "frame-ancestors 'self'")
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
HSTS = "max-age=31536000"
```

Create `src/phishhawk/server/views.py`:

```python
"""Queries the API and the pages share."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Analysis, Indicator, Message, Submission, User
from .store import BlobStore

PAGE = 50


def report_data(store: BlobStore, analysis: Analysis) -> dict[str, Any] | None:
    """The full JSON report while tier 1 exists."""
    if analysis.data_blob is None:
        return None
    data: dict[str, Any] = json.loads(store.get(analysis.data_blob))
    return data


def summary(store: BlobStore, analysis: Analysis, message: Message, submission: Submission,
            with_report: bool = False, submitter: str | None = None) -> dict[str, Any]:
    report = report_data(store, analysis)
    view = {
        "id": analysis.id, "message_id": message.id, "submission_id": submission.id,
        "submitted_by": submission.user_id, "submitted_by_name": submitter, "source": submission.source,
        "offline": submission.offline,
        "sha256": message.sha256, "report_id": analysis.report_id, "verdict": analysis.verdict,
        "score": analysis.score, "sender": message.sender, "sender_domain": message.sender_domain,
        "subject": report["subject"] if report else None, "created_at": analysis.created_at.isoformat(),
        "providers": analysis.providers, "lookups": analysis.lookups, "techniques": analysis.techniques,
        "hold": message.hold, "tier1_deleted_at": message.tier1_deleted_at.isoformat()
        if message.tier1_deleted_at else None,
        "files": [{k: f[k] for k in ("name", "kind", "type", "size", "sha256")} | {"available": bool(f["blob"])}
                  for f in analysis.files],
    }
    if with_report:
        view["report"] = report
    return view


def find(db: Session, analysis_id: int) -> tuple[Analysis, Message, Submission] | None:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        return None
    message, submission = db.get(Message, analysis.message_id), db.get(Submission, analysis.submission_id)
    if message is None or submission is None:
        return None
    return analysis, message, submission


def listing(db: Session, store: BlobStore, q: str = "", verdict: str = "",
            offset: int = 0) -> list[dict[str, Any]]:
    query = (select(Analysis, Message, Submission).join(Message, Analysis.message_id == Message.id)
             .join(Submission, Analysis.submission_id == Submission.id).order_by(Analysis.id.desc()))
    if verdict:
        query = query.where(Analysis.verdict == verdict)
    q = q.strip()
    if q:
        query = query.where(or_(Message.sha256.startswith(q.lower(), autoescape=True),
                                Analysis.report_id == q.upper(),
                                Analysis.id.in_(select(Indicator.analysis_id)
                                                .where(Indicator.value.contains(q, autoescape=True)))))
    rows = db.execute(query.offset(max(0, offset)).limit(PAGE)).all()
    names = usernames(db)
    return [summary(store, a, m, s, submitter=names.get(s.user_id or 0)) for a, m, s in rows]


def is_owner(db: Session, message_id: int, user_id: int) -> bool:
    return db.scalars(select(Submission.id).where(Submission.message_id == message_id,
                                                  Submission.user_id == user_id).limit(1)).first() is not None


def usernames(db: Session) -> dict[int, str]:
    return {u.id: u.username for u in db.scalars(select(User))}
```

Create `src/phishhawk/server/deps.py`:

```python
"""Request dependencies: the database session (committed before the response
is sent), who is asking, CSRF for browser sessions, and roles."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import auth
from .auth import Actor
from .processing import Services

COOKIE = "phishhawk_session"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def services(request: Request) -> Services:
    found: Services = request.app.state.services
    return found


def secret(request: Request) -> str:
    return services(request).settings.secret_key.get_secret_value()


def get_db(request: Request) -> Iterator[Session]:
    with services(request).sessions() as db, db.begin():
        yield db


DB = Annotated[Session, Depends(get_db, scope="function")]


def optional_actor(request: Request, db: DB) -> Actor | None:
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        actor = auth.find_token(db, header[7:].strip())
        if actor is None:
            raise HTTPException(401, "that API token is not valid")
        return actor
    cookie = request.cookies.get(COOKIE)
    if not cookie:
        return None
    return auth.find_session(db, cookie, secret(request), services(request).settings.session_idle_minutes)


async def require_actor(request: Request, current: Annotated[Actor | None, Depends(optional_actor)]) -> Actor:
    if current is None:
        raise HTTPException(401, "log in first")
    if request.method in SAFE_METHODS:
        return current
    if current.via == "token":
        if current.scope != "submit":
            raise HTTPException(403, "this API token can only read")
        return current
    sent = request.headers.get("x-csrf-token", "")
    if not sent and request.headers.get("content-type", "").startswith(
            ("application/x-www-form-urlencoded", "multipart/form-data")):
        sent = str((await request.form()).get("csrf_token", ""))
    if not sent or sent != current.csrf:
        raise HTTPException(403, "the form is out of date: reload the page and try again")
    return current


def require_admin(current: Annotated[Actor, Depends(require_actor)]) -> Actor:
    if not current.is_admin:
        raise HTTPException(403, "only an admin can do that")
    return current


CurrentActor = Annotated[Actor, Depends(require_actor)]
Admin = Annotated[Actor, Depends(require_admin)]
```

Create `src/phishhawk/server/routes/__init__.py`:

```python

```

Create `src/phishhawk/server/routes/files.py`:

```python
"""Serving stored exports. The HTML report opens in the browser inside a
sandbox; everything else, and the raw message, downloads as an attachment."""

from __future__ import annotations

from fastapi import HTTPException
from fastapi.responses import Response

from ..models import Analysis
from ..security import REPORT_CSP
from ..store import BlobStore

MEDIA = {"json": "application/json", "stix": "application/json", "misp": "application/json",
         "manifest": "application/json", "md": "text/markdown; charset=utf-8", "csv": "text/csv; charset=utf-8",
         "html": "text/html; charset=utf-8"}


def serve_file(store: BlobStore, analysis: Analysis, name: str, download: bool) -> Response:
    entry = next((f for f in analysis.files if f["name"] == name), None)
    if entry is None:
        raise HTTPException(404, "no such file")
    if not entry.get("blob"):
        raise HTTPException(410, "deleted after the retention period")
    content = store.get(entry["blob"])
    if entry["kind"] == "html" and not download:
        return Response(content, media_type=MEDIA["html"], headers={"Content-Security-Policy": REPORT_CSP})
    return Response(content, media_type=MEDIA[entry["kind"]],
                    headers={"Content-Disposition": 'attachment; filename="%s"' % entry["name"]})
```

Create `src/phishhawk/server/routes/api.py`:

```python
"""The JSON API under /api/v1: what the pages use and what IntelPulse will
call. Every route is in the role matrix test (tests/server/test_rbac.py)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select

from .. import appsettings, audit, auth, intake, jobs, retention, views
from ..deps import COOKIE, DB, Admin, CurrentActor, secret, services
from ..models import Analysis, ApiToken, AuditRecord, Message, Submission, User, utcnow
from .files import serve_file

router = APIRouter(prefix="/api/v1")
MB = 1024 * 1024


class Login(BaseModel):
    username: str
    password: str


def login_response(request: Request, db: DB, username: str, password: str) -> tuple[str, str] | JSONResponse:
    """(cookie, csrf) on success; a JSON error response otherwise (committed, so failures are audited)."""
    throttle = request.app.state.throttle
    keys = ("user:" + username, "ip:" + (request.client.host if request.client else ""))
    wait = throttle.wait(*keys)
    if wait > 0:
        return JSONResponse({"error": "throttled", "detail": "too many attempts: wait %d s" % (wait + 1)},
                            status_code=429, headers={"Retry-After": str(int(wait) + 1)})
    user = auth.check_login(db, username, password)
    if user is None:
        throttle.failed(*keys)
        audit.record(db, username[:64] or "?", "login_failed")
        return JSONResponse({"error": "unauthorized", "detail": "wrong username or password"}, status_code=401)
    throttle.succeeded(*keys)
    cookie, session = auth.open_session(db, user, secret(request))
    audit.record(db, user.username, "login")
    return cookie, session.csrf_token


def set_cookie(request: Request, response: Response, cookie: str) -> None:
    settings = services(request).settings
    response.set_cookie(COOKIE, cookie, httponly=True, secure=settings.cookie_secure, samesite="strict",
                        max_age=settings.session_idle_minutes * 60, path="/")


@router.post("/session")
def create_session(request: Request, db: DB, body: Login) -> Response:
    outcome = login_response(request, db, body.username, body.password)
    if isinstance(outcome, JSONResponse):
        return outcome
    response = JSONResponse({"csrf": outcome[1]})
    set_cookie(request, response, outcome[0])
    return response


@router.delete("/session", status_code=204)
def delete_session(request: Request, db: DB, actor: CurrentActor) -> Response:
    auth.close_session(db, request.cookies.get(COOKIE, ""), secret(request))
    audit.record(db, actor.label, "logout")
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/")
    return response


@router.post("/submissions", status_code=202)
async def submit(request: Request, db: DB, actor: CurrentActor,
                 file: Annotated[UploadFile | None, File()] = None,
                 raw: Annotated[str, Form()] = "", offline: Annotated[bool, Form()] = False) -> dict[str, Any]:
    s = services(request)
    data = await file.read(appsettings.limit(db, s.settings, "max_upload_mb") * MB + 1) if file else raw.encode()
    try:
        submission = intake.accept(db, s.store, data, source="upload" if file else "paste", user_id=actor.user_id,
                                   actor=actor.label, offline=offline,
                                   max_bytes=appsettings.limit(db, s.settings, "max_upload_mb") * MB)
    except intake.IntakeError as exc:
        raise HTTPException(exc.status, str(exc)) from exc
    return submission_view(db, submission)


def submission_view(db: DB, submission: Submission) -> dict[str, Any]:
    analysis = db.scalars(select(Analysis.id).where(Analysis.submission_id == submission.id)).first()
    return {"id": submission.id, "status": submission.status, "error": submission.error,
            "analysis_id": analysis, "submitted_at": submission.submitted_at.isoformat()}


@router.get("/submissions/{submission_id}")
def get_submission(db: DB, actor: CurrentActor, submission_id: int) -> dict[str, Any]:
    submission = db.get(Submission, submission_id)
    if submission is None:
        raise HTTPException(404, "no such submission")
    return submission_view(db, submission)


@router.get("/analyses")
def list_analyses(request: Request, db: DB, actor: CurrentActor, q: str = "", verdict: str = "",
                  offset: Annotated[int, Query(ge=0)] = 0) -> list[dict[str, Any]]:
    return views.listing(db, services(request).store, q, verdict, offset)


def _found(db: DB, analysis_id: int) -> tuple[Any, Message, Submission]:
    found = views.find(db, analysis_id)
    if found is None:
        raise HTTPException(404, "no such analysis")
    return found


@router.get("/analyses/{analysis_id}")
def get_analysis(request: Request, db: DB, actor: CurrentActor, analysis_id: int) -> dict[str, Any]:
    analysis, message, submission = _found(db, analysis_id)
    submitter = views.usernames(db).get(submission.user_id or 0)
    return views.summary(services(request).store, analysis, message, submission, with_report=True,
                         submitter=submitter)


@router.get("/analyses/{analysis_id}/files/{name}")
def get_file(request: Request, db: DB, actor: CurrentActor, analysis_id: int, name: str,
             download: bool = False) -> Response:
    analysis, _, _ = _found(db, analysis_id)
    audit.record(db, actor.label, "download", "analysis", analysis_id, {"file": name})
    return serve_file(services(request).store, analysis, name, download)


@router.post("/analyses/{analysis_id}/reanalyze", status_code=202)
def reanalyze(db: DB, actor: CurrentActor, analysis_id: int) -> dict[str, Any]:
    _, message, old = _found(db, analysis_id)
    if message.raw_blob is None:
        raise HTTPException(410, "the message was deleted after the retention period")
    submission = Submission(message_id=message.id, user_id=actor.user_id, source=old.source, offline=old.offline)
    db.add(submission)
    db.flush()
    jobs.enqueue(db, "analyze", {"submission_id": submission.id})
    audit.record(db, actor.label, "reanalyze", "analysis", analysis_id, {"submission": submission.id})
    return submission_view(db, submission)


def _session_only(actor: Any, what: str) -> None:
    """Raw messages and deletions need a person at a browser, never an API token."""
    if actor.via != "session":
        raise HTTPException(403, "an API token cannot %s" % what)


def _message(db: DB, message_id: int) -> Message:
    message = db.get(Message, message_id)
    if message is None:
        raise HTTPException(404, "no such message")
    return message


@router.get("/messages/{message_id}/raw")
def get_raw(request: Request, db: DB, actor: CurrentActor, message_id: int) -> Response:
    _session_only(actor, "download a raw message")
    message = _message(db, message_id)
    if not actor.is_admin and not views.is_owner(db, message_id, actor.user_id):
        raise HTTPException(403, "only the submitter or an admin can download the raw message")
    if message.raw_blob is None:
        raise HTTPException(410, "deleted after the retention period")
    audit.record(db, actor.label, "download_raw", "message", message_id)
    return Response(services(request).store.get(message.raw_blob), media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="%s.eml"' % message.sha256[:16]})


@router.delete("/messages/{message_id}")
def delete_message(request: Request, db: DB, actor: CurrentActor, message_id: int,
                   scope: Annotated[str, Query(pattern="^(tier1|all)$")] = "tier1") -> dict[str, Any]:
    _session_only(actor, "delete messages")
    message, store = _message(db, message_id), services(request).store
    if message.hold:
        raise HTTPException(409, "this message is on hold; an admin must release it first")
    if scope == "all":
        if not actor.is_admin:
            raise HTTPException(403, "only an admin can delete completely")
        sha256 = retention.delete_completely(db, store, message)
        audit.record(db, actor.label, "delete_completely", "message", message_id, {"sha256": sha256})
        return {"deleted": "all"}
    if not actor.is_admin and not views.is_owner(db, message_id, actor.user_id):
        raise HTTPException(403, "only the submitter or an admin can delete this message")
    retention.delete_tier1(db, store, message, "manual")
    audit.record(db, actor.label, "delete_tier1", "message", message_id, {"sha256": message.sha256})
    return {"deleted": "tier1"}


@router.post("/messages/{message_id}/hold")
def hold(db: DB, actor: Admin, message_id: int) -> dict[str, Any]:
    _message(db, message_id).hold = True
    audit.record(db, actor.label, "hold", "message", message_id)
    return {"hold": True}


@router.delete("/messages/{message_id}/hold")
def release(db: DB, actor: Admin, message_id: int) -> dict[str, Any]:
    _message(db, message_id).hold = False
    audit.record(db, actor.label, "release", "message", message_id)
    return {"hold": False}


class SettingsPatch(BaseModel):
    providers: list[str] | None = None
    protected_domains: list[str] | None = None
    allow_domains: list[str] | None = None
    block_domains: list[str] | None = None
    trusted_authserv: list[str] | None = None
    retention_days: int | None = None
    max_upload_mb: int | None = None
    max_batch_messages: int | None = None
    campaign_window_days: int | None = None
    keys: dict[str, str] | None = None  # provider -> new key ("" removes it)


@router.get("/settings")
def get_settings(request: Request, db: DB, actor: Admin) -> dict[str, Any]:
    s = services(request)
    return appsettings.public_view(db, s.box, s.settings)


@router.patch("/settings")
def patch_settings(request: Request, db: DB, actor: Admin, body: SettingsPatch) -> dict[str, Any]:
    s = services(request)
    changed = apply_settings(db, s, body)
    audit.record(db, actor.label, "settings", details={"changed": changed})
    return appsettings.public_view(db, s.box, s.settings)


def apply_settings(db: DB, s: Any, body: SettingsPatch) -> list[str]:
    changed: list[str] = []
    for name in appsettings.LISTS:
        value = getattr(body, name)
        if value is not None:
            appsettings.set_value(db, name, sorted({v.strip().lower() for v in value if v.strip()}))
            changed.append(name)
    for name in appsettings.LIMITS:
        value = getattr(body, name)
        if value is not None:
            if not 1 <= value <= 100000:
                raise HTTPException(422, "%s must be between 1 and 100000" % name)
            appsettings.set_value(db, name, value)
            changed.append(name)
    for provider, key in (body.keys or {}).items():
        if provider not in appsettings.KEYED:
            raise HTTPException(422, "no API key for %s" % provider)
        appsettings.set_secret(db, s.box, "key:" + provider, key.strip())
        changed.append("key:" + provider)  # the key itself is never audited
    return changed


class NewUser(BaseModel):
    username: str
    password: str
    role: str


class UserPatch(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None


def _user_view(user: User) -> dict[str, Any]:
    return {"id": user.id, "username": user.username, "role": user.role, "disabled": user.disabled,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None}


@router.get("/users")
def list_users(db: DB, actor: Admin) -> list[dict[str, Any]]:
    return [_user_view(u) for u in db.scalars(select(User).order_by(User.username))]


@router.post("/users", status_code=201)
def create_user(db: DB, actor: Admin, body: NewUser) -> dict[str, Any]:
    try:
        user = auth.create_user(db, body.username, body.password, body.role)
    except auth.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor.label, "user_create", "user", user.id, {"username": user.username, "role": user.role})
    return _user_view(user)


@router.patch("/users/{user_id}")
def patch_user(db: DB, actor: Admin, user_id: int, body: UserPatch) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "no such user")
    if user.id == actor.user_id and (body.disabled or (body.role and body.role != "admin")):
        raise HTTPException(422, "you cannot disable yourself or remove your own admin role")
    if body.role is not None:
        if body.role not in auth.ROLES:
            raise HTTPException(422, "role must be admin or analyst")
        user.role = body.role
    if body.disabled is not None:
        user.disabled = body.disabled
    if body.password:
        try:
            auth.set_password(user, body.password)
        except auth.AuthError as exc:
            raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor.label, "user_change", "user", user.id,
                 {"role": body.role, "disabled": body.disabled, "password_changed": bool(body.password)})
    return _user_view(user)


class NewToken(BaseModel):
    name: str
    scope: str
    user_id: int


@router.get("/tokens")
def list_tokens(db: DB, actor: Admin) -> list[dict[str, Any]]:
    return [{"id": t.id, "name": t.name, "scope": t.scope, "user_id": t.user_id,
             "created_at": t.created_at.isoformat(), "revoked": t.revoked_at is not None}
            for t in db.scalars(select(ApiToken).order_by(ApiToken.id))]


@router.post("/tokens", status_code=201)
def create_token(db: DB, actor: Admin, body: NewToken) -> dict[str, Any]:
    user = db.get(User, body.user_id)
    if user is None:
        raise HTTPException(404, "no such user")
    try:
        token = auth.create_token(db, user, body.name, body.scope)
    except auth.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor.label, "token_create", "user", user.id, {"name": body.name, "scope": body.scope})
    return {"token": token, "note": "shown once: store it now"}


@router.delete("/tokens/{token_id}")
def revoke_token(db: DB, actor: Admin, token_id: int) -> dict[str, Any]:
    token = db.get(ApiToken, token_id)
    if token is None:
        raise HTTPException(404, "no such token")
    token.revoked_at = token.revoked_at or utcnow()
    audit.record(db, actor.label, "token_revoke", "token", token_id, {"name": token.name})
    return {"revoked": True}


@router.get("/audit")
def list_audit(db: DB, actor: CurrentActor, offset: Annotated[int, Query(ge=0)] = 0) -> list[dict[str, Any]]:
    query = select(AuditRecord).order_by(AuditRecord.id.desc())
    if not actor.is_admin:
        query = query.where(AuditRecord.actor == actor.label)
    return [{"id": r.id, "at": r.at.isoformat(), "actor": r.actor, "action": r.action,
             "object_type": r.object_type, "object_id": r.object_id, "details": r.details}
            for r in db.scalars(query.offset(offset).limit(100))]
```

Create `src/phishhawk/server/app.py`:

```python
"""The web application: services, security headers, errors, routes."""

from __future__ import annotations

import shutil
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select, text

from .. import __version__
from .auth import LoginThrottle
from .config import ServerSettings, load_settings
from .crypto import Box
from .db import make_engine, make_sessionmaker, transaction
from .models import Job
from .processing import Services
from .security import APP_CSP, BASE_HEADERS, HSTS
from .store import BlobStore


def build_services(settings: ServerSettings) -> Services:
    """Refuses to start without a valid encryption key (fail closed)."""
    box = Box.from_b64(settings.encryption_key.get_secret_value())
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return Services(settings, make_sessionmaker(make_engine(settings.db_url)), box,
                    BlobStore(settings.data_dir / "blobs", box))


def create_app(settings: ServerSettings | None = None, services: Services | None = None) -> FastAPI:
    services = services or build_services(settings or load_settings())
    app = FastAPI(title="PhishHawk", version=__version__, docs_url=None, redoc_url=None)
    app.state.services = services
    app.state.throttle = LoginThrottle()

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", APP_CSP)
        for name, value in BASE_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", HSTS)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        body = {"error": _code(exc.status_code), "detail": exc.detail}
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> Response:
        return JSONResponse({"error": "invalid", "detail": "the request is not valid"}, status_code=422)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        with transaction(services.sessions) as db:
            db.execute(text("SELECT 1"))
            queued = db.scalar(select(func.count()).select_from(Job).where(Job.status == "queued")) or 0
            beat = db.scalar(select(func.max(Job.heartbeat_at)))
        disk = shutil.disk_usage(services.settings.data_dir)
        return {"status": "ok", "version": __version__, "queue": queued,
                "last_heartbeat": beat.isoformat() if beat else None, "disk_free_mb": disk.free // (1024 * 1024)}

    from .routes import api

    app.include_router(api.router)
    return app


ERROR_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
               410: "gone", 413: "too_large", 415: "unsupported", 422: "invalid", 429: "throttled"}


def _code(status: int) -> str:
    return ERROR_CODES.get(status, "error")
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_api.py tests/server/test_rbac.py
```
Expected: 21 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/app.py src/phishhawk/server/deps.py src/phishhawk/server/routes/__init__.py src/phishhawk/server/routes/api.py src/phishhawk/server/routes/files.py src/phishhawk/server/security.py src/phishhawk/server/views.py tests/server/conftest.py tests/server/serverkit.py tests/server/test_api.py tests/server/test_rbac.py
git commit -m "Add the web app's JSON API with a role matrix test"
```

### Task 12: Pages

*PR 6.*

The browser side: log in, submit (upload, paste or drag and drop), the queue with search, the analysis page with the sandboxed report and the downloads, settings, users and tokens, and the audit log. Server-rendered Jinja2 with no inline script or style, so the strict CSP holds; every colour clears WCAG AA in light and dark; a message with a markup payload in every field a sender controls cannot put markup on any page.

**Files:**

- Create: `src/phishhawk/server/routes/pages.py`
- Create: `src/phishhawk/server/templates/base.html`
- Create: `src/phishhawk/server/templates/error.html`
- Create: `src/phishhawk/server/templates/login.html`
- Create: `src/phishhawk/server/templates/_verdict.html`
- Create: `src/phishhawk/server/templates/_table.html`
- Create: `src/phishhawk/server/templates/home.html`
- Create: `src/phishhawk/server/templates/submission.html`
- Create: `src/phishhawk/server/templates/queue.html`
- Create: `src/phishhawk/server/templates/analysis.html`
- Create: `src/phishhawk/server/templates/settings.html`
- Create: `src/phishhawk/server/templates/users.html`
- Create: `src/phishhawk/server/templates/audit.html`
- Create: `src/phishhawk/server/static/app.css`
- Create: `src/phishhawk/server/static/app.js`
- Modify: `src/phishhawk/server/app.py`
- Test: `tests/server/test_pages.py` (new)
- Test: `tests/server/test_hostile.py` (new)
- Test: `tests/server/test_app_style.py` (new)
- Test: `tests/conftest.py` (changed)
- Test: `tests/test_report_a11y.py` (changed)
- Test: `tests/server/test_rbac.py` (changed)

**Interfaces:**

- Consumes:
  - `phishhawk.report.common` (main): `printable(text: str) -> str`
  - `phishhawk.server.appsettings` (task 7): `KEYED`; `LIMITS`; `LISTS`; `PROVIDERS_ALL`; `limit(db: Session, settings: ServerSettings, name: str) -> int`; `public_view(db: Session, box: Box, settings: ServerSettings) -> dict[str, Any]`
  - `phishhawk.server.auth` (task 6): `ROLES`; `TOKEN_SCOPES`
  - `phishhawk.server.deps` (task 11): `Admin = Annotated[Actor, Depends(require_admin)]`; `COOKIE`; `CurrentActor = Annotated[Actor, Depends(require_actor)]`; `DB = Annotated[Session, Depends(get_db, scope='function')]`; `optional_actor(request: Request, db: DB) -> Actor | None`; `services(request: Request) -> Services`
  - `phishhawk.server.intake` (task 9): `accept(db: Session, store: BlobStore, raw: bytes, *, source: str, user_id: int | None, actor: str, offline: bool, max_bytes: int) -> Submission`; `class IntakeError(ValueError)`
  - `phishhawk.server.models` (task 3): `class Analysis(Base)`; `class ApiToken(Base)`; `class AuditRecord(Base)`; `class Submission(Base)`; `class User(Base)`
  - `phishhawk.server.routes.api` (task 11): `class NewToken(BaseModel)`; `class NewUser(BaseModel)`; `class SettingsPatch(BaseModel)`; `class UserPatch(BaseModel)`; `create_token`; `create_user`; `delete_message`; `delete_session`; `get_file`; `hold`; `login_response(request: Request, db: DB, username: str, password: str) -> tuple[str, str] | JSONResponse`; `patch_settings`; `patch_user`; `reanalyze`; `release`; `revoke_token`; `set_cookie(request: Request, response: Response, cookie: str) -> None`; `submission_view(db: DB, submission: Submission) -> dict[str, Any]`
  - `phishhawk.server.views` (task 11): `PAGE`; `find(db: Session, analysis_id: int) -> tuple[Analysis, Message, Submission] | None`; `is_owner(db: Session, message_id: int, user_id: int) -> bool`; `listing(db: Session, store: BlobStore, q: str='', verdict: str='', offset: int=0) -> list[dict[str, Any]]`; `summary(store: BlobStore, analysis: Analysis, message: Message, submission: Submission, with_report: bool=False, submitter: str | None=None) -> dict[str, Any]`; `usernames(db: Session) -> dict[int, str]`
- Produces:
  - `phishhawk.server.routes.pages`: `MB`; `VERDICTS`; `GET /login` → `login_page`; `POST /login` → `login`; `POST /logout` → `logout`; `GET /` → `home`; `POST /` → `submit`; `GET /submissions/{submission_id}` → `submission_page`; `GET /queue` → `queue`; `GET /analyses/{analysis_id}` → `analysis_page`; `GET /analyses/{analysis_id}/files/{name}` → `analysis_file`; `POST /analyses/{analysis_id}/reanalyze` → `reanalyze`; `POST /messages/{message_id}/delete` → `delete`; `POST /messages/{message_id}/hold` → `hold`; `GET /settings` → `settings_page`; `POST /settings` → `save_settings`; `GET /users` → `users_page`; `POST /users` → `add_user`; `POST /users/{user_id}` → `change_user`; `POST /tokens` → `add_token`; `POST /tokens/{token_id}/revoke` → `revoke`; `GET /audit` → `audit_page`
  - `phishhawk.server.app`: `html_response(request: Request, template: str, context: dict[str, Any], status: int=200) -> HTMLResponse`

**Notes:**

- Jinja2 autoescapes every `.html` template; the `printable` filter also strips control characters.
- `static/app.js` only adds drag and drop to the upload box; every page works without it.
- The report sits in `<iframe sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads">` and is also served with the sandbox CSP, so it cannot run script even when opened on its own.
- The analysis page shows only what the viewer may do: no raw download or Delete now for someone else's message, no delete buttons while a message is on hold.
- All colours are tokens in `:root`; `test_app_style.py` checks every text colour against its surface and that no colour is written anywhere else. The contrast helpers move from the report's accessibility test into `tests/conftest.py` so both tests share them.

- [ ] **Step 1: Write the failing tests**

Change `tests/conftest.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/conftest.py
+++ b/tests/conftest.py
@@ -2,6 +2,7 @@
 
 import importlib.util
 import os
+import re
 from email.message import EmailMessage
 
 # The web app's tests need the [server] extra; without it they are not collected.
@@ -73,3 +74,34 @@
         msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename,
                            disposition=disposition)
     return msg.as_bytes()
+
+
+# ------------------------------------------------- colour contrast (WCAG) --
+# Shared by the report's and the web app's accessibility tests.
+
+def css_tokens(block: str) -> dict:
+    return dict(re.findall(r"--([\w-]+):([^;]+);", block))
+
+
+def css_rgb(value: str, under=(255, 255, 255)) -> tuple:
+    value = value.strip()
+    if value.startswith("#"):
+        h = value[1:]
+        if len(h) == 3:
+            h = "".join(c * 2 for c in h)
+        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
+    r, g, b, a = (float(x) for x in re.match(r"rgba\(([^)]+)\)", value).group(1).split(","))
+    return tuple(round(c * a + u * (1 - a)) for c, u in zip((r, g, b), under, strict=True))
+
+
+def _luminance(rgb) -> float:
+    def lin(c):
+        c /= 255
+        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
+    r, g, b = (lin(c) for c in rgb)
+    return 0.2126 * r + 0.7152 * g + 0.0722 * b
+
+
+def contrast(fg, bg) -> float:
+    hi, lo = sorted((_luminance(fg), _luminance(bg)), reverse=True)
+    return (hi + 0.05) / (lo + 0.05)
```

Change `tests/test_report_a11y.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/test_report_a11y.py
+++ b/tests/test_report_a11y.py
@@ -10,7 +10,7 @@
 from phishhawk.pipeline import triage_file
 from phishhawk.report import html
 
-from conftest import sample
+from conftest import contrast, css_rgb, css_tokens, sample
 
 
 @pytest.fixture(scope="module")
@@ -72,34 +72,6 @@
 
 # --------------------------------------------------------------- contrast --
 
-def _tokens(block: str) -> dict:
-    return dict(re.findall(r"--([\w-]+):([^;]+);", block))
-
-
-def _rgb(value: str, under=(255, 255, 255)) -> tuple:
-    value = value.strip()
-    if value.startswith("#"):
-        h = value[1:]
-        if len(h) == 3:
-            h = "".join(c * 2 for c in h)
-        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
-    r, g, b, a = (float(x) for x in re.match(r"rgba\(([^)]+)\)", value).group(1).split(","))
-    return tuple(round(c * a + u * (1 - a)) for c, u in zip((r, g, b), under, strict=True))
-
-
-def _luminance(rgb) -> float:
-    def lin(c):
-        c /= 255
-        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
-    r, g, b = (lin(c) for c in rgb)
-    return 0.2126 * r + 0.7152 * g + 0.0722 * b
-
-
-def _contrast(fg, bg) -> float:
-    hi, lo = sorted((_luminance(fg), _luminance(bg)), reverse=True)
-    return (hi + 0.05) / (lo + 0.05)
-
-
 # Every text colour the report puts on a surface, by token.
 TEXT_PAIRS = [
     ("ink", "paper"), ("ink-2", "paper"), ("ink-3", "paper"), ("ink-2", "ground"), ("ink-3", "ground"),
@@ -114,14 +86,14 @@
 
 @pytest.mark.parametrize("theme", ["light", "dark"])
 def test_text_colours_clear_wcag_aa_in_both_themes(theme):
-    tokens = _tokens(html.LIGHT)
+    tokens = css_tokens(html.LIGHT)
     if theme == "dark":
-        tokens.update(_tokens(html.DARK))
-    paper = _rgb(tokens["paper"])
+        tokens.update(css_tokens(html.DARK))
+    paper = css_rgb(tokens["paper"])
     failures = []
     for fg, bg in TEXT_PAIRS:
-        background = _rgb(tokens[bg], under=paper)
-        ratio = _contrast(_rgb(tokens[fg], under=background), background)
+        background = css_rgb(tokens[bg], under=paper)
+        ratio = contrast(css_rgb(tokens[fg], under=background), background)
         if ratio < 4.5:
             failures.append("%s on %s: %.2f" % (fg, bg, ratio))
     assert not failures, failures
```

Create `tests/server/test_pages.py`:

```python
"""The pages, used the way a browser uses them (the CSRF token as a form
field): log in, submit, the analysis page and its report, settings, users,
tokens, hold and delete, and logging out."""

import secrets

from sqlalchemy import select

from phishhawk.server import appsettings, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import AuditRecord, Message
from phishhawk.server.security import REPORT_CSP

from conftest import sample


def _browser(client):
    """Send the CSRF token in forms only, as the pages do."""
    return client.headers.pop("X-CSRF-Token")


def _raw():
    with open(sample("sample_phish.eml"), "rb") as handle:
        return handle.read()


def _analysed(client, services):
    body = client.post("/api/v1/submissions", files={"file": ("m.eml", _raw())}, data={"offline": "true"}).json()
    worker.run_one(services)
    return client.get("/api/v1/submissions/%d" % body["id"]).json()["analysis_id"]


def test_pages_and_static_files_have_the_security_headers(anon):
    for path in ("/login", "/static/app.css"):
        headers = anon.get(path).headers
        assert "default-src 'none'" in headers["content-security-policy"], path
        assert "frame-ancestors 'none'" in headers["content-security-policy"], path
        assert headers["x-content-type-options"] == "nosniff" and headers["referrer-policy"] == "no-referrer"


def test_pages_redirect_to_login_and_the_login_form_works(anon):
    assert anon.get("/queue", follow_redirects=False).headers["location"] == "/login"
    response = anon.post("/login", data={"username": "alice", "password": "correct horse battery"},
                         follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/"
    page = anon.get("/").text
    assert page.count("<h1") == 1 and 'name="csrf_token"' in page and '<label for="file">' in page


def test_the_page_flow_from_submit_to_the_analysis_page(alice, services):
    csrf = _browser(alice)
    response = alice.post("/", data={"csrf_token": csrf, "raw": _raw().decode(), "offline": "true"},
                          files={"file": ("", b"", "application/octet-stream")}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/submissions/")
    assert "refresh" in alice.get(response.headers["location"]).text  # still queued
    worker.run_one(services)
    page = alice.get(response.headers["location"])  # redirected to the analysis page
    assert "LIKELY PHISHING" in page.text and "<iframe" in page.text and 'sandbox="allow-popups' in page.text


def test_the_report_opens_sandboxed_and_is_gone_after_deletion(alice, services):
    analysis_id = _analysed(alice, services)
    body = alice.get("/api/v1/analyses/%d" % analysis_id).json()
    report = "/analyses/%d/files/%s" % (analysis_id, next(f["name"] for f in body["files"] if f["kind"] == "html"))
    opened = alice.get(report)
    assert opened.status_code == 200 and opened.headers["content-security-policy"] == REPORT_CSP
    alice.delete("/api/v1/messages/%d" % body["message_id"])
    assert alice.get(report).status_code == 410


def test_the_settings_form_enables_providers_keeps_keys_masked_and_sets_limits(admin, services):
    csrf = _browser(admin)
    key = "vt-" + secrets.token_hex(8) + "1234"  # made at run time, for the secret scanner
    form = {"csrf_token": csrf, "provider_virustotal": "1", "key_virustotal": key,
            "protected_domains": "example-corp.co.uk\nexample.org", "retention_days": "7", "max_upload_mb": "10"}
    response = admin.post("/settings", data=form, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/settings?saved=1"
    page = admin.get("/settings").text
    assert "...1234" in page and key not in page
    with transaction(services.sessions) as s:
        assert appsettings.get_value(s, "providers") == ["virustotal"]
        assert appsettings.get_value(s, "protected_domains") == ["example-corp.co.uk", "example.org"]
        assert appsettings.limit(s, services.settings, "retention_days") == 7
        assert s.scalars(select(AuditRecord).where(AuditRecord.action == "settings")).one()


def test_an_admin_adds_a_user_and_a_token_that_is_shown_once_then_revoked(admin, anon):
    csrf = _browser(admin)
    form = {"csrf_token": csrf, "username": "carol", "password": "carol's long password", "role": "analyst"}
    assert admin.post("/users", data=form, follow_redirects=False).status_code == 303
    carol = next(u for u in admin.get("/api/v1/users").json() if u["username"] == "carol")
    page = admin.post("/tokens", data={"csrf_token": csrf, "name": "intelpulse", "scope": "read",
                                       "user_id": str(carol["id"])}).text
    token = page.split("phk_", 1)[1].split("<", 1)[0]
    bearer = {"Authorization": "Bearer phk_" + token}
    assert anon.get("/api/v1/analyses", headers=bearer).status_code == 200
    assert "phk_" + token not in admin.get("/users").text  # shown once
    token_id = admin.get("/api/v1/tokens").json()[0]["id"]
    assert admin.post("/tokens/%d/revoke" % token_id, data={"csrf_token": csrf},
                      follow_redirects=False).status_code == 303
    assert anon.get("/api/v1/analyses", headers=bearer).status_code == 401


def test_a_short_password_is_refused_with_the_reason(admin):
    csrf = _browser(admin)
    response = admin.post("/users", data={"csrf_token": csrf, "username": "dave", "password": "short",
                                          "role": "analyst"})
    assert response.status_code == 422 and "at least 12 characters" in response.text


def test_a_held_message_cannot_be_deleted_until_it_is_released(alice, admin, services):
    analysis_id = _analysed(alice, services)
    message_id = alice.get("/api/v1/analyses/%d" % analysis_id).json()["message_id"]
    admin_csrf, alice_csrf = _browser(admin), _browser(alice)
    assert admin.post("/messages/%d/hold" % message_id, data={"csrf_token": admin_csrf},
                      follow_redirects=False).status_code == 303
    refused = alice.post("/messages/%d/delete" % message_id, data={"csrf_token": alice_csrf})
    assert refused.status_code == 409 and "on hold" in refused.text
    assert admin.delete("/api/v1/messages/%d?scope=all" % message_id,
                        headers={"X-CSRF-Token": admin_csrf}).status_code == 409
    admin.post("/messages/%d/hold" % message_id, data={"csrf_token": admin_csrf, "hold": "false"})
    assert alice.post("/messages/%d/delete" % message_id, data={"csrf_token": alice_csrf},
                      follow_redirects=False).status_code == 303
    with transaction(services.sessions) as s:
        message = s.get(Message, message_id)
        assert message.raw_blob is None and message.deletion_reason == "manual"


def test_logging_out_ends_the_session(alice):
    csrf = _browser(alice)
    response = alice.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert alice.get("/", follow_redirects=False).headers["location"] == "/login"


def test_the_analysis_page_offers_only_what_the_viewer_may_do(alice, bob, admin, services):
    analysis_id = _analysed(alice, services)
    message_id = alice.get("/api/v1/analyses/%d" % analysis_id).json()["message_id"]
    page = "/analyses/%d" % analysis_id
    assert "Raw message" in alice.get(page).text and "Delete now" in alice.get(page).text
    assert "Raw message" not in bob.get(page).text and "Delete now" not in bob.get(page).text
    admin.post("/api/v1/messages/%d/hold" % message_id)
    assert "Delete now" not in alice.get(page).text
    held = admin.get(page).text
    assert "Release hold" in held and "Delete completely" not in held
```

Create `tests/server/test_hostile.py`:

```python
"""A message with a markup payload in every field a sender controls, sent
through the web app: no page may turn any of it into markup (spec 7.3)."""

from html.parser import HTMLParser

from phishhawk.server import worker

from conftest import build_eml

P = '"><svg onload=alert(1)>'
APP_TAGS = {"html", "head", "meta", "title", "link", "body", "a", "header", "nav", "form", "input", "span",
            "button", "main", "h1", "h2", "p", "div", "label", "textarea", "table", "caption", "thead", "tbody",
            "tr", "th", "td", "em", "strong", "section", "dl", "dt", "dd", "ul", "li", "details", "summary",
            "iframe", "footer", "script", "select", "option", "fieldset", "legend"}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = []

    def handle_starttag(self, tag, attrs):
        self.found.append((tag, dict(attrs)))


def _hostile_eml():
    return build_eml(subject=P, sender='"' + P + '" <ceo@evil-login.top>', to=P + " <victim@example-corp.co.uk>",
                     text="see https://evil-login.top/" + P,
                     html='<a href="javascript:alert(1)">' + P + '</a><script>alert(1)</script>',
                     headers=[("Reply-To", P + " <x@evil-login.top>"),
                              ("Message-ID", "<" + P + "@evil-login.top>")],
                     attachments=[(b"<html>" + P.encode(), "text", "html", P + ".html")])


def test_no_page_turns_attacker_text_into_markup(alice, services):
    response = alice.post("/api/v1/submissions", files={"file": ("m.eml", _hostile_eml(), "message/rfc822")},
                          data={"offline": "true"})
    worker.run_one(services)
    analysis = alice.get("/api/v1/submissions/%d" % response.json()["id"]).json()["analysis_id"]
    assert analysis, "the hostile message was not analysed"
    for path in ("/", "/queue", "/analyses/%d" % analysis, "/audit", "/queue?q=" + P):
        page = alice.get(path).text
        assert "<svg" not in page and "onload=alert" not in page.replace("onload=alert(1)&gt;", ""), path
        parser = _Tags()
        parser.feed(page)
        for tag, attrs in parser.found:
            assert tag in APP_TAGS, (path, tag)
            assert not [name for name in attrs if name.startswith("on")], (path, tag, attrs)
            if tag == "script":
                assert attrs == {"src": "/static/app.js"}, (path, attrs)
            for name in ("href", "src", "action"):
                if name in attrs:
                    assert attrs[name].startswith(("/", "#", "?")), (path, tag, attrs)
```

Create `tests/server/test_app_style.py`:

```python
"""The web app's colours clear WCAG AA (4.5:1) for every text colour on every
surface it is used on, in the light and the dark scheme."""

import re
from importlib.resources import files

import pytest

from conftest import contrast, css_rgb, css_tokens

CSS = (files("phishhawk.server") / "static" / "app.css").read_text(encoding="utf-8")

# Every text colour the app puts on a surface, by token.
TEXT_PAIRS = [
    ("ink", "bg"), ("ink", "paper"), ("ink-2", "bg"), ("ink-2", "paper"), ("ink-3", "bg"), ("ink-3", "paper"),
    ("link", "paper"), ("link", "bg"), ("bad", "paper"), ("ok", "paper"), ("on-brand", "brand"),
    ("top-ink", "top"), ("top-brand", "top"), ("top-muted", "top"),
]


def _scheme(dark):
    light = re.search(r":root\{([^}]*)\}", CSS).group(1)
    tokens = css_tokens(light + ";")
    if dark:
        tokens.update(css_tokens(re.search(r"prefers-color-scheme:dark\)\{:root\{([^}]*)\}", CSS).group(1) + ";"))
    return tokens


@pytest.mark.parametrize("dark", [False, True], ids=["light", "dark"])
def test_text_colours_clear_wcag_aa(dark):
    tokens = _scheme(dark)
    failures = ["%s on %s: %.2f" % (fg, bg, ratio) for fg, bg in TEXT_PAIRS
                if (ratio := contrast(css_rgb(tokens[fg]), css_rgb(tokens[bg]))) < 4.5]
    assert not failures, failures


def test_no_colour_is_written_outside_the_tokens():
    rules = re.sub(r":root\{[^}]*\}", "", CSS)
    assert not re.findall(r"#[0-9a-fA-F]{3,6}\b", rules)
```

Change `tests/server/test_rbac.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/test_rbac.py
+++ b/tests/server/test_rbac.py
@@ -24,6 +24,9 @@
     ("POST", "/api/v1/users", (401, 403, 201, 403, 403)),
     ("GET", "/api/v1/tokens", (401, 403, 200, 403, 403)),
     ("GET", "/api/v1/audit", (401, 200, 200, 200, 200)),
+    ("GET", "/settings", (303, 403, 200, 403, 403)),
+    ("GET", "/users", (303, 403, 200, 403, 403)),
+    ("GET", "/queue", (303, 200, 200, 200, 200)),
 ]
 BODIES = {("PATCH", "/api/v1/settings"): {"retention_days": 20},
           ("POST", "/api/v1/users"): {"username": "carol", "password": "another long password", "role": "analyst"}}
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_pages.py tests/server/test_hostile.py tests/server/test_app_style.py tests/server/test_rbac.py
```

Expected: FAIL. The first error is `FileNotFoundError: [Errno 2] No such file or directory: 'src/phishhawk/server/static/app.css'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/routes/pages.py`:

```python
"""HTML pages. Every form works without JavaScript and carries the CSRF
token; the pages call the same helpers as the JSON API."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from .. import appsettings, auth, intake, views
from ..app import html_response
from ..deps import COOKIE, DB, Admin, CurrentActor, optional_actor, services
from ..models import Analysis, ApiToken, AuditRecord, Submission, User
from . import api

router = APIRouter()
MB = 1024 * 1024
VERDICTS = ("NO STRONG INDICATORS", "SUSPICIOUS", "LIKELY PHISHING", "MALICIOUS")


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


@router.get("/login")
def login_page(request: Request, db: DB) -> Response:
    if optional_actor(request, db) is not None:
        return _see_other("/")
    return html_response(request, "login.html", {"actor": None, "error": ""})


@router.post("/login")
def login(request: Request, db: DB, username: Annotated[str, Form()],
          password: Annotated[str, Form()]) -> Response:
    outcome = api.login_response(request, db, username, password)
    if not isinstance(outcome, tuple):
        detail = ("Wrong username or password." if outcome.status_code == 401
                  else "Too many attempts: wait a little.")
        return html_response(request, "login.html", {"actor": None, "error": detail}, outcome.status_code)
    response = _see_other("/")
    api.set_cookie(request, response, outcome[0])
    return response


@router.post("/logout")
def logout(request: Request, db: DB, actor: CurrentActor) -> Response:
    api.delete_session(request, db, actor)
    response = _see_other("/login")
    response.delete_cookie(COOKIE, path="/")
    return response


@router.get("/")
def home(request: Request, db: DB, actor: CurrentActor) -> Response:
    recent = views.listing(db, services(request).store)[:10]
    return html_response(request, "home.html", {"actor": actor, "recent": recent, "error": ""})


@router.post("/")
async def submit(request: Request, db: DB, actor: CurrentActor,
                 file: Annotated[UploadFile | None, File()] = None, raw: Annotated[str, Form()] = "",
                 offline: Annotated[bool, Form()] = False) -> Response:
    s = services(request)
    limit = appsettings.limit(db, s.settings, "max_upload_mb") * MB
    data = await file.read(limit + 1) if file is not None and file.filename else raw.encode()
    try:
        submission = intake.accept(db, s.store, data, source="upload" if file and file.filename else "paste",
                                   user_id=actor.user_id, actor=actor.label, offline=offline, max_bytes=limit)
    except intake.IntakeError as exc:
        recent = views.listing(db, s.store)[:10]
        return html_response(request, "home.html", {"actor": actor, "recent": recent, "error": str(exc)},
                             exc.status)
    return _see_other("/submissions/%d" % submission.id)


@router.get("/submissions/{submission_id}")
def submission_page(request: Request, db: DB, actor: CurrentActor, submission_id: int) -> Response:
    submission = db.get(Submission, submission_id)
    if submission is None:
        raise HTTPException(404, "no such submission")
    view = api.submission_view(db, submission)
    if view["analysis_id"]:
        return _see_other("/analyses/%d" % view["analysis_id"])
    return html_response(request, "submission.html", {"actor": actor, "submission": view})


@router.get("/queue")
def queue(request: Request, db: DB, actor: CurrentActor, q: str = "", verdict: str = "",
          offset: Annotated[int, Query(ge=0)] = 0) -> Response:
    rows = views.listing(db, services(request).store, q, verdict, offset)
    return html_response(request, "queue.html", {"actor": actor, "rows": rows, "q": q, "verdict": verdict,
                                                 "verdicts": VERDICTS, "offset": offset, "page": views.PAGE})


@router.get("/analyses/{analysis_id}")
def analysis_page(request: Request, db: DB, actor: CurrentActor, analysis_id: int) -> Response:
    found = views.find(db, analysis_id)
    if found is None:
        raise HTTPException(404, "no such analysis")
    analysis, message, submission = found
    view = views.summary(services(request).store, analysis, message, submission)
    report = next((f for f in view["files"] if f["kind"] == "html"), None)
    can_delete = actor.is_admin or views.is_owner(db, message.id, actor.user_id)
    submitter = views.usernames(db).get(submission.user_id or 0, "")
    return html_response(request, "analysis.html", {"actor": actor, "a": view, "report": report,
                                                    "can_delete": can_delete, "submitter": submitter})


@router.get("/analyses/{analysis_id}/files/{name}")
def analysis_file(request: Request, db: DB, actor: CurrentActor, analysis_id: int, name: str,
                  download: bool = False) -> Response:
    return api.get_file(request, db, actor, analysis_id, name, download)


@router.post("/analyses/{analysis_id}/reanalyze")
def reanalyze(db: DB, actor: CurrentActor, analysis_id: int) -> Response:
    return _see_other("/submissions/%d" % api.reanalyze(db, actor, analysis_id)["id"])


@router.post("/messages/{message_id}/delete")
def delete(request: Request, db: DB, actor: CurrentActor, message_id: int,
           scope: Annotated[str, Form(pattern="^(tier1|all)$")] = "tier1") -> Response:
    analysis_id = db.scalars(select(Analysis.id).where(Analysis.message_id == message_id)
                             .order_by(Analysis.id.desc())).first()
    api.delete_message(request, db, actor, message_id, scope)
    return _see_other("/queue" if scope == "all" or analysis_id is None else "/analyses/%d" % analysis_id)


@router.post("/messages/{message_id}/hold")
def hold(db: DB, actor: Admin, message_id: int, hold: Annotated[bool, Form()] = True) -> Response:
    (api.hold if hold else api.release)(db, actor, message_id)
    analysis_id = db.scalars(select(Analysis.id).where(Analysis.message_id == message_id)
                             .order_by(Analysis.id.desc())).first()
    return _see_other("/analyses/%d" % analysis_id if analysis_id else "/queue")


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.replace(",", "\n").splitlines() if line.strip()]


@router.get("/settings")
def settings_page(request: Request, db: DB, actor: Admin, saved: bool = False) -> Response:
    s = services(request)
    view = appsettings.public_view(db, s.box, s.settings)
    return html_response(request, "settings.html", {"actor": actor, "s": view, "saved": saved, "error": "",
                                                    "providers": appsettings.PROVIDERS_ALL})


@router.post("/settings")
async def save_settings(request: Request, db: DB, actor: Admin) -> Response:
    form = await request.form()
    fields: dict[str, Any] = {name: _lines(str(form.get(name, ""))) for name in appsettings.LISTS}
    fields["providers"] = [p for p in appsettings.PROVIDERS_ALL if form.get("provider_" + p)]
    fields.update({name: int(str(form.get(name))) for name in appsettings.LIMITS
                   if str(form.get(name, "")).isdigit()})
    fields["keys"] = {p: str(form.get("key_" + p, "")) for p in appsettings.KEYED
                      if form.get("key_" + p) or form.get("remove_" + p)}
    body = api.SettingsPatch.model_validate(fields)
    try:
        api.patch_settings(request, db, actor, body)
    except HTTPException as exc:
        s = services(request)
        return html_response(request, "settings.html", {"actor": actor, "providers": appsettings.PROVIDERS_ALL,
                                                        "s": appsettings.public_view(db, s.box, s.settings),
                                                        "saved": False, "error": exc.detail}, exc.status_code)
    return _see_other("/settings?saved=1")


def _users_page(request: Request, db: DB, actor: Any, new_token: str = "", error: str = "",
                status: int = 200) -> Response:
    users = db.scalars(select(User).order_by(User.username)).all()
    tokens = db.scalars(select(ApiToken).order_by(ApiToken.id)).all()
    return html_response(request, "users.html", {"actor": actor, "users": users, "tokens": tokens,
                                                 "names": views.usernames(db), "new_token": new_token,
                                                 "error": error, "roles": auth.ROLES,
                                                 "scopes": auth.TOKEN_SCOPES}, status)


@router.get("/users")
def users_page(request: Request, db: DB, actor: Admin) -> Response:
    return _users_page(request, db, actor)


@router.post("/users")
def add_user(request: Request, db: DB, actor: Admin, username: Annotated[str, Form()],
             password: Annotated[str, Form()], role: Annotated[str, Form()]) -> Response:
    try:
        api.create_user(db, actor, api.NewUser(username=username, password=password, role=role))
    except HTTPException as exc:
        return _users_page(request, db, actor, error=str(exc.detail), status=exc.status_code)
    return _see_other("/users")


@router.post("/users/{user_id}")
def change_user(request: Request, db: DB, actor: Admin, user_id: int, role: Annotated[str, Form()] = "",
                disabled: Annotated[bool, Form()] = False, password: Annotated[str, Form()] = "") -> Response:
    try:
        api.patch_user(db, actor, user_id, api.UserPatch(role=role or None, disabled=disabled,
                                                         password=password or None))
    except HTTPException as exc:
        return _users_page(request, db, actor, error=str(exc.detail), status=exc.status_code)
    return _see_other("/users")


@router.post("/tokens")
def add_token(request: Request, db: DB, actor: Admin, name: Annotated[str, Form()],
              scope: Annotated[str, Form()], user_id: Annotated[int, Form()]) -> Response:
    try:
        token = api.create_token(db, actor, api.NewToken(name=name, scope=scope, user_id=user_id))["token"]
    except HTTPException as exc:
        return _users_page(request, db, actor, error=str(exc.detail), status=exc.status_code)
    return _users_page(request, db, actor, new_token=token)


@router.post("/tokens/{token_id}/revoke")
def revoke(db: DB, actor: Admin, token_id: int) -> Response:
    api.revoke_token(db, actor, token_id)
    return _see_other("/users")


@router.get("/audit")
def audit_page(request: Request, db: DB, actor: CurrentActor, offset: Annotated[int, Query(ge=0)] = 0) -> Response:
    query = select(AuditRecord).order_by(AuditRecord.id.desc())
    if not actor.is_admin:
        query = query.where(AuditRecord.actor == actor.label)
    rows = db.scalars(query.offset(offset).limit(100)).all()
    return html_response(request, "audit.html", {"actor": actor, "rows": rows, "offset": offset})
```

Create `src/phishhawk/server/templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{% block title %}PhishHawk{% endblock %}</title>
<link rel="stylesheet" href="/static/app.css">
{% block head %}{% endblock %}
</head>
<body>
<a class="skip" href="#main">Skip to the content</a>
<header class="top">
  <a class="brand" href="/">PhishHawk</a>
  {% if actor %}
  <nav aria-label="Main">
    <a href="/">Submit</a>
    <a href="/queue">Queue</a>
    <a href="/audit">Audit</a>
    {% if actor.is_admin %}<a href="/settings">Settings</a><a href="/users">Users</a>{% endif %}
  </nav>
  <form class="logout" method="post" action="/logout">
    <input type="hidden" name="csrf_token" value="{{ actor.csrf }}">
    <span class="who">{{ actor.username }} ({{ actor.role }})</span>
    <button type="submit">Log out</button>
  </form>
  {% endif %}
</header>
<main id="main">
{% block main %}{% endblock %}
</main>
<footer class="foot">PhishHawk is read-only: it never deletes, moves or quarantines mail.</footer>
<script src="/static/app.js"></script>
</body>
</html>
```

Create `src/phishhawk/server/templates/error.html`:

```html
{% extends "base.html" %}
{% block title %}Error {{ status }} · PhishHawk{% endblock %}
{% block main %}
<h1>Something went wrong ({{ status }})</h1>
<p>{{ detail }}</p>
<p><a href="/">Back to Submit</a></p>
{% endblock %}
```

Create `src/phishhawk/server/templates/login.html`:

```html
{% extends "base.html" %}
{% block title %}Log in · PhishHawk{% endblock %}
{% block main %}
<h1>Log in</h1>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post" action="/login" class="card narrow">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Log in</button>
</form>
{% endblock %}
```

Create `src/phishhawk/server/templates/_verdict.html`:

```html
<span class="verdict v-{{ verdict|lower|replace(' ', '-') }}">{{ verdict }}</span>
```

Create `src/phishhawk/server/templates/_table.html`:

```html
{% set items = recent if recent is defined else rows %}
{% if items %}
<table class="list">
  <caption class="sr-only">Analyses, newest first</caption>
  <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Subject</th><th scope="col">Sender domain</th><th scope="col">Verdict</th><th scope="col">Score</th><th scope="col">Source</th></tr></thead>
  <tbody>
  {% for a in items %}
  <tr>
    <td data-label="Time">{{ a.created_at[:16]|replace('T', ' ') }}</td>
    <td data-label="Subject"><a href="/analyses/{{ a.id }}">{% if a.subject is not none %}{{ (a.subject|printable)[:90] or '(no subject)' }}{% else %}<em>deleted after retention</em>{% endif %}</a></td>
    <td data-label="Sender domain">{{ a.sender_domain|printable }}</td>
    <td data-label="Verdict">{% with verdict=a.verdict %}{% include "_verdict.html" %}{% endwith %}</td>
    <td data-label="Score">{{ a.score }}</td>
    <td data-label="Source">{{ a.source }}{% if a.offline %} · offline{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>Nothing here yet.</p>
{% endif %}
```

Create `src/phishhawk/server/templates/home.html`:

```html
{% extends "base.html" %}
{% block title %}Submit · PhishHawk{% endblock %}
{% block main %}
<h1>Submit a reported email</h1>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post" action="/" enctype="multipart/form-data" class="card">
  <input type="hidden" name="csrf_token" value="{{ actor.csrf }}">
  <div class="drop" data-drop>
    <label for="file">An .eml or .msg file</label>
    <input id="file" name="file" type="file" accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook">
  </div>
  <label for="raw">Or paste the raw message (headers and body)</label>
  <textarea id="raw" name="raw" rows="8" spellcheck="false"></textarea>
  <label class="check"><input type="checkbox" name="offline" value="true"> Offline: no reputation lookups for this message</label>
  <button type="submit">Analyse</button>
</form>
<h2>Recent</h2>
{% include "_table.html" %}
{% endblock %}
```

Create `src/phishhawk/server/templates/submission.html`:

```html
{% extends "base.html" %}
{% block title %}Analysing · PhishHawk{% endblock %}
{% block head %}{% if submission.status in ('queued', 'running') %}<meta http-equiv="refresh" content="2">{% endif %}{% endblock %}
{% block main %}
<h1>Submission {{ submission.id }}</h1>
{% if submission.status in ('queued', 'running') %}
<p role="status">Status: <strong>{{ submission.status }}</strong>. This page refreshes until the verdict is ready.</p>
{% else %}
<p class="error" role="alert">The analysis failed: {{ submission.error }}</p>
{% endif %}
{% endblock %}
```

Create `src/phishhawk/server/templates/queue.html`:

```html
{% extends "base.html" %}
{% block title %}Queue · PhishHawk{% endblock %}
{% block main %}
<h1>Queue</h1>
<form method="get" action="/queue" class="filters">
  <label for="q">Search SHA-256, report ID or indicator</label>
  <input id="q" name="q" value="{{ q }}">
  <label for="verdict">Verdict</label>
  <select id="verdict" name="verdict">
    <option value="">Any</option>
    {% for v in verdicts %}<option value="{{ v }}"{% if v == verdict %} selected{% endif %}>{{ v }}</option>{% endfor %}
  </select>
  <button type="submit">Filter</button>
</form>
{% include "_table.html" %}
<nav class="pager" aria-label="Pages">
  {% if offset > 0 %}<a href="/queue?q={{ q|urlencode }}&amp;verdict={{ verdict|urlencode }}&amp;offset={{ [offset - page, 0]|max }}">Newer</a>{% endif %}
  {% if rows|length == page %}<a href="/queue?q={{ q|urlencode }}&amp;verdict={{ verdict|urlencode }}&amp;offset={{ offset + page }}">Older</a>{% endif %}
</nav>
{% endblock %}
```

Create `src/phishhawk/server/templates/analysis.html`:

```html
{% extends "base.html" %}
{% block title %}{{ a.report_id }} · PhishHawk{% endblock %}
{% block main %}
<section class="card bar" aria-label="Summary">
  <h1>{% with verdict=a.verdict %}{% include "_verdict.html" %}{% endwith %} <span class="score">score {{ a.score }}</span></h1>
  <dl>
    <dt>Report ID</dt><dd class="mono">{{ a.report_id }}</dd>
    <dt>SHA-256</dt><dd class="mono">{{ a.sha256 }}</dd>
    <dt>Submitted</dt><dd>{{ a.created_at[:16]|replace('T', ' ') }} UTC by {{ submitter or 'system' }} ({{ a.source }})</dd>
    <dt>Lookups</dt><dd>{% if a.offline %}none: submitted offline{% elif a.providers %}{{ a.providers|join(', ') }}{% else %}none: no provider is enabled{% endif %}</dd>
    {% if a.hold %}<dt>Hold</dt><dd>on hold: kept past the retention period</dd>{% endif %}
  </dl>
  {% if a.tier1_deleted_at %}
  <p>The message and its reports were deleted on {{ a.tier1_deleted_at[:10] }}. The verdict, indicators and audit trail remain.</p>
  {% else %}
  <ul class="downloads" aria-label="Downloads">
    {% for f in a.files %}<li><a href="/analyses/{{ a.id }}/files/{{ f.name }}?download=1">{{ f.type }}</a> <span class="mono hash">{{ f.sha256[:16] }}…</span></li>{% endfor %}
    {% if can_delete %}<li><a href="/api/v1/messages/{{ a.message_id }}/raw">Raw message</a></li>{% endif %}
  </ul>
  {% endif %}
  {% if a.lookups %}
  <details><summary>Outbound lookups ({{ a.lookups|length }})</summary>
    <ul>{% for l in a.lookups %}<li><span class="mono">{{ l.provider }} {{ l.method }} {{ l.url|printable }}</span></li>{% endfor %}</ul>
  </details>
  {% endif %}
  <div class="actions">
    {% if not a.tier1_deleted_at %}
    <form method="post" action="/analyses/{{ a.id }}/reanalyze"><input type="hidden" name="csrf_token" value="{{ actor.csrf }}"><button type="submit">Re-analyze</button></form>
    {% endif %}
    {% if can_delete and not a.tier1_deleted_at and not a.hold %}
    <form method="post" action="/messages/{{ a.message_id }}/delete"><input type="hidden" name="csrf_token" value="{{ actor.csrf }}"><input type="hidden" name="scope" value="tier1"><button type="submit" class="danger">Delete now</button></form>
    {% endif %}
    {% if actor.is_admin %}
    <form method="post" action="/messages/{{ a.message_id }}/hold"><input type="hidden" name="csrf_token" value="{{ actor.csrf }}"><input type="hidden" name="hold" value="{{ 'false' if a.hold else 'true' }}"><button type="submit">{{ 'Release hold' if a.hold else 'Hold' }}</button></form>
    {% if not a.hold %}<form method="post" action="/messages/{{ a.message_id }}/delete"><input type="hidden" name="csrf_token" value="{{ actor.csrf }}"><input type="hidden" name="scope" value="all"><button type="submit" class="danger">Delete completely</button></form>{% endif %}
    {% endif %}
  </div>
</section>
{% if report and report.available %}
<p><a href="/analyses/{{ a.id }}/files/{{ report.name }}" target="_blank" rel="noopener">Open full report</a> (for printing)</p>
<iframe class="report" title="HTML report" src="/analyses/{{ a.id }}/files/{{ report.name }}" sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"></iframe>
{% endif %}
{% endblock %}
```

Create `src/phishhawk/server/templates/settings.html`:

```html
{% extends "base.html" %}
{% block title %}Settings · PhishHawk{% endblock %}
{% block main %}
<h1>Settings</h1>
{% if saved %}<p class="ok" role="status">Saved.</p>{% endif %}
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form method="post" action="/settings" class="card">
  <input type="hidden" name="csrf_token" value="{{ actor.csrf }}">
  <fieldset><legend>Reputation lookups (all off on a fresh install)</legend>
  {% for p in providers %}
    <label class="check"><input type="checkbox" name="provider_{{ p }}" value="1"{% if p in s.providers %} checked{% endif %}> {{ p }}</label>
    {% if p in s['keys'] %}
    <label for="key_{{ p }}">{{ p }} API key {% if s['keys'][p] %}(set, {{ s['keys'][p] }}){% else %}(not set){% endif %}</label>
    <input id="key_{{ p }}" name="key_{{ p }}" type="password" autocomplete="off" placeholder="leave blank to keep">
    {% if s['keys'][p] %}<label class="check"><input type="checkbox" name="remove_{{ p }}" value="1"> remove the {{ p }} key</label>{% endif %}
    {% endif %}
  {% endfor %}
  </fieldset>
  <fieldset><legend>Domains (one per line)</legend>
    <label for="protected_domains">Your own domains (lookalikes of these are flagged)</label>
    <textarea id="protected_domains" name="protected_domains" rows="3">{{ s.protected_domains|join('\n') }}</textarea>
    <label for="allow_domains">Partners, never reported as lookalikes or indicators</label>
    <textarea id="allow_domains" name="allow_domains" rows="3">{{ s.allow_domains|join('\n') }}</textarea>
    <label for="block_domains">Always flagged</label>
    <textarea id="block_domains" name="block_domains" rows="3">{{ s.block_domains|join('\n') }}</textarea>
    <label for="trusted_authserv">Your mail servers' authserv-id (trusted Authentication-Results)</label>
    <textarea id="trusted_authserv" name="trusted_authserv" rows="2">{{ s.trusted_authserv|join('\n') }}</textarea>
  </fieldset>
  <fieldset><legend>Limits</legend>
    <label for="retention_days">Delete messages and reports after (days)</label>
    <input id="retention_days" name="retention_days" type="number" min="1" value="{{ s.retention_days }}">
    <label for="max_upload_mb">Largest upload (MB)</label>
    <input id="max_upload_mb" name="max_upload_mb" type="number" min="1" value="{{ s.max_upload_mb }}">
  </fieldset>
  <button type="submit">Save</button>
</form>
{% endblock %}
```

Create `src/phishhawk/server/templates/users.html`:

```html
{% extends "base.html" %}
{% block title %}Users · PhishHawk{% endblock %}
{% block main %}
<h1>Users and API tokens</h1>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
{% if new_token %}<div class="card ok" role="status"><p>New API token, shown once: store it now.</p><p class="mono">{{ new_token }}</p></div>{% endif %}
<table class="list">
  <caption class="sr-only">Users</caption>
  <thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Change</th></tr></thead>
  <tbody>
  {% for u in users %}
  <tr>
    <td data-label="User">{{ u.username }}</td><td data-label="Role">{{ u.role }}</td>
    <td data-label="Status">{{ 'disabled' if u.disabled else 'active' }}</td>
    <td data-label="Change">
      <form method="post" action="/users/{{ u.id }}" class="inline">
        <input type="hidden" name="csrf_token" value="{{ actor.csrf }}">
        <label for="role-{{ u.id }}" class="sr-only">Role</label>
        <select id="role-{{ u.id }}" name="role">{% for r in roles %}<option value="{{ r }}"{% if r == u.role %} selected{% endif %}>{{ r }}</option>{% endfor %}</select>
        <label class="check"><input type="checkbox" name="disabled" value="true"{% if u.disabled %} checked{% endif %}> disabled</label>
        <label for="pw-{{ u.id }}" class="sr-only">New password</label>
        <input id="pw-{{ u.id }}" name="password" type="password" autocomplete="new-password" placeholder="new password (optional)">
        <button type="submit">Save</button>
      </form>
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>
<h2>Add a user</h2>
<form method="post" action="/users" class="card">
  <input type="hidden" name="csrf_token" value="{{ actor.csrf }}">
  <label for="nu">Username</label><input id="nu" name="username" required>
  <label for="np">Password (12 characters or more)</label><input id="np" name="password" type="password" autocomplete="new-password" required>
  <label for="nr">Role</label><select id="nr" name="role">{% for r in roles %}<option value="{{ r }}">{{ r }}</option>{% endfor %}</select>
  <button type="submit">Add</button>
</form>
<h2>API tokens</h2>
<table class="list">
  <caption class="sr-only">API tokens</caption>
  <thead><tr><th scope="col">Name</th><th scope="col">User</th><th scope="col">Scope</th><th scope="col">Status</th></tr></thead>
  <tbody>
  {% for t in tokens %}
  <tr><td data-label="Name">{{ t.name }}</td><td data-label="User">{{ names.get(t.user_id, '') }}</td><td data-label="Scope">{{ t.scope }}</td>
    <td data-label="Status">{% if t.revoked_at %}revoked{% else %}<form method="post" action="/tokens/{{ t.id }}/revoke" class="inline"><input type="hidden" name="csrf_token" value="{{ actor.csrf }}"><button type="submit" class="danger">Revoke</button></form>{% endif %}</td></tr>
  {% endfor %}
  </tbody>
</table>
<form method="post" action="/tokens" class="card">
  <input type="hidden" name="csrf_token" value="{{ actor.csrf }}">
  <label for="tn">Token name</label><input id="tn" name="name" required>
  <label for="tu">For user</label><select id="tu" name="user_id">{% for u in users %}<option value="{{ u.id }}">{{ u.username }}</option>{% endfor %}</select>
  <label for="ts">Scope</label><select id="ts" name="scope">{% for sc in scopes %}<option value="{{ sc }}">{{ sc }}</option>{% endfor %}</select>
  <button type="submit">Create token</button>
</form>
{% endblock %}
```

Create `src/phishhawk/server/templates/audit.html`:

```html
{% extends "base.html" %}
{% block title %}Audit · PhishHawk{% endblock %}
{% block main %}
<h1>Audit log{% if not actor.is_admin %}: your actions{% endif %}</h1>
<table class="list">
  <caption class="sr-only">Audit records, newest first</caption>
  <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Who</th><th scope="col">Action</th><th scope="col">Object</th><th scope="col">Details</th></tr></thead>
  <tbody>
  {% for r in rows %}
  <tr><td data-label="Time">{{ r.at.isoformat()[:19]|replace('T', ' ') }}</td><td data-label="Who">{{ r.actor|printable }}</td><td data-label="Action">{{ r.action }}</td>
    <td data-label="Object">{{ r.object_type }} {{ r.object_id }}</td><td data-label="Details" class="mono">{{ r.details|tojson|printable }}</td></tr>
  {% endfor %}
  </tbody>
</table>
<nav class="pager" aria-label="Pages">{% if rows|length == 100 %}<a href="/audit?offset={{ offset + 100 }}">Older</a>{% endif %}</nav>
{% endblock %}
```

Create `src/phishhawk/server/static/app.css`:

```css
:root{--bg:#f6f7fb;--paper:#fff;--ink:#141a2a;--ink-2:#3c4458;--ink-3:#5b6478;--line:#d9dee8;--brand:#c2410c;--on-brand:#fff;--link:#9a3412;--ok:#166534;--bad:#b91c1c;--focus:#c2410c;--top:#0f172a;--top-ink:#fff;--top-brand:#fdba74;--top-muted:#cbd5e1;--top-line:#475569;--report-bg:#fff;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--paper:#131b2e;--ink:#eef2f8;--ink-2:#c7cfdc;--ink-3:#9aa4b5;--line:#2a3550;--brand:#fb923c;--on-brand:#0b1220;--link:#fdba74;--ok:#4ade80;--bad:#f87171;--focus:#fb923c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);line-height:1.5}
a{color:var(--link)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.skip{position:absolute;left:-999px}.skip:focus{left:8px;top:8px;background:var(--paper);padding:8px;z-index:10}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.top{display:flex;flex-wrap:wrap;align-items:center;gap:16px;padding:12px 20px;background:var(--top);color:var(--top-ink)}
.top a{color:var(--top-ink);text-decoration:none}.top .brand{font-weight:700;color:var(--top-brand)}
.top nav{display:flex;gap:14px;flex-wrap:wrap}.top nav a{padding:6px 0}
.logout{margin-left:auto;display:flex;gap:10px;align-items:center}.who{font-size:14px;color:var(--top-muted)}
main{max-width:1180px;margin:0 auto;padding:20px 16px 40px}
h1{font-size:26px;margin:8px 0 16px}h2{font-size:20px;margin:28px 0 10px}
.card{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:18px;margin:0 0 18px}
.narrow{max-width:420px}
label{display:block;margin:12px 0 4px;font-weight:600;color:var(--ink-2)}
label.check{font-weight:400;display:flex;gap:8px;align-items:center}
input,select,textarea{font:inherit;width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--paper);color:var(--ink);min-height:40px}
input[type=checkbox]{width:auto;min-height:auto}
textarea{font-family:ui-monospace,Menlo,monospace;font-size:13px}
button{font:inherit;font-weight:600;margin-top:14px;min-height:40px;padding:8px 16px;border-radius:8px;border:1px solid var(--brand);background:var(--brand);color:var(--on-brand);cursor:pointer}
button.danger{background:transparent;color:var(--bad);border-color:var(--bad)}
.logout button{margin:0;background:transparent;border-color:var(--top-line);color:var(--top-ink)}
.drop{border:2px dashed var(--line);border-radius:12px;padding:16px}.drop.over{border-color:var(--brand)}
.error{color:var(--bad);font-weight:600}.ok{color:var(--ok)}
table.list{width:100%;border-collapse:collapse;background:var(--paper);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.list th,.list td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.list th{font-size:13px;color:var(--ink-3);text-transform:uppercase;letter-spacing:.04em}
.verdict{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:700;font-size:13px;border:1px solid currentColor}
.v-malicious,.v-likely-phishing{color:var(--bad)}.v-suspicious{color:var(--link)}.v-no-strong-indicators{color:var(--ok)}
.bar h1 .verdict{font-size:20px}.score{font-size:18px;color:var(--ink-3);margin-left:8px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:12px 0}dt{color:var(--ink-3)}dd{margin:0;overflow-wrap:anywhere}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px;overflow-wrap:anywhere}
.downloads{display:flex;flex-wrap:wrap;gap:8px 20px;padding:0;list-style:none}
.actions{display:flex;flex-wrap:wrap;gap:10px}.actions form{margin:0}
.filters{display:grid;grid-template-columns:2fr 1fr auto;gap:0 12px;align-items:end;margin-bottom:16px}
form.inline{display:flex;flex-wrap:wrap;gap:8px;align-items:center}form.inline button{margin:0}
.pager{display:flex;gap:16px;margin-top:12px}
iframe.report{width:100%;height:80vh;border:1px solid var(--line);border-radius:12px;background:var(--report-bg)}
.foot{text-align:center;color:var(--ink-3);font-size:13px;padding:20px}
@media (max-width:720px){
  .filters{grid-template-columns:1fr}
  .list thead{display:none}.list tr{display:block;border-bottom:1px solid var(--line);padding:8px 0}
  .list td{display:block;border:0;padding:4px 12px}.list td::before{content:attr(data-label) ": ";font-weight:600;color:var(--ink-3)}
  dl{grid-template-columns:1fr}.logout{margin-left:0}
}
```

Create `src/phishhawk/server/static/app.js`:

```javascript
// Drag and drop onto the file field; the form works without this script.
document.querySelectorAll("[data-drop]").forEach(function (zone) {
  var input = zone.querySelector("input[type=file]");
  ["dragenter", "dragover"].forEach(function (name) {
    zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (name) {
    zone.addEventListener(name, function () { zone.classList.remove("over"); });
  });
  zone.addEventListener("drop", function (event) {
    event.preventDefault();
    if (event.dataTransfer && event.dataTransfer.files.length) { input.files = event.dataTransfer.files; }
  });
});
```

Change `src/phishhawk/server/app.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/app.py
+++ b/src/phishhawk/server/app.py
@@ -1,16 +1,20 @@
-"""The web application: services, security headers, errors, routes."""
+"""The web application: services, security headers, error pages, routes."""
 
 from __future__ import annotations
 
 import shutil
+from importlib.resources import files
 from typing import Any
 
 from fastapi import FastAPI, HTTPException, Request
 from fastapi.exceptions import RequestValidationError
-from fastapi.responses import JSONResponse, Response
+from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
+from fastapi.staticfiles import StaticFiles
+from fastapi.templating import Jinja2Templates
 from sqlalchemy import func, select, text
 
 from .. import __version__
+from ..report.common import printable
 from .auth import LoginThrottle
 from .config import ServerSettings, load_settings
 from .crypto import Box
@@ -34,6 +38,9 @@
     app = FastAPI(title="PhishHawk", version=__version__, docs_url=None, redoc_url=None)
     app.state.services = services
     app.state.throttle = LoginThrottle()
+    templates = Jinja2Templates(directory=str(files("phishhawk.server") / "templates"))
+    templates.env.filters["printable"] = lambda value: printable(str(value)) if value is not None else ""
+    app.state.templates = templates
 
     @app.middleware("http")
     async def security_headers(request: Request, call_next: Any) -> Response:
@@ -49,8 +56,13 @@
 
     @app.exception_handler(HTTPException)
     async def http_error(request: Request, exc: HTTPException) -> Response:
-        body = {"error": _code(exc.status_code), "detail": exc.detail}
-        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)
+        if request.url.path.startswith("/api/"):
+            body = {"error": _code(exc.status_code), "detail": exc.detail}
+            return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)
+        if exc.status_code == 401:
+            return RedirectResponse("/login", status_code=303)
+        context = {"status": exc.status_code, "detail": exc.detail, "actor": None}
+        return templates.TemplateResponse(request, "error.html", context, status_code=exc.status_code)
 
     @app.exception_handler(RequestValidationError)
     async def invalid(request: Request, exc: RequestValidationError) -> Response:
@@ -66,9 +78,11 @@
         return {"status": "ok", "version": __version__, "queue": queued,
                 "last_heartbeat": beat.isoformat() if beat else None, "disk_free_mb": disk.free // (1024 * 1024)}
 
-    from .routes import api
+    from .routes import api, pages
 
     app.include_router(api.router)
+    app.include_router(pages.router)
+    app.mount("/static", StaticFiles(directory=str(files("phishhawk.server") / "static")), name="static")
     return app
 
 
@@ -78,3 +92,8 @@
 
 def _code(status: int) -> str:
     return ERROR_CODES.get(status, "error")
+
+
+def html_response(request: Request, template: str, context: dict[str, Any], status: int = 200) -> HTMLResponse:
+    templates: Jinja2Templates = request.app.state.templates
+    return templates.TemplateResponse(request, template, context, status_code=status)
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_pages.py tests/server/test_hostile.py tests/server/test_app_style.py tests/server/test_rbac.py
```
Expected: 31 passed.

```bash
python -m pytest tests/test_report_a11y.py
```
Expected: 9 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/app.py src/phishhawk/server/routes/pages.py src/phishhawk/server/static/app.css src/phishhawk/server/static/app.js src/phishhawk/server/templates/_table.html src/phishhawk/server/templates/_verdict.html src/phishhawk/server/templates/analysis.html src/phishhawk/server/templates/audit.html src/phishhawk/server/templates/base.html src/phishhawk/server/templates/error.html src/phishhawk/server/templates/home.html src/phishhawk/server/templates/login.html src/phishhawk/server/templates/queue.html src/phishhawk/server/templates/settings.html src/phishhawk/server/templates/submission.html src/phishhawk/server/templates/users.html tests/conftest.py tests/server/test_app_style.py tests/server/test_hostile.py tests/server/test_pages.py tests/server/test_rbac.py tests/test_report_a11y.py
git commit -m "Add the web app's pages, with the hostile-payload and contrast tests"
```

### Task 13: Your own frontend at /app/, and who is logged in

*PR 6.*

The owner builds the main frontend in Google AI Studio and serves it from this server, so it shares the API's origin: no CORS, the session cookie stays `SameSite=Strict`, and the app's CSP covers it. When `PHISHHAWK_FRONTEND_DIR` names a build folder, it is served at `/app/`, with `index.html` for the frontend's own routes. `GET /api/v1/session` tells a frontend after a reload who is logged in, with which role, and the CSRF token it must send. The built-in pages stay as the backup and admin interface.

**Files:**

- Create: `src/phishhawk/server/frontend.py`
- Modify: `src/phishhawk/server/config.py`
- Modify: `src/phishhawk/server/routes/api.py`
- Modify: `src/phishhawk/server/app.py`
- Test: `tests/server/test_frontend.py` (new)
- Test: `tests/server/test_rbac.py` (changed)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:
  - `phishhawk.server.frontend`: `class Frontend(StaticFiles)`: `__init__(directory: str) -> None`; `get_response(path: str, scope: Scope) -> Response`
  - `phishhawk.server.config`: `class ServerSettings(BaseSettings)`: `data_dir: Path`; `database_url: str`; `secret_key: SecretStr`; `encryption_key: SecretStr`; `retention_days: int`; `max_upload_mb: int`; `max_batch_messages: int`; `campaign_window_days: int`; `host: str`; `port: int`; `tls_cert: str`; `tls_key: str`; `session_idle_minutes: int`; `analysis_memory_mb: int`; `analysis_cpu_seconds: int`; `cookie_secure: bool`; `frontend_dir: str`; `property db_url() -> str`
  - `phishhawk.server.routes.api`: `GET /api/v1/session` → `current_session`

**Notes:**

- The mount exists only when `PHISHHAWK_FRONTEND_DIR` is set; otherwise `/app/` is a 404.
- A path without a file extension falls back to `index.html`, so `/app/analyses/12` reloads; a missing asset stays a 404. Starlette's `StaticFiles` refuses paths outside the build folder (the test sends `%2e%2e`).
- The security-headers middleware gives the frontend the same CSP as the pages: scripts, styles, fonts and requests from this origin only. A build that loads anything from a CDN, Google Fonts or Gemini will not run; docs/FRONTEND.md (task 18) says so and gives a starting prompt for AI Studio.
- Returning the CSRF token from a GET is safe here: the cookie is `SameSite=Strict` and the API sends no CORS headers, so no other site can make the call with the cookie or read the answer.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_frontend.py`:

```python
"""A frontend built elsewhere (the owner builds one in Google AI Studio),
served from this origin at /app/ under the app's CSP, and the endpoint it
asks after a reload who is logged in."""

import pytest

PAGE = '<!doctype html><title>PhishHawk</title><div id="root"></div>' \
       '<script type="module" src="/app/assets/app.js"></script>'


@pytest.fixture
def built(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(PAGE)
    (dist / "assets" / "app.js").write_text("document.title = 'PhishHawk'")
    (tmp_path / "secret.txt").write_text("outside the build")
    return dist


@pytest.fixture
def frontend(services, built):
    from fastapi.testclient import TestClient

    from phishhawk.server.app import create_app

    services.settings.frontend_dir = str(built)
    return TestClient(create_app(services=services))


def test_the_frontend_is_served_under_the_app_csp_and_its_own_routes_reload(frontend):
    for path in ("/app/", "/app/queue", "/app/analyses/12"):
        page = frontend.get(path)
        assert page.status_code == 200 and 'id="root"' in page.text, path
        assert "script-src 'self'" in page.headers["content-security-policy"], path
    script = frontend.get("/app/assets/app.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"]


def test_a_missing_file_or_a_path_outside_the_build_is_not_found(frontend):
    assert frontend.get("/app/assets/missing.js").status_code == 404
    assert frontend.get("/app/%2e%2e/secret.txt").status_code == 404


def test_without_a_built_frontend_nothing_is_served_at_app(anon):
    assert anon.get("/app/").status_code == 404


def test_the_session_endpoint_says_who_is_calling(alice, admin, anon):
    assert anon.get("/api/v1/session").status_code == 401
    alice_id = next(u["id"] for u in admin.get("/api/v1/users").json() if u["username"] == "alice")
    assert alice.get("/api/v1/session").json() == {"user_id": alice_id, "username": "alice", "role": "analyst",
                                                   "via": "session", "scope": "full",
                                                   "csrf": alice.headers["X-CSRF-Token"]}
```

Change `tests/server/test_rbac.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/test_rbac.py
+++ b/tests/server/test_rbac.py
@@ -10,6 +10,7 @@
 
 # (method, path, (anonymous, analyst, admin, read token, submit token))
 MATRIX = [
+    ("GET", "/api/v1/session", (401, 200, 200, 200, 200)),
     ("GET", "/api/v1/analyses", (401, 200, 200, 200, 200)),
     ("GET", "/api/v1/analyses/{analysis}", (401, 200, 200, 200, 200)),
     ("GET", "/api/v1/submissions/{submission}", (401, 200, 200, 200, 200)),
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_frontend.py tests/server/test_rbac.py
```

Expected: FAIL. The first error is `ValueError: "ServerSettings" object has no field "frontend_dir"`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/frontend.py`:

```python
"""A frontend built elsewhere (docs/FRONTEND.md), served from this origin at
/app/: its files, and its index.html for any path without a file extension,
so the frontend's own routes survive a reload. Everything else in the build
folder's parent stays out of reach."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope


class Frontend(StaticFiles):
    def __init__(self, directory: str) -> None:
        super().__init__(directory=directory, html=True)

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404 and "." not in path.rsplit("/", 1)[-1]:
                return await super().get_response("index.html", scope)
            raise
```

Change `src/phishhawk/server/config.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/config.py
+++ b/src/phishhawk/server/config.py
@@ -32,6 +32,7 @@
     analysis_memory_mb: int = 2048
     analysis_cpu_seconds: int = 120
     cookie_secure: bool = True  # False only for plain-HTTP local testing
+    frontend_dir: str = ""  # a frontend's build, served at /app/ (docs/FRONTEND.md)
 
     @property
     def db_url(self) -> str:
```

Change `src/phishhawk/server/routes/api.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/routes/api.py
+++ b/src/phishhawk/server/routes/api.py
@@ -57,6 +57,13 @@
     response = JSONResponse({"csrf": outcome[1]})
     set_cookie(request, response, outcome[0])
     return response
+
+
+@router.get("/session")
+def current_session(actor: CurrentActor) -> dict[str, Any]:
+    """Who is calling, for a frontend after a reload; the CSRF token too."""
+    return {"user_id": actor.user_id, "username": actor.username, "role": actor.role, "via": actor.via,
+            "scope": actor.scope, "csrf": actor.csrf}
 
 
 @router.delete("/session", status_code=204)
```

Change `src/phishhawk/server/app.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/app.py
+++ b/src/phishhawk/server/app.py
@@ -19,6 +19,7 @@
 from .config import ServerSettings, load_settings
 from .crypto import Box
 from .db import make_engine, make_sessionmaker, transaction
+from .frontend import Frontend
 from .models import Job
 from .processing import Services
 from .security import APP_CSP, BASE_HEADERS, HSTS
@@ -83,6 +84,8 @@
     app.include_router(api.router)
     app.include_router(pages.router)
     app.mount("/static", StaticFiles(directory=str(files("phishhawk.server") / "static")), name="static")
+    if services.settings.frontend_dir:
+        app.mount("/app", Frontend(services.settings.frontend_dir), name="frontend")
     return app
 
 
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_frontend.py tests/server/test_rbac.py
```
Expected: 22 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/server/app.py src/phishhawk/server/config.py src/phishhawk/server/frontend.py src/phishhawk/server/routes/api.py tests/server/test_frontend.py tests/server/test_rbac.py
git commit -m "Serve a frontend built elsewhere at /app/ and tell it who is logged in"
```

### Task 14: The phishhawk server command

*PR 7.*

`phishhawk server run | worker | migrate | create-admin | rotate-key | audit verify`, and the hand-over from the main CLI. `run` migrates, starts one worker process and the web app, and stops both cleanly on SIGTERM or Ctrl+C. A real-process test submits a bundled sample and needs the verdict within 5 seconds.

**Files:**

- Create: `src/phishhawk/server/cli.py`
- Modify: `src/phishhawk/cli.py`
- Test: `tests/server/test_server_cli.py` (new)
- Test: `tests/server/test_serve.py` (new)
- Test: `tests/test_cli.py` (changed)
- Test: `tests/server/serverkit.py` (changed)

**Interfaces:**

- Consumes:
  - `phishhawk.server.app` (task 11): `build_services(settings: ServerSettings) -> Services`
  - `phishhawk.server.audit` (task 5): `record(db: Session, actor: str, action: str, object_type: str='', object_id: object='', details: dict[str, Any] | None=None) -> AuditRecord`; `verify(db: Session) -> list[str]`
  - `phishhawk.server.auth` (task 6): `class AuthError(ValueError)`; `create_user(db: DbSession, username: str, password: str, role: str) -> User`
  - `phishhawk.server.config` (task 2): `class ServerSettings(BaseSettings)`; `load_settings() -> ServerSettings`
  - `phishhawk.server.crypto` (task 2): `class Box`; `class DecryptError(Exception)`
  - `phishhawk.server.db` (task 3): `migrate(url: str) -> None`; `transaction(factory: sessionmaker[Session]) -> Iterator[Session]`
  - `phishhawk.server.models` (task 3): `class AuditRecord(Base)`
  - `phishhawk.server.rotation` (task 10): `rotate(db: Session, store: BlobStore, new_box: Box, actor: str) -> dict[str, int]`
  - `phishhawk.server.worker` (task 9): `run_forever(services: Services, should_stop: Callable[[], bool]=lambda: False, idle: float=1.0) -> None`
- Produces:
  - `phishhawk.server.cli`: `class CliError(Exception)`; `build_parser() -> argparse.ArgumentParser`; `settings_or_error() -> ServerSettings`; `create_admin(settings: ServerSettings, username: str, from_stdin: bool) -> int`; `rotate_key(settings: ServerSettings) -> int`; `verify_audit(settings: ServerSettings) -> int`; `run_worker(parent: int | None=None) -> None`; `serve(settings: ServerSettings) -> int`; `main(argv: list[str]) -> int`
  - `phishhawk.cli`: `cmd_server(argv: list[str]) -> int`

**Notes:**

- Setting errors name the variables (`PHISHHAWK_SECRET_KEY`, ...) and never echo a value.
- uvicorn raises the signal again after its own shutdown. `serve()` installs handlers that turn it into `SystemExit(0)`, so its `finally` block stops the worker; without them the worker is orphaned (the test checks that no child outlives the server).
- The worker also stops when the process that started it is gone (`os.getppid()` changes).
- The main CLI hands `server ...` over before argparse, so `phishhawk server --help` shows the server's own help, and without the extra it says how to install it (exit 3).
- `create-admin --password-stdin` reads one line, for scripts and `docker compose exec -T`.

- [ ] **Step 1: Write the failing tests**

Change `tests/test_cli.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/test_cli.py
+++ b/tests/test_cli.py
@@ -134,3 +134,9 @@
     assert main([str(tmp_path), *OFFLINE, "--quiet"]) == 1
     out = capsys.readouterr().out
     assert "Inbox.mbox#1" in out and "Inbox.mbox#2" in out and "BATCH SUMMARY (2 messages)" in out
+
+
+def test_server_without_the_extra_says_how_to_install_it(monkeypatch, capsys):
+    monkeypatch.setitem(sys.modules, "phishhawk.server.cli", None)  # as if fastapi were missing
+    assert main(["server", "run"]) == 3
+    assert "pip install 'phishhawk[server]'" in capsys.readouterr().err
```

Change `tests/server/serverkit.py` (apply with `git apply`, or edit by hand):

```diff
--- a/tests/server/serverkit.py
+++ b/tests/server/serverkit.py
@@ -1,6 +1,19 @@
 """Helpers the server tests share."""
 
+import contextlib
+import os
+import signal
+import socket
+import subprocess
+import sys
+import time
+from dataclasses import dataclass
+from pathlib import Path
+
+import requests
+
 PASSWORD = "correct horse battery"
+COMMAND = [sys.executable, "-m", "phishhawk", "server"]
 
 
 def login(app, username):
@@ -12,3 +25,47 @@
     assert response.status_code == 200, response.text
     client.headers["X-CSRF-Token"] = response.json()["csrf"]
     return client
+
+
+@dataclass
+class Running:
+    base: str
+    process: subprocess.Popen
+    log: Path
+
+
+def _free_port():
+    with socket.socket() as sock:
+        sock.bind(("127.0.0.1", 0))
+        return sock.getsockname()[1]
+
+
+@contextlib.contextmanager
+def running_server(tmp_path):
+    """phishhawk server run as a real process on a free port, with an admin
+    "root"; stopped with SIGTERM afterwards if the test has not stopped it."""
+    from phishhawk.server.crypto import new_key
+
+    port = _free_port()
+    env = dict(os.environ, PHISHHAWK_DATA_DIR=str(tmp_path), PHISHHAWK_PORT=str(port),
+               PHISHHAWK_SECRET_KEY=new_key(), PHISHHAWK_ENCRYPTION_KEY=new_key(), PHISHHAWK_COOKIE_SECURE="false")
+    log = tmp_path / "server.log"
+    with open(log, "wb") as output:  # a file, not a pipe: a stray worker would hold a pipe open
+        process = subprocess.Popen(COMMAND + ["run"], env=env, stdout=output, stderr=subprocess.STDOUT)
+    try:
+        base = "http://127.0.0.1:%d" % port
+        deadline = time.monotonic() + 30
+        while True:
+            try:
+                requests.get(base + "/healthz", timeout=1)
+                break
+            except requests.ConnectionError:
+                assert time.monotonic() < deadline, log.read_text("utf-8", "replace")
+                time.sleep(0.2)
+        subprocess.run(COMMAND + ["create-admin", "root", "--password-stdin"], env=env, input=PASSWORD + "\n",
+                       text=True, check=True, capture_output=True)
+        yield Running(base, process, log)
+    finally:
+        if process.poll() is None:
+            process.send_signal(signal.SIGTERM)
+            process.wait(timeout=60)
```

Create `tests/server/test_server_cli.py`:

```python
"""phishhawk server: migrate, create-admin, audit verify and rotate-key, run
in-process against a temporary data directory."""

import io

import pytest
from sqlalchemy import select, update

from phishhawk import cli as main_cli
from phishhawk.server import appsettings, cli
from phishhawk.server.crypto import Box, new_key
from phishhawk.server.db import make_engine, make_sessionmaker, transaction
from phishhawk.server.models import AuditRecord, User

from .serverkit import PASSWORD

KEY = new_key()


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHHAWK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", new_key())
    monkeypatch.setenv("PHISHHAWK_ENCRYPTION_KEY", KEY)
    monkeypatch.delenv("PHISHHAWK_NEW_ENCRYPTION_KEY", raising=False)
    return make_sessionmaker(make_engine("sqlite:///%s" % (tmp_path / "phishhawk.sqlite3")))


def test_migrate_then_create_the_first_admin(env, monkeypatch, capsys):
    assert cli.main(["migrate"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "root", "--password-stdin"]) == 0
    with transaction(env) as s:
        assert s.scalars(select(User)).one().role == "admin"
        entry = s.scalars(select(AuditRecord)).one()
        assert (entry.actor, entry.action, entry.details) == ("cli", "user_create", {"username": "root",
                                                                                   "role": "admin"})
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "root", "--password-stdin"]) == 3
    assert "that username is taken" in capsys.readouterr().err


def test_missing_settings_are_named_and_never_echoed(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PHISHHAWK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHHAWK_RETENTION_DAYS", "not-a-number-s3cret")
    for name in ("PHISHHAWK_SECRET_KEY", "PHISHHAWK_ENCRYPTION_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert cli.main(["migrate"]) == 3
    err = capsys.readouterr().err
    for name in ("PHISHHAWK_SECRET_KEY", "PHISHHAWK_ENCRYPTION_KEY", "PHISHHAWK_RETENTION_DAYS"):
        assert name in err
    assert "s3cret" not in err


def test_audit_verify_exits_1_after_tampering(env, monkeypatch, capsys):
    cli.main(["migrate"])
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    cli.main(["create-admin", "root", "--password-stdin"])
    assert cli.main(["audit", "verify"]) == 0
    assert "audit log verified: 1 record" in capsys.readouterr().out
    with transaction(env) as s:
        s.execute(update(AuditRecord).values(actor="someone-else"))
    assert cli.main(["audit", "verify"]) == 1
    assert "record 1 was changed" in capsys.readouterr().out


def test_rotate_key_needs_the_new_key_and_moves_secrets(env, monkeypatch, capsys):
    cli.main(["migrate"])
    with transaction(env) as s:
        appsettings.set_secret(s, Box.from_b64(KEY), "key:urlscan", "us-key-9876")
    assert cli.main(["rotate-key"]) == 3
    assert "PHISHHAWK_NEW_ENCRYPTION_KEY" in capsys.readouterr().err
    new = new_key()
    monkeypatch.setenv("PHISHHAWK_NEW_ENCRYPTION_KEY", new)
    assert cli.main(["rotate-key"]) == 0
    assert "0 blobs and 1 secret" in capsys.readouterr().out
    with transaction(env) as s:
        assert appsettings.get_secret(s, Box.from_b64(new), "key:urlscan") == "us-key-9876"


def test_the_main_cli_hands_server_commands_over(env, capsys):
    assert main_cli.main(["server", "migrate"]) == 0
    assert "database is up to date" in capsys.readouterr().out
    assert "server" in main_cli.COMMANDS


def test_help_server_lists_every_action(capsys):
    with pytest.raises(SystemExit) as done:
        main_cli.main(["help", "server"])
    assert done.value.code == 0
    out = capsys.readouterr().out
    for action in ("run", "worker", "migrate", "create-admin", "rotate-key", "audit"):
        assert action in out
```

Create `tests/server/test_serve.py`:

```python
"""phishhawk server run, as a real process: health, log in, submit a bundled
sample, verdict within 5 seconds offline, every file downloads, clean stop."""

import os
import signal
import time

import requests

from .serverkit import PASSWORD, running_server
from conftest import sample

KINDS = ["json", "stix", "misp", "md", "csv", "html", "manifest"]


def _children(pid):
    """Linux only; elsewhere the check that no worker outlives the server is skipped."""
    path = "/proc/%d/task/%d/children" % (pid, pid)
    if not os.path.exists(path):
        return []
    with open(path) as handle:
        return [int(child) for child in handle.read().split()]


def _alive(pid):
    """Running, not a zombie waiting to be reaped."""
    try:
        with open("/proc/%d/stat" % pid) as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def test_run_serves_a_sample_end_to_end_and_stops_cleanly(tmp_path):
    with running_server(tmp_path) as server:
        web = requests.Session()
        login = web.post(server.base + "/api/v1/session", json={"username": "root", "password": PASSWORD})
        web.headers["X-CSRF-Token"] = login.json()["csrf"]
        with open(sample("sample_phish.eml"), "rb") as handle:
            started = time.monotonic()
            submitted = web.post(server.base + "/api/v1/submissions", files={"file": ("m.eml", handle)},
                                 data={"offline": "true"})
        assert submitted.status_code == 202, submitted.text
        status = submitted.json()
        while status["status"] in ("queued", "running") and time.monotonic() - started < 30:
            time.sleep(0.1)
            status = web.get(server.base + "/api/v1/submissions/%d" % status["id"]).json()
        elapsed = time.monotonic() - started
        assert status["status"] == "done", status
        assert elapsed < 5, "submit to verdict took %.1f s" % elapsed
        analysis = web.get(server.base + "/api/v1/analyses/%d" % status["analysis_id"]).json()
        assert analysis["verdict"] == "LIKELY PHISHING"
        assert [f["kind"] for f in analysis["files"]] == KINDS
        for entry in analysis["files"]:
            got = web.get(server.base + "/api/v1/analyses/%d/files/%s" % (analysis["id"], entry["name"]))
            assert got.status_code == 200 and len(got.content) == entry["size"]
        children = _children(server.process.pid)
        server.process.send_signal(signal.SIGTERM)
        server.process.wait(timeout=60)
        assert server.process.returncode == 0, server.log.read_text("utf-8", "replace")
    time.sleep(1)
    assert not [pid for pid in children if _alive(pid)], "a worker outlived the server"
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/test_cli.py tests/server/test_server_cli.py tests/server/test_serve.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'cli' from 'phishhawk.server'`.

- [ ] **Step 3: Write the code**

Create `src/phishhawk/server/cli.py`:

```python
"""phishhawk server: run the web app and its worker, and the admin tasks that
need no web page (migrate, create-admin, rotate-key, audit verify)."""

from __future__ import annotations

import argparse
import getpass
import multiprocessing
import os
import signal
import sys
from types import FrameType

from pydantic import ValidationError

from . import audit, auth, rotation
from .app import build_services
from .config import ServerSettings, load_settings
from .crypto import Box, DecryptError
from .db import migrate, transaction

EXIT_FAILED, EXIT_ERROR = 1, 3


class CliError(Exception):
    """A problem to report in one line, with exit code 3."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishhawk server",
        description="Run the PhishHawk web app. Settings come from PHISHHAWK_* environment variables; "
                    "see docs/SERVER.md.")
    actions = parser.add_subparsers(dest="action", metavar="<action>", required=True)
    actions.add_parser("run", help="bring the database up to date, then start the web app and one worker")
    actions.add_parser("worker", help="run a worker without the web app")
    actions.add_parser("migrate", help="create the database or bring it up to date")
    admin = actions.add_parser("create-admin", help="create an admin user (the first one, or another)")
    admin.add_argument("username")
    admin.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    actions.add_parser("rotate-key", help="re-encrypt everything under PHISHHAWK_NEW_ENCRYPTION_KEY "
                                          "(stop the server first)")
    log = actions.add_parser("audit", help="audit log tasks")
    log.add_subparsers(dest="audit_action", metavar="<task>", required=True).add_parser(
        "verify", help="check the audit log's hash chain")
    return parser


def settings_or_error() -> ServerSettings:
    """The settings, or a CliError naming each bad variable but never its value."""
    try:
        settings = load_settings()
        Box.from_b64(settings.encryption_key.get_secret_value())
        return settings
    except ValidationError as exc:
        names = sorted({"PHISHHAWK_" + str(error["loc"][0]).upper() for error in exc.errors()})
        raise CliError("missing or not valid: " + ", ".join(names)) from None
    except ValueError as exc:
        raise CliError(str(exc)) from None


def _password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Password again: "):
        raise CliError("the passwords do not match")
    return first


def _plural(count: int, word: str) -> str:
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def create_admin(settings: ServerSettings, username: str, from_stdin: bool) -> int:
    password = _password(from_stdin)
    with transaction(build_services(settings).sessions) as db:
        try:
            user = auth.create_user(db, username, password, "admin")
        except auth.AuthError as exc:
            raise CliError(str(exc)) from None
        audit.record(db, "cli", "user_create", "user", user.id, {"username": user.username, "role": "admin"})
    print("created admin %s" % username)
    return 0


def rotate_key(settings: ServerSettings) -> int:
    text = os.environ.get("PHISHHAWK_NEW_ENCRYPTION_KEY", "")
    if not text:
        raise CliError("set PHISHHAWK_NEW_ENCRYPTION_KEY to the new key (32 bytes, base64)")
    try:
        new_box = Box.from_b64(text)
    except ValueError:
        raise CliError("PHISHHAWK_NEW_ENCRYPTION_KEY must be 32 bytes in base64") from None
    services = build_services(settings)
    try:
        with transaction(services.sessions) as db:
            counts = rotation.rotate(db, services.store, new_box, actor="cli")
    except DecryptError:
        raise CliError("a stored value opens under neither key; nothing was deleted, and the rotation can be "
                       "run again once PHISHHAWK_ENCRYPTION_KEY is the current key") from None
    print("re-encrypted %s and %s. Now set PHISHHAWK_ENCRYPTION_KEY to the new key and start the server."
          % (_plural(counts["blobs"], "blob"), _plural(counts["secrets"], "secret")))
    return 0


def verify_audit(settings: ServerSettings) -> int:
    from sqlalchemy import func, select

    from .models import AuditRecord

    with transaction(build_services(settings).sessions) as db:
        problems = audit.verify(db)
        count = db.scalar(select(func.count()).select_from(AuditRecord)) or 0
    if problems:
        print("\n".join(problems))
        return EXIT_FAILED
    print("audit log verified: %s" % _plural(count, "record"))
    return 0


def run_worker(parent: int | None = None) -> None:
    """The worker loop until SIGTERM or SIGINT, or until the server process
    that started it is gone; the job in hand is finished first."""
    from .worker import run_forever

    stop = []

    def _stop(signum: int, frame: FrameType | None) -> None:
        stop.append(signum)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    orphaned = (lambda: os.getppid() != parent) if parent else (lambda: False)
    run_forever(build_services(settings_or_error()), should_stop=lambda: bool(stop) or orphaned())


def _exit_cleanly(signum: int, frame: FrameType | None) -> None:
    raise SystemExit(0)


def serve(settings: ServerSettings) -> int:
    import uvicorn

    migrate(settings.db_url)
    # uvicorn raises the signal again once it has shut down; this turns it into
    # an exception, so the finally block below stops the worker
    signal.signal(signal.SIGTERM, _exit_cleanly)
    signal.signal(signal.SIGINT, _exit_cleanly)
    worker = multiprocessing.get_context("spawn").Process(target=run_worker, args=(os.getpid(),),
                                                          name="phishhawk-worker")
    worker.start()
    try:
        uvicorn.run("phishhawk.server.app:create_app", factory=True, host=settings.host, port=settings.port,
                    ssl_certfile=settings.tls_cert or None, ssl_keyfile=settings.tls_key or None,
                    server_header=False)
    finally:
        worker.terminate()
        worker.join(30)
        if worker.is_alive():
            worker.kill()
    return 0


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = settings_or_error()
        if args.action == "migrate":
            migrate(settings.db_url)
            print("database is up to date")
            return 0
        if args.action == "create-admin":
            return create_admin(settings, args.username, args.password_stdin)
        if args.action == "rotate-key":
            return rotate_key(settings)
        if args.action == "audit":
            return verify_audit(settings)
        if args.action == "worker":
            run_worker()
            return 0
        return serve(settings)
    except CliError as exc:
        print("phishhawk server: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
```

Change `src/phishhawk/cli.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/cli.py
+++ b/src/phishhawk/cli.py
@@ -48,7 +48,7 @@
 from .report.common import printable, safe_report_name, to_dict
 
 COMMANDS = ("scan", "imap", "graph", "gmail", "campaign", "sweep", "evidence", "doctor", "cache", "techniques",
-            "help")
+            "server", "help")
 EXIT_CODES = {"NO STRONG INDICATORS": 0, "SUSPICIOUS": 1, "LIKELY PHISHING": 1, "MALICIOUS": 2}
 EXIT_ERROR = 3
 
@@ -467,6 +467,9 @@
         help="list the MITRE ATT&CK techniques PhishHawk can evidence",
         description="The MITRE ATT&CK techniques PhishHawk can evidence, and what it looks for.")
     techniques.add_argument("--json", action="store_true", help="machine-readable output")
+
+    commands.add_parser("server", add_help=False, help="run the web app (needs: pip install 'phishhawk[server]'); "
+                                                        "see phishhawk server --help")
 
     helper = commands.add_parser("help", help="show help for a command")
     helper.add_argument("topic", nargs="?", choices=COMMANDS[:-1])
@@ -1224,9 +1227,23 @@
 # entry point
 # ---------------------------------------------------------------------------
 
+def cmd_server(argv: list[str]) -> int:
+    try:
+        from .server.cli import main as server_main
+    except ImportError:
+        sys.stderr.write("phishhawk server needs the web app's dependencies: pip install 'phishhawk[server]'\n")
+        return EXIT_ERROR
+    return server_main(argv)
+
+
 def main(argv: list[str] | None = None) -> int:
     parser = build_parser()
-    args = parser.parse_args(normalise_argv(list(sys.argv[1:] if argv is None else argv)))
+    argv = normalise_argv(list(sys.argv[1:] if argv is None else argv))
+    if argv[:2] == ["help", "server"]:
+        argv = ["server", "--help"]
+    if argv[:1] == ["server"]:
+        return cmd_server(argv[1:])
+    args = parser.parse_args(argv)
     for flag in ("no_color", "no_banner"):
         setattr(args, flag, getattr(args, flag, False) or getattr(args, "top_" + flag, False))
 
```

- [ ] **Step 4: Run the tests again**

Run, in order:

```bash
python -m pytest tests/test_cli.py tests/server/test_server_cli.py tests/server/test_serve.py
```
Expected: 30 passed.

```bash
ruff check src tests && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 5: Commit**

```bash
git add src/phishhawk/cli.py src/phishhawk/server/cli.py tests/server/serverkit.py tests/server/test_serve.py tests/server/test_server_cli.py tests/test_cli.py
git commit -m "Add the phishhawk server command and hand it over from the main CLI"
```

### Task 15: The OpenAPI document

*PR 7.*

`docs/api/openapi.json` is the contract other tools (IntelPulse later) build on. A test fails when the routes change without it.

**Files:**

- Create: `tools/make_openapi.py`
- Modify: `src/phishhawk/server/app.py`
- Modify: `src/phishhawk/server/routes/pages.py`
- Test: `tests/server/test_openapi.py` (new)
- Generate: `docs/api/openapi.json`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces:
  - `phishhawk.server.app`: `openapi_json(app: FastAPI) -> str`

**Notes:**

- The pages router is left out of the schema; the document covers `/api/v1` and `/healthz`.
- `info.version` is the API version, `v1`, not the release number: OpenAPI requires the field, and a version bump alone should not change the document.
- Regenerate with `python tools/make_openapi.py`; never edit the JSON by hand.
- `main` may already carry `docs/api/openapi.json`, generated from the prototype so the frontend could start early. The tool then rewrites it, and `git diff docs/api/openapi.json` should show no change.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_openapi.py`:

```python
"""docs/api/openapi.json is the contract other tools build on, so it must
match the routes. After changing an API route: python tools/make_openapi.py"""

import json
import os

from phishhawk.server.app import openapi_json

DOCUMENT = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "api", "openapi.json")


def test_the_published_openapi_document_matches_the_routes(app):
    with open(DOCUMENT, encoding="utf-8") as handle:
        assert handle.read() == openapi_json(app), "run: python tools/make_openapi.py"


def test_it_describes_the_api_and_health_but_not_the_pages(app):
    paths = app.openapi()["paths"]
    assert "/healthz" in paths and "/api/v1/submissions" in paths
    assert all(path == "/healthz" or path.startswith("/api/v1/") for path in paths)


def test_it_carries_the_api_version_not_the_release(app):
    # info.version is required by OpenAPI; the release number would change it on every bump.
    assert json.loads(openapi_json(app))["info"]["version"] == "v1"
```

- [ ] **Step 2: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_openapi.py
```

Expected: FAIL. The first error is `ImportError: cannot import name 'openapi_json' from 'phishhawk.server.app'`.

- [ ] **Step 3: Write the code**

Change `src/phishhawk/server/app.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/app.py
+++ b/src/phishhawk/server/app.py
@@ -2,6 +2,7 @@
 
 from __future__ import annotations
 
+import json
 import shutil
 from importlib.resources import files
 from typing import Any
@@ -89,6 +90,15 @@
     return app
 
 
+def openapi_json(app: FastAPI) -> str:
+    """The API description as docs/api/openapi.json holds it: versioned as
+    the API (v1), not the release, so a version bump alone does not change
+    the contract."""
+    document = app.openapi()
+    document["info"]["version"] = "v1"
+    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
+
+
 ERROR_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
                410: "gone", 413: "too_large", 415: "unsupported", 422: "invalid", 429: "throttled"}
 
```

Change `src/phishhawk/server/routes/pages.py` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/routes/pages.py
+++ b/src/phishhawk/server/routes/pages.py
@@ -15,7 +15,7 @@
 from ..models import Analysis, ApiToken, AuditRecord, Submission, User
 from . import api
 
-router = APIRouter()
+router = APIRouter(include_in_schema=False)  # the API is documented; pages are not
 MB = 1024 * 1024
 VERDICTS = ("NO STRONG INDICATORS", "SUSPICIOUS", "LIKELY PHISHING", "MALICIOUS")
 
```

Create `tools/make_openapi.py`:

```python
#!/usr/bin/env python3
"""Write docs/api/openapi.json from the web app's routes.

    python tools/make_openapi.py

Needs the server extra (pip install -e ".[dev,server]"). The app is built with
throwaway keys in a temporary folder; nothing is stored. tests/server/
test_openapi.py fails when the routes change and this has not been run.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from phishhawk.server.app import create_app, openapi_json
from phishhawk.server.config import ServerSettings
from phishhawk.server.crypto import new_key

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCUMENT = os.path.join(ROOT, "docs", "api", "openapi.json")


def main() -> None:
    with tempfile.TemporaryDirectory() as data:
        settings = ServerSettings(data_dir=Path(data), secret_key=new_key(), encryption_key=new_key())
        text = openapi_json(create_app(settings))
    os.makedirs(os.path.dirname(DOCUMENT), exist_ok=True)
    with open(DOCUMENT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print("wrote %s" % os.path.relpath(DOCUMENT, ROOT))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Generate the document**

Run:

```bash
python tools/make_openapi.py
```

This writes `docs/api/openapi.json` (about 30 KB). Do not edit it by hand.

- [ ] **Step 5: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_openapi.py
```
Expected: 3 passed.

```bash
ruff check src tests tools && mypy
```

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 6: Commit**

```bash
git add docs/api/openapi.json src/phishhawk/server/app.py src/phishhawk/server/routes/pages.py tests/server/test_openapi.py tools/make_openapi.py
git commit -m "Publish the API description and test it against the routes"
```

### Task 16: Docker image, Compose and the smoke check

*PR 8.*

A non-root image and a Compose file that keeps the keys in Docker secrets and the data in a volume, plus `tools/server_smoke.py`, which checks a running app from outside the way an analyst uses it. CI builds the stack, creates an admin, runs the smoke check, verifies the audit log and checks for a clean stop.

**Files:**

- Create: `tools/server_smoke.py`
- Create: `server.Dockerfile`
- Create: `compose.yaml`
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: no new Python names (configuration, templates or documentation).

**Notes:**

- The container runs as uid 10001 with a read-only root file system, no capabilities, `no-new-privileges` and `init: true` (it reaps the worker's helper processes).
- Compose secret files are bind-mounted with their host permissions: the files must be readable by the container user (644), so the `secrets/` folder (700) is what keeps other host users out.
- Session cookies are `Secure`. Browsers accept them on `http://127.0.0.1`; Python's cookie jar does not, so CI sets `PHISHHAWK_COOKIE_SECURE=false` for the smoke check. The default stays true.
- Port 8000 is published on 127.0.0.1 only; anything wider goes through a TLS reverse proxy.
- If Docker Hub rate-limits the build, pass `--build-arg BASE=public.ecr.aws/docker/library/python:3.12-slim`, as with the CLI image.

- [ ] **Step 1: Write the smoke check**

Create `tools/server_smoke.py`:

```python
#!/usr/bin/env python3
"""Check a running PhishHawk web app from outside, the way an analyst uses it.

    SMOKE_PASSWORD=... python tools/server_smoke.py http://127.0.0.1:8000 --user admin

Waits for /healthz, logs in, submits samples/sample_phish.eml offline, waits
for the verdict, downloads every file and checks the HTML report is served
sandboxed. Exits 1 at the first step that fails. CI runs it against the
Compose stack; admins can run it after an upgrade.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "sample_phish.eml")
KINDS = ["json", "stix", "misp", "md", "csv", "html", "manifest"]


def check(base: str, user: str, password: str, wait: float = 60) -> None:
    deadline = time.monotonic() + wait
    while True:
        try:
            health = requests.get(base + "/healthz", timeout=5).json()
            break
        except (requests.ConnectionError, ValueError):
            if time.monotonic() > deadline:
                raise AssertionError("no answer from %s/healthz" % base) from None
            time.sleep(1)
    print("health: %s, version %s" % (health["status"], health["version"]))
    web = requests.Session()
    login = web.post(base + "/api/v1/session", json={"username": user, "password": password}, timeout=10)
    assert login.status_code == 200, "log in: HTTP %d" % login.status_code
    web.headers["X-CSRF-Token"] = login.json()["csrf"]
    with open(SAMPLE, "rb") as handle:
        submitted = web.post(base + "/api/v1/submissions", files={"file": ("sample_phish.eml", handle)},
                             data={"offline": "true"}, timeout=30)
    assert submitted.status_code == 202, "submit: HTTP %d" % submitted.status_code
    status = submitted.json()
    while status["status"] in ("queued", "running"):
        assert time.monotonic() < deadline + wait, "no verdict after %d s" % wait
        time.sleep(0.5)
        status = web.get(base + "/api/v1/submissions/%d" % status["id"], timeout=10).json()
    assert status["status"] == "done", "analysis: %s" % status.get("error")
    analysis = web.get(base + "/api/v1/analyses/%d" % status["analysis_id"], timeout=10).json()
    print("verdict: %s, score %s, report %s" % (analysis["verdict"], analysis["score"], analysis["report_id"]))
    assert [f["kind"] for f in analysis["files"]] == KINDS, "files: %s" % analysis["files"]
    for entry in analysis["files"]:
        got = web.get(base + "/api/v1/analyses/%d/files/%s" % (analysis["id"], entry["name"]), timeout=30)
        assert got.status_code == 200 and len(got.content) == entry["size"], "download %s" % entry["name"]
    html = next(f["name"] for f in analysis["files"] if f["kind"] == "html")
    page = web.get(base + "/analyses/%d/files/%s" % (analysis["id"], html), timeout=30)
    assert page.headers.get("content-security-policy", "").startswith("sandbox"), "report not sandboxed"
    print("downloads: all %d files; HTML report served sandboxed" % len(analysis["files"]))
    web.delete(base + "/api/v1/session", timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("base", help="the app's address, e.g. http://127.0.0.1:8000")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password-env", default="SMOKE_PASSWORD", metavar="NAME",
                        help="the environment variable that holds the password (default: SMOKE_PASSWORD)")
    args = parser.parse_args()
    try:
        check(args.base.rstrip("/"), args.user, os.environ[args.password_env])
    except (AssertionError, KeyError, requests.RequestException) as exc:
        print("FAILED: %s" % exc, file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it and watch it fail**

Run:

```bash
SMOKE_PASSWORD=x python tools/server_smoke.py http://127.0.0.1:8000  # nothing is running yet
```

Expected: `FAILED: no answer from http://127.0.0.1:8000/healthz` after 60 s, exit code 1.

- [ ] **Step 3: Write the image and the Compose file**

Create `server.Dockerfile`:

```dockerfile
# The PhishHawk web app: phishhawk server run (web app and one worker).
# The database and the encrypted blobs live in /data; the two keys come from
# Docker secrets (compose.yaml) or PHISHHAWK_* variables. See docs/SERVER.md.
ARG BASE=python:3.12-slim
FROM ${BASE}

LABEL org.opencontainers.image.title="phishhawk-server" \
      org.opencontainers.image.description="PhishHawk web app: phishing triage for a small SOC team" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /opt/phishhawk
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[server,qr]" \
 && useradd --create-home --uid 10001 phishhawk \
 && install -d -o phishhawk -m 700 /data

USER phishhawk
ENV PHISHHAWK_DATA_DIR=/data PHISHHAWK_HOST=0.0.0.0 PHISHHAWK_PORT=8000 PYTHONDONTWRITEBYTECODE=1
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]
ENTRYPOINT ["phishhawk", "server"]
CMD ["run"]
```

Create `compose.yaml`:

```yaml
# PhishHawk web app. Before the first start, create the two keys (docs/SERVER.md):
#   mkdir -m 700 secrets
#   openssl rand -base64 32 > secrets/phishhawk_secret_key
#   openssl rand -base64 32 > secrets/phishhawk_encryption_key
#   chmod 644 secrets/*    # the container's user reads them; the folder keeps others out
# Then: docker compose up -d
#       docker compose exec phishhawk phishhawk server create-admin admin
# Keep a copy of the encryption key: without it no backup can be read.
services:
  phishhawk:
    build:
      context: .
      dockerfile: server.Dockerfile
    image: phishhawk-server
    ports:
      - "127.0.0.1:8000:8000"  # this machine only; put a TLS reverse proxy in front for anything else
    environment:
      # false only to test over plain HTTP with a client other than a browser (CI does)
      PHISHHAWK_COOKIE_SECURE: ${PHISHHAWK_COOKIE_SECURE:-true}
      # your own frontend's build, served at /app/ (docs/FRONTEND.md), with the mount below
      # PHISHHAWK_FRONTEND_DIR: /frontend
    volumes:
      - phishhawk-data:/data
      # - ./frontend-dist:/frontend:ro
    secrets:
      - phishhawk_secret_key
      - phishhawk_encryption_key
    init: true  # reaps the worker's helper processes
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped

secrets:
  phishhawk_secret_key:
    file: ./secrets/phishhawk_secret_key
  phishhawk_encryption_key:
    file: ./secrets/phishhawk_encryption_key

volumes:
  phishhawk-data:
```

Change `.gitignore` (apply with `git apply`, or edit by hand):

```diff
--- a/.gitignore
+++ b/.gitignore
@@ -10,3 +10,4 @@
 /*.csv
 /*.md.out
 .coverage
+/secrets/
```

- [ ] **Step 4: Build, start and check the stack**

Run, from the repository root (`secrets/` is ignored by git):

```bash
mkdir -m 700 secrets
openssl rand -base64 32 > secrets/phishhawk_secret_key
openssl rand -base64 32 > secrets/phishhawk_encryption_key
chmod 644 secrets/*
PHISHHAWK_COOKIE_SECURE=false docker compose up -d --build --wait
SMOKE_PASSWORD="smoke-$(openssl rand -hex 12)"
export SMOKE_PASSWORD
printf '%s\n' "$SMOKE_PASSWORD" | docker compose exec -T phishhawk phishhawk server create-admin smoke --password-stdin
python tools/server_smoke.py http://127.0.0.1:8000 --user smoke
docker compose exec -T phishhawk phishhawk server audit verify
docker compose stop
docker inspect "$(docker compose ps -aq phishhawk)" --format '{{.State.ExitCode}}'
docker compose down -v && rm -r secrets
```

Expected: `docker compose up` reports the container healthy; the smoke check prints `health: ok`, `verdict: LIKELY PHISHING, score 35, report PH-...`, `downloads: all 7 files; HTML report served sandboxed` and `ok`; `audit verify` prints `audit log verified: ... records`; the stop takes a second or two and the exit code is `0`.

- [ ] **Step 5: Add the Compose job to CI**

Change `.github/workflows/ci.yml` (apply with `git apply`, or edit by hand):

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -108,6 +108,41 @@
           coverage run -m pytest
           coverage report
 
+  server-docker:
+    name: web app in Docker Compose
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
+      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
+        with:
+          python-version: "3.12"
+      - name: Keys, made the way docs/SERVER.md says
+        run: |
+          mkdir -m 700 secrets
+          openssl rand -base64 32 > secrets/phishhawk_secret_key
+          openssl rand -base64 32 > secrets/phishhawk_encryption_key
+          chmod 644 secrets/*
+      - name: Build and start, then wait for the health check
+        env:
+          PHISHHAWK_COOKIE_SECURE: "false"  # the check below talks plain HTTP to 127.0.0.1
+        run: docker compose up -d --build --wait
+      - name: Log in, submit a sample, fetch every file, verify the audit log
+        run: |
+          SMOKE_PASSWORD="smoke-$(openssl rand -hex 12)"
+          export SMOKE_PASSWORD
+          printf '%s\n' "$SMOKE_PASSWORD" |
+            docker compose exec -T phishhawk phishhawk server create-admin smoke --password-stdin
+          python -m pip install requests
+          python tools/server_smoke.py http://127.0.0.1:8000 --user smoke
+          docker compose exec -T phishhawk phishhawk server audit verify
+      - name: Stop cleanly
+        run: |
+          docker compose stop
+          test "$(docker inspect "$(docker compose ps -aq phishhawk)" --format '{{.State.ExitCode}}')" -eq 0
+      - name: Logs
+        if: failure()
+        run: docker compose logs
+
   installer:
     runs-on: ubuntu-latest
     steps:
```

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml .gitignore compose.yaml server.Dockerfile tools/server_smoke.py
git commit -m "Add the web app's Docker image, Compose file and smoke check"
```

### Task 17: Browser test

*PR 8.*

One test in headless Chromium: log in with the keyboard only, submit a sample, read the verdict and the sandboxed report, download a file, and check five widths from 320 to 1440 px for sideways scrolling, with no console errors (a CSP violation shows up as one). It skips when Playwright is not installed; CI installs it on Python 3.12.

**Files:**

- Create: `src/phishhawk/server/static/favicon.svg`
- Modify: `src/phishhawk/server/templates/base.html`
- Modify: `.github/workflows/ci.yml`
- Test: `tests/server/test_browser.py` (new)

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: no new Python names (configuration, templates or documentation).

**Notes:**

- Run it here and it fails on a console error: the browser asks for `/favicon.ico` and gets a 404. The fix is a small static `favicon.svg` linked from `base.html`; a `data:` icon would break the hostile-payload test, which allows same-origin links only.
- `PHISHHAWK_CHROMIUM` can name a Chromium executable when Playwright's own download is not wanted.

- [ ] **Step 1: Prepare**

Run:

```bash
python -m pip install playwright
python -m playwright install chromium
```

- [ ] **Step 2: Write the failing tests**

Create `tests/server/test_browser.py`:

```python
"""The web app in a real browser (headless Chromium through Playwright):
keyboard-only login, submit, verdict, download; no horizontal scrolling from
320 to 1440 px; no console errors, so nothing broke the CSP. Skipped when
Playwright or a Chromium for it is missing; PHISHHAWK_CHROMIUM may name the
browser's executable."""

import os

import pytest

from .serverkit import PASSWORD, running_server
from conftest import sample

sync_api = pytest.importorskip("playwright.sync_api")
WIDTHS = (320, 390, 768, 1024, 1440)


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as playwright:
        try:
            chromium = playwright.chromium.launch(executable_path=os.environ.get("PHISHHAWK_CHROMIUM") or None)
        except sync_api.Error as exc:
            pytest.skip("no Chromium for Playwright: %s" % str(exc).splitlines()[0])
        yield chromium
        chromium.close()


def _tab_to(page, element_id, limit=15):
    for _ in range(limit):
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement.id") == element_id:
            return
    raise AssertionError("Tab never reached #%s" % element_id)


def test_an_analyst_works_a_message_with_the_keyboard(browser, tmp_path):
    with running_server(tmp_path) as server:
        page = browser.new_page()
        errors = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.goto(server.base + "/login")
        _tab_to(page, "username")
        page.keyboard.type("root")
        _tab_to(page, "password")
        page.keyboard.type(PASSWORD)
        page.keyboard.press("Enter")
        page.wait_for_url(server.base + "/")
        page.set_input_files("#file", sample("sample_phish.eml"))  # the file picker is the system's own
        _tab_to(page, "raw")
        page.keyboard.press("Tab")  # the offline box
        page.keyboard.press("Space")
        page.keyboard.press("Tab")
        page.keyboard.press("Enter")
        page.wait_for_url("**/analyses/*", timeout=30_000)
        assert "LIKELY PHISHING" in page.locator("h1").inner_text()
        assert "LIKELY PHISHING" in page.frame_locator("iframe.report").locator("body").inner_text()
        with page.expect_download() as download:
            page.get_by_role("link", name="CSV indicators").click()
        assert download.value.suggested_filename.endswith(".csv")
        analysis = page.url
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 800})
            for path in (server.base + "/", server.base + "/queue", analysis, server.base + "/audit"):
                page.goto(path)
                overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                assert overflow <= 0, "%s scrolls sideways at %d px" % (path, width)
        assert not errors, errors
```

- [ ] **Step 3: Run them and watch them fail**

Run:

```bash
python -m pytest tests/server/test_browser.py
```

Expected: FAIL. The first error is `AssertionError: ['Failed to load resource: the server responded with a status of 404 (Not Found)']`.

- [ ] **Step 4: Write the code**

Create `src/phishhawk/server/static/favicon.svg`:

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0f172a"/><path d="M7 22 16 8l9 14-9-4z" fill="#fdba74"/></svg>
```

Change `src/phishhawk/server/templates/base.html` (apply with `git apply`, or edit by hand):

```diff
--- a/src/phishhawk/server/templates/base.html
+++ b/src/phishhawk/server/templates/base.html
@@ -6,6 +6,7 @@
 <meta name="referrer" content="no-referrer">
 <title>{% block title %}PhishHawk{% endblock %}</title>
 <link rel="stylesheet" href="/static/app.css">
+<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
 {% block head %}{% endblock %}
 </head>
 <body>
```

Change `.github/workflows/ci.yml` (apply with `git apply`, or edit by hand):

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -101,6 +101,11 @@
           cache-dependency-path: pyproject.toml
       - name: Install with the web app's dependencies
         run: python -m pip install -e ".[dev,server]"
+      - name: A browser for the browser test (one Python is enough)
+        if: matrix.python == '3.12'
+        run: |
+          python -m pip install playwright
+          python -m playwright install --with-deps chromium
       - name: Type check
         run: mypy
       - name: Every test, the web app's included, and coverage
```

- [ ] **Step 5: Run the tests again**

Run, in order:

```bash
python -m pytest tests/server/test_browser.py
```
Expected: 1 passed.

```bash
python -m pytest tests/server/test_hostile.py
```
Expected: 1 passed.

Everything passes, and ruff and mypy report nothing.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml src/phishhawk/server/static/favicon.svg src/phishhawk/server/templates/base.html tests/server/test_browser.py
git commit -m "Test the web app in a real browser and give it an icon"
```

### Task 18: Documentation and the milestone check

*PR 8.*

docs/SERVER.md for admins (start, settings, roles, providers, what is stored and for how long, backups, keys, the audit log, upgrades, troubleshooting), docs/FRONTEND.md for whoever builds a frontend of their own (the rules, the API in five calls, build and deploy, and a starting prompt for Google AI Studio), the README and USAGE pointers, the changelog entry, and the check that M1 is done.

**Files:**

- Create: `docs/SERVER.md`
- Create: `docs/FRONTEND.md`
- Modify: `README.md`
- Modify: `docs/USAGE.md`
- Modify: `CHANGELOG.md`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: no new Python names (configuration, templates or documentation).

**Notes:**

- Every claim in SERVER.md is something a test above exercises; nothing is documented that M1 does not do (Postgres is named as milestone 2).

- [ ] **Step 1: Write the documentation**

Create `docs/SERVER.md`:

````markdown
# PhishHawk web app

The web app puts PhishHawk's engine behind a browser and an API for a small SOC
team on one machine you control. An analyst uploads or pastes a reported
message, sees the verdict and the full HTML report, and downloads all six
export formats. Every action is recorded in a hash-chained audit log.

This is milestone 1 of v3: one message at a time. Batch upload, campaigns and
mailbox import come in later milestones (see the
[design](superpowers/specs/2026-10-06-phishhawk-v3-web-design.md)).

- [Start it with Docker Compose](#start-it-with-docker-compose)
- [Start it without Docker](#start-it-without-docker)
- [Settings](#settings)
- [Users, roles and API tokens](#users-roles-and-api-tokens)
- [Reputation lookups](#reputation-lookups)
- [What is stored, and for how long](#what-is-stored-and-for-how-long)
- [Backups](#backups)
- [Changing the keys](#changing-the-keys)
- [The audit log](#the-audit-log)
- [Upgrades](#upgrades)
- [Health and troubleshooting](#health-and-troubleshooting)
- [Commands](#commands)

## Start it with Docker Compose

```bash
git clone https://github.com/vinitrami-Soc/phishhawk.git && cd phishhawk
mkdir -m 700 secrets
openssl rand -base64 32 > secrets/phishhawk_secret_key
openssl rand -base64 32 > secrets/phishhawk_encryption_key
chmod 644 secrets/*        # the container's user reads them; the folder keeps others out
docker compose up -d --wait
docker compose exec phishhawk phishhawk server create-admin admin
```

Open <http://127.0.0.1:8000> and log in. Compose publishes the port on this
machine only. To reach it from other machines, put a reverse proxy with TLS
(Caddy or nginx) in front of it; do not publish port 8000 on a network.

**Keep a copy of `secrets/phishhawk_encryption_key` somewhere safe.** Every
stored message and report is encrypted with it. Without it, nothing in a backup
can be read, by you or anyone else.

The container runs as an unprivileged user with a read-only file system, no
Linux capabilities and `no-new-privileges`. Its only writable places are the
`phishhawk-data` volume (`/data`) and a `/tmp` in memory.

## Start it without Docker

```bash
pip install "phishhawk[server]"
export PHISHHAWK_DATA_DIR=/var/lib/phishhawk
export PHISHHAWK_SECRET_KEY="$(openssl rand -base64 32)"
export PHISHHAWK_ENCRYPTION_KEY="$(openssl rand -base64 32)"   # keep a copy
phishhawk server create-admin admin
phishhawk server run
```

`run` brings the database up to date, then starts the web app and one worker.
Stop it with Ctrl+C or SIGTERM. The worker finishes the message in hand if it
can within 30 seconds; otherwise it is stopped and that message is analysed
again after the next start.

Session cookies are marked `Secure`. Browsers accept them on
`http://127.0.0.1` and `http://localhost`, and over HTTPS. Set
`PHISHHAWK_COOKIE_SECURE=false` only to test over plain HTTP with a client
that is not a browser.

For TLS without a proxy, set `PHISHHAWK_TLS_CERT` and `PHISHHAWK_TLS_KEY`.

## Settings

From the environment, or from files in `/run/secrets` named like the variable
in lower case (Docker secrets). A variable wins over a file.

| Variable | Default | What it does |
|---|---|---|
| `PHISHHAWK_SECRET_KEY` | none, required | Keys the session cookies. A new value logs everyone out; nothing else changes. |
| `PHISHHAWK_ENCRYPTION_KEY` | none, required | 32 bytes in base64. Encrypts every stored message, report and API key. The server refuses to start without a valid one. |
| `PHISHHAWK_DATA_DIR` | `/var/lib/phishhawk` | The database (SQLite) and the encrypted files. |
| `PHISHHAWK_DATABASE_URL` | SQLite in the data folder | Milestone 1 is built and tested on SQLite only; Postgres support, for several workers, comes with milestone 2. |
| `PHISHHAWK_HOST`, `PHISHHAWK_PORT` | `127.0.0.1`, `8000` | Where the web app listens. |
| `PHISHHAWK_TLS_CERT`, `PHISHHAWK_TLS_KEY` | empty | Serve HTTPS directly. |
| `PHISHHAWK_RETENTION_DAYS` | `30` | Days before a message's sensitive data is deleted (see below). |
| `PHISHHAWK_MAX_UPLOAD_MB` | `25` | Largest message accepted. |
| `PHISHHAWK_SESSION_IDLE_MINUTES` | `480` | A session not used for this long ends. |
| `PHISHHAWK_ANALYSIS_MEMORY_MB`, `PHISHHAWK_ANALYSIS_CPU_SECONDS` | `2048`, `120` | Limits for the process that analyses one message. A message that exceeds them fails; the server does not. |
| `PHISHHAWK_COOKIE_SECURE` | `true` | See above. |
| `PHISHHAWK_FRONTEND_DIR` | empty | The build of your own frontend, served at `/app/`; see [FRONTEND.md](FRONTEND.md). |

An admin can change the retention period and the upload limit on the Settings
page; the value set there wins over the variable.

## Users, roles and API tokens

There are two roles.

- **Analyst**: submits messages, sees every analysis, downloads reports and
  exports, re-analyses, deletes the sensitive data of messages they submitted,
  and downloads the raw message of those messages. Sees their own entries in
  the audit log.
- **Admin**: everything an analyst can, for every message, plus users, API
  tokens, settings, hold and release, deleting a message completely, and the
  whole audit log.

Passwords need at least 12 characters and are stored as argon2id hashes.
After three wrong passwords for a user or from an address, each further try
waits twice as long as the last, up to five minutes.

An admin creates API tokens on the Users page, for a user and with one scope:
`read` (look up analyses and download exports) or `submit` (also submit
messages). A token is shown once. Send it as `Authorization: Bearer phk_...`.
Admin actions, raw message downloads and deletions need a logged-in session;
a token cannot do them, whoever it belongs to.

The API is described in [docs/api/openapi.json](api/openapi.json). To build
your own frontend on it (for example in Google AI Studio) and serve it from
this server at `/app/`, see [FRONTEND.md](FRONTEND.md).

## Reputation lookups

A new installation makes no outbound lookups. An admin turns providers on
under Settings (VirusTotal, urlscan.io, RDAP and AbuseIPDB) and enters the API
keys, which are stored encrypted and shown afterwards only as their last four
characters. With providers on, an analyst can still tick "offline" for a
message. Every analysis records which providers were asked and each request
made, without the keys.

## What is stored, and for how long

Each message has two tiers.

- **Sensitive (tier 1)**: the raw message, the full JSON report and the six
  exports. Encrypted with AES-256-GCM under the encryption key, each file bound
  to its own ID. Deleted after the retention period by an hourly job.
- **Summary (tier 2)**: SHA-256, size, verdict, score, report ID, sender and
  sender domain, recipient count, indicators and ATT&CK techniques. Kept until
  someone deletes it. The subject and the sender's display name are kept only
  as keyed hashes, for matching campaigns later; they cannot be read back.

Recipient addresses, the subject in clear, body text and attachment names
never reach tier 2.

On a message's page:

- **Delete now** removes its tier 1 at once (an analyst for their own
  submissions, an admin for any).
- **Hold** (admin) keeps its tier 1 past the retention period, for an
  investigation, until released. A message on hold cannot be deleted, by
  anyone, until an admin releases it.
- **Delete completely** (admin) removes both tiers. The audit log keeps the
  message's SHA-256 and who deleted it.

The same message submitted twice is one message with two submissions.

## Backups

Back up the data folder (or the `phishhawk-data` volume) and, with Postgres,
the database, at the same moment. Keep the encryption key separately: a backup
without it cannot be read, by design.

## Changing the keys

`PHISHHAWK_SECRET_KEY` can be changed at any time; everyone has to log in
again.

To change the encryption key, stop the server, then:

```bash
PHISHHAWK_NEW_ENCRYPTION_KEY="$(openssl rand -base64 32)"   # keep a copy
export PHISHHAWK_NEW_ENCRYPTION_KEY
phishhawk server rotate-key
```

It re-encrypts every stored file and API key under the new key and records the
rotation in the audit log. Then set `PHISHHAWK_ENCRYPTION_KEY` to the new key
and start the server. If it stops halfway, run it again with the same two keys:
what has already moved is skipped. If something opens under neither key, it
stops and deletes nothing.

With Compose: `docker compose stop`, then
`docker compose run --rm -e PHISHHAWK_NEW_ENCRYPTION_KEY phishhawk rotate-key`,
then replace `secrets/phishhawk_encryption_key` and `docker compose up -d`.

## The audit log

Logins (and failed ones), submissions, analyses, downloads, re-analyses,
deletions, holds, settings changes, user and token changes, key rotation and
each retention run are recorded with who did it and when. Each record holds the
hash of the one before it, so an edited, removed, reordered or cut-off record
is detected:

```bash
phishhawk server audit verify      # exit code 0 when intact, 1 otherwise
docker compose exec phishhawk phishhawk server audit verify
```

## Upgrades

```bash
git pull && docker compose up -d --build --wait
```

`run` applies database migrations on start. Without Docker:
`pip install -U "phishhawk[server]"`, then restart; `phishhawk server migrate`
does the same step on its own.

## Health and troubleshooting

`GET /healthz` needs no login and answers with the version, the number of
queued jobs, the last worker heartbeat and the free disk space. The Docker
image's health check uses it.

- **"missing or not valid: PHISHHAWK_..."** at start: the named variables are
  not set or not valid. Values are never printed.
- **A submission stays queued**: the worker is not running. `phishhawk server
  run` starts one; check its output.
- **"this message exceeded the analysis limits"**: the message needed more
  memory or CPU time than allowed. Raise the limits if the message is genuine.
- **More than one worker**: `run` already starts one. SQLite takes one writer
  at a time, so extra workers (`phishhawk server worker`) mostly wait; Postgres
  support comes with milestone 2.

## Commands

```text
phishhawk server run            bring the database up to date, then start the web app and one worker
phishhawk server worker         run a worker without the web app
phishhawk server migrate        create the database or bring it up to date
phishhawk server create-admin   create an admin user (--password-stdin to read it from standard input)
phishhawk server rotate-key     re-encrypt everything under PHISHHAWK_NEW_ENCRYPTION_KEY
phishhawk server audit verify   check the audit log's hash chain
```

Exit codes: 0 done, 1 the audit log failed verification, 2 a usage error,
3 a setting or input problem (the message says which).
````

Create `docs/FRONTEND.md`:

````markdown
# Your own frontend

The web app comes with its own pages, but you can build a frontend of your own,
for example in Google AI Studio, and let PhishHawk serve it at `/app/`. It runs
on the same origin as the API, so it needs no CORS and the session cookie
stays `SameSite=Strict`. The built-in pages keep working beside it, as the
backup and admin interface.

- [The rules](#the-rules)
- [The API in five calls](#the-api-in-five-calls)
- [Build and deploy](#build-and-deploy)
- [A starting prompt for Google AI Studio](#a-starting-prompt-for-google-ai-studio)

## The rules

Everything in a reported email is written by the attacker: the subject, the
sender's name, every indicator, every value in the report. Your frontend shows
that text to your analysts, so it is part of the defence.

1. **Show message data as text, never as HTML.** In React, `{value}` is safe.
   Never pass message data to `dangerouslySetInnerHTML`, `innerHTML`, a
   Markdown-to-HTML renderer, or an `href`. That includes `subject`, `sender`,
   `sender_domain`, file names, indicators and anything inside `report`.
2. **Open the full report only in a sandboxed frame**, from the server:

   ```html
   <iframe sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
           src="/analyses/{id}/files/{html file name}"></iframe>
   ```

   Never fetch the report and insert it into your page.
3. **Load nothing from other sites.** The app's Content-Security-Policy allows
   scripts, styles, fonts, images and requests from this server only. No CDN,
   no import map that points at a CDN, no Google Fonts: install packages with
   npm and let the build bundle them.
4. **Send no message data anywhere else.** No Gemini or other AI calls, no
   analytics. PhishHawk is self-hosted so that reported mail stays on your
   server; the CSP blocks such requests anyway.
5. **Use relative URLs** (`/api/v1/...`), so the browser sends the session
   cookie, and send the CSRF token on every request that changes something.

## The API in five calls

The full description is [docs/api/openapi.json](api/openapi.json). Errors are
JSON: `{"error": "<code>", "detail": "<text>"}`.

| Step | Call | Notes |
|---|---|---|
| On start | `GET /api/v1/session` | 401: show your login form. 200: `{"user_id", "username", "role", "via", "scope", "csrf"}`; keep `csrf` in memory. |
| Log in | `POST /api/v1/session` with JSON `{"username", "password"}` | 200: `{"csrf"}` and the session cookie. 401: wrong details. 429: wait (the `Retry-After` header says how long). |
| Submit | `POST /api/v1/submissions`, multipart: `file` (an .eml or .msg) or `raw` (pasted text), and `offline` (`true` for no reputation lookups) | Header `X-CSRF-Token: <csrf>`. 202: `{"id", "status", "error", "analysis_id", "submitted_at"}`. |
| Wait | `GET /api/v1/submissions/{id}` every second or two | Until `status` is `done` (then `analysis_id` is set) or `failed` (then `error` says why). |
| Show | `GET /api/v1/analyses/{id}` | `verdict`, `score`, `report_id`, `sha256`, `sender`, `subject`, `submitted_by` (a user ID) and `submitted_by_name`, `techniques`, `lookups`, `hold`, `files` (each with `name`, `kind`, `type`, `size`, `sha256`, `available`) and `report` (the full JSON report while the message is kept). |

Also useful: `GET /api/v1/analyses?q=&verdict=&offset=` (the queue, 50 at a
time; `q` matches a SHA-256, a report ID or an indicator), downloads at
`/api/v1/analyses/{id}/files/{name}?download=1`, `DELETE /api/v1/session` to
log out, and `GET /api/v1/audit`. Settings, users and tokens are admin calls;
the built-in pages already cover them.

Roles: analysts submit and read everything, and delete their own submissions;
admins also hold, release and delete completely. Show only the buttons the
user's `role` allows; the server refuses the rest (403) whatever the frontend
shows.

## Build and deploy

1. Build static files with base path `/app/`. With Vite, set `base: '/app/'` in
   `vite.config.ts`, then run `npm run build`. The result is a `dist/` folder.
2. Copy `dist/` to the server, for example to `/srv/phishhawk-frontend`.
3. Set `PHISHHAWK_FRONTEND_DIR=/srv/phishhawk-frontend` and restart. With
   Compose, mount the folder read-only and set the variable; `compose.yaml`
   has the two lines, commented out.
4. Open `/app/`. Your frontend's own routes (`/app/queue`, `/app/analyses/12`)
   load `index.html`, so a reload works.

If the page stays blank, open the browser's console. A "Content Security
Policy" error names the script, style or font that came from another site;
bundle it instead.

## A starting prompt for Google AI Studio

Attach `docs/api/openapi.json` and paste:

```text
Build a web frontend for PhishHawk, a phishing triage service, in React and
TypeScript with Vite. The attached OpenAPI file describes its API.

- It is served by the PhishHawk server at /app/ on the same origin: set Vite's
  base to '/app/' and call the API with relative URLs such as /api/v1/session.
- Install every library with npm. Do not load scripts, styles or fonts from a
  CDN or Google Fonts, and do not use an import map. Do not call Gemini or any
  other external service.
- On start, GET /api/v1/session. On 401 show a login form that POSTs
  {"username", "password"} to /api/v1/session. Keep the returned "csrf" value
  in memory and send it as the X-CSRF-Token header on every POST, PATCH and
  DELETE.
- Pages: Submit (upload an .eml or .msg file, or paste raw text, with an
  "Offline" checkbox; then poll GET /api/v1/submissions/{id} until status is
  done or failed), Queue (GET /api/v1/analyses with search and a verdict
  filter), and Analysis (GET /api/v1/analyses/{id}: verdict, score, report ID,
  sender, the downloads, and the full report in
  <iframe sandbox="allow-popups allow-popups-to-escape-sandbox allow-downloads"
  src="/analyses/{id}/files/{name of the file whose kind is html}">).
- Every value that comes from an email is attacker-controlled. Render it as
  text only: never dangerouslySetInnerHTML, innerHTML, a Markdown renderer, or
  a link built from it.
- Accessible: one h1 per page, labels on every field, visible keyboard focus,
  WCAG AA contrast in light and dark.
```

Review what it produces against [the rules](#the-rules) before you deploy it.
````

Change `README.md` (apply with `git apply`, or edit by hand):

````diff
--- a/README.md
+++ b/README.md
@@ -237,6 +237,15 @@
 ```bash
 ./phishhawk suspicious.eml      # straight from the checkout; needs `requests` importable
 ```
+
+### The web app (preview)
+
+For a team, `phishhawk server` runs PhishHawk as a web app: log in, upload or
+paste a reported message, read the report and download every format, with
+encrypted storage, retention and an audit log. It needs the `server` extra
+(`pip install "phishhawk[server]"`) or Docker Compose (`docker compose up -d`).
+Setup, roles, keys and backups: [docs/SERVER.md](docs/SERVER.md). To put your own frontend
+on its API, for example one built in Google AI Studio: [docs/FRONTEND.md](docs/FRONTEND.md).
 
 ### Check the install
 
@@ -721,7 +730,7 @@
 phishhawk/
 ├── src/phishhawk/
 │   ├── cli.py          scan / imap / graph / gmail / campaign / sweep / evidence / doctor / cache /
-│   │                   techniques / help
+│   │                   techniques / server / help
 │   ├── banner.py       start-up banner (_logo_art.py is generated from docs/images/logo.svg)
 │   ├── mailpolicy.py   the email parser, hardened against headers written to break it
 │   ├── parse.py        MIME walk, unwrapping, inline forwards, hidden text, the mail path
@@ -749,15 +758,20 @@
 │   ├── cache.py        SQLite TTL cache
 │   ├── enrich/         VirusTotal, urlscan.io, RDAP, AbuseIPDB
 │   ├── report/         console, HTML, JSON, STIX, MISP, Markdown, CSV; campaign and sweep output
-│   └── pipeline.py     parse → detect → enrich
+│   ├── pipeline.py     parse → detect → enrich
+│   ├── analysis.py     one message in, the analysis and every report format out (the web app's entry)
+│   └── server/         the web app (optional extra): API, pages, worker, encrypted store, audit log
 ├── tests/              643 offline tests: unit, security, fuzz-found regressions, Hypothesis properties,
 │                       and the evaluation gate
 ├── samples/            five inert sample emails and the script that makes them
 ├── eval/               labelled corpus, evaluation runner, real-corpus fetchers, results.json
 ├── tools/              scripts that draw the logo, banner, demo and charts in docs/images
-├── docs/               usage, detections, integrations and security review; the JSON Schema; images
+├── docs/               usage, the web app and your own frontend, detections, integrations and security
+│                       review; the JSON Schema;
+│                       the API description (api/openapi.json); images
 ├── install.sh          user-level installer (pipx or virtualenv)
-├── Dockerfile          non-root image
+├── Dockerfile          non-root image for the command line
+├── server.Dockerfile   the web app's image; compose.yaml runs it
 └── phishhawk           run-from-checkout launcher
 ```
 
````

Change `docs/USAGE.md` (apply with `git apply`, or edit by hand):

````diff
--- a/docs/USAGE.md
+++ b/docs/USAGE.md
@@ -42,6 +42,7 @@
   doctor       check dependencies, API keys, cache and network
   cache        show or clear the lookup cache
   techniques   list the MITRE ATT&CK techniques PhishHawk can evidence
+  server       run the web app (needs: pip install 'phishhawk[server]'); see docs/SERVER.md
   help         show help for a command
 ```
 
````

Change `CHANGELOG.md` (apply with `git apply`, or edit by hand):

```diff
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -9,6 +9,19 @@
 
 ### Added
 
+- **Web app, milestone 1 (preview).** `pip install "phishhawk[server]"` adds
+  `phishhawk server`: a web app and API for a small team on one machine. Log
+  in, upload or paste a reported message, see the verdict and the full HTML
+  report (sandboxed), and download all six formats and the manifest. Admin
+  and analyst roles, API tokens scoped to read or submit, provider settings
+  with encrypted keys (all off by default), AES-256-GCM encryption of every
+  stored message and report, 30-day retention with hold and deletion, a
+  hash-chained audit log with `phishhawk server audit verify`, key rotation,
+  `/healthz`, and a Docker image with a Compose file. A frontend of your own
+(for example from Google AI Studio) can be served from the same server at
+`/app/` ([docs/FRONTEND.md](docs/FRONTEND.md)). The command line is
+  unchanged; the base install still needs only `requests`. See
+  [docs/SERVER.md](docs/SERVER.md).
 - **HTML report: decisions first.** Each message opens with section links
   (plain anchors, no script), the verdict and why, whether the analysis was
   complete, whether reputation was checked and whether custody was
```

- [ ] **Step 2: Check the milestone**

Run the whole check, first with the server extra:

```bash
python -m pip install -e ".[dev,server]"
ruff check src tests samples eval tools phishhawk
mypy
coverage run -m pytest && coverage report
```

then without it, in a fresh virtualenv, as CI's base job does:

```bash
python -m venv /tmp/phishhawk-base && /tmp/phishhawk-base/bin/pip install -e ".[dev]"
/tmp/phishhawk-base/bin/mypy
/tmp/phishhawk-base/bin/coverage run -m pytest && /tmp/phishhawk-base/bin/coverage report --omit='*/phishhawk/server/*'
```

Expected: with the extra, `801 passed, 1 skipped` and total coverage 90%; without it, `693 passed, 1 skipped` and 90%. ruff and mypy report nothing.

Then tick off the spec's "done when" for M1, each against the test that proves it:

| Done when | Proved by |
|---|---|
| An analyst logs in, submits a bundled sample, sees the verdict and downloads all six formats | `test_serve.py`, `test_browser.py`, `test_api.py::test_submit_analyse_view_and_download`, and `tools/server_smoke.py` in the Compose job |
| The audit log verifies | `test_audit.py`, `test_server_cli.py::test_audit_verify_exits_1_after_tampering`, `audit verify` in the Compose job |
| A message past retention loses its tier 1 and keeps its tier 2 | `test_worker.py::test_the_sweep_deletes_tier1_after_the_retention_period_and_audits_the_count`, `test_processing.py::test_retention_deletes_tier1_keeps_tier2_and_skips_held_messages` |
| The hostile-payload test passes on every page | `test_hostile.py` |

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md README.md docs/FRONTEND.md docs/SERVER.md docs/USAGE.md
git commit -m "Document the web app for admins and record it in the changelog"
```

## Spec coverage

How each M1 requirement in the spec maps to the tasks above.

| Spec | Requirement | Task |
|---|---|---|
| 4 | Facade `analyze()` returning the analysis, JSON, six exports, manifest, summary, trait record, lookups | 1 |
| 4, 5.2 | Settings from the environment and secret files; keys required | 2 |
| 5.1 | Two tiers; no recipients, subject or body in tier 2; one message per SHA-256 | 3, 9 |
| 5.2 | AES-256-GCM, fresh nonce, blob ID as associated data; secrets sealed; trait key made once; key rotation; fail closed | 2, 4, 7, 10, 11 |
| 5.3 | Hourly retention sweep, delete now, delete completely, hold, all audited | 9, 11, 12 |
| 6.1 | Upload or paste, size and magic-byte checks, 202, worker in a limited child, tier 1 and 2 stored, page waits for the verdict, files served side by side | 9, 11, 12 |
| 6.5 | Job claim, heartbeat, no retry on input failures, requeue a dead worker's job at most twice, scheduler in the worker | 8, 9 |
| 7.2 | argon2id, throttle per user and address, `create-admin`, cookie flags, eight-hour idle timeout, CSRF, scoped tokens shown once, the role table | 6, 11, 12, 14 |
| 7.3 | CSP on every response, nosniff, no-referrer, HSTS over TLS, autoescape plus `printable()`, sandboxed report, attachments | 11, 12, 13 |
| 7.4 | Upload limits, resource limits, lookups recorded and shown | 1, 8, 9, 12 |
| 7.6 | Secrets only from the environment or files; the audited events; `audit verify` | 2, 5, 11, 14 |
| 8 | Login, submit, queue (verdict filter and search), analysis, settings, users, audit pages; light and dark; WCAG AA; keyboard | 12, 17 |
| 9 | `/api/v1` routes for M1, JSON errors, `/healthz`, `docs/api/openapi.json` with a test | 11, 13, 15 |
| 10 | Sanitised failure reasons, limits, health, backups documented | 9, 11, 18 |
| 11 (M1) | Docker image and Compose file | 16 |
| 12 | Role matrix, CSRF, session expiry, throttle, scopes, store, jobs, decompression bomb, duplicates, hostile payload on every page, CSP, sandbox, attachments, audit tampering, browser, performance, CI jobs | 2 to 17 |
| Owner | The main frontend built in Google AI Studio, served at `/app/` on the same origin, with its rules documented | 13, 18 |
