"""Your own YARA rules, run over the raw message and every file PhishHawk
opens, archive members and disk-image contents included.

Optional: needs `pip install 'phishhawk[yara]'` (yara-python). A rule's
meta can set `severity` (high, medium, low; default high), `description`
and `mitre` (technique IDs, comma-separated) for the signal it raises.
"""

from __future__ import annotations

import os
import re
from typing import Any

MATCH_TIMEOUT = 10  # seconds per scanned buffer
MAX_MATCHES = 50
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class YaraError(ValueError):
    pass


def _module():
    try:
        import yara  # noqa: PLC0415
    except ImportError:
        return None
    return yara


def available() -> bool:
    return _module() is not None


def version() -> str:
    module = _module()
    return getattr(module, "__version__", "") if module else ""


class Rules:
    """Compiled rules from a .yar/.yara file or a folder of them."""

    def __init__(self, path: str) -> None:
        module = _module()
        if module is None:
            raise YaraError("YARA rules need yara-python: pip install 'phishhawk[yara]'")
        if os.path.isdir(path):
            files = {os.path.splitext(name)[0]: os.path.join(path, name) for name in sorted(os.listdir(path))
                     if name.lower().endswith((".yar", ".yara")) and os.path.isfile(os.path.join(path, name))}
        elif os.path.isfile(path):
            files = {os.path.splitext(os.path.basename(path))[0]: path}
        else:
            raise YaraError("no YARA rules at %s" % path)
        if not files:
            raise YaraError("no .yar or .yara files in %s" % path)
        try:
            self.compiled = module.compile(filepaths=files)
        except module.Error as exc:
            raise YaraError("YARA rules do not compile: %s" % exc) from exc
        self.module = module
        self.path = path
        self.count = len(files)

    def match(self, data: bytes) -> list[dict[str, Any]]:
        try:
            matches = self.compiled.match(data=data, timeout=MATCH_TIMEOUT)
        except self.module.Error:  # a timeout or an internal error: no verdict from YARA
            return []
        out = []
        for match in matches[:MAX_MATCHES]:
            meta = {str(k).lower(): v for k, v in (match.meta or {}).items()}
            severity = str(meta.get("severity", "high")).lower()
            techniques = [t.strip().upper() for t in str(meta.get("mitre", meta.get("attack", ""))).split(",")]
            out.append({"rule": match.rule, "namespace": match.namespace,
                        "severity": severity if severity in ("high", "medium", "low") else "high",
                        "description": str(meta.get("description", ""))[:200],
                        "techniques": [t for t in techniques if _TECHNIQUE_RE.match(t)],
                        "tags": list(match.tags)[:10]})
        return out


def hook(rules: Rules):
    """A parse-time hook that runs the rules over every file opened."""
    def run(analysis, ioc, data: bytes) -> None:
        for match in rules.match(data):
            match["where"] = ioc.filename
            if len(analysis.yara) < MAX_MATCHES:
                analysis.yara.append(match)
    return run
