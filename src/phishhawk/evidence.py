"""Evidence: the exact bytes a report is about, kept so they can be shown
later to be unchanged.

Every report carries the SHA-256, SHA-1, MD5 and size of the bytes PhishHawk
was given (for a reported message, the report as it arrived, not the
original unwrapped from it). With --evidence DIR those bytes are also kept
in DIR, read-only and named by their SHA-256, and a line is appended to
DIR/custody.jsonl saying what was analysed, when, by whom and with what
verdict. Each line includes the hash of the line before it, so editing,
removing or reordering a record breaks the chain at that point, and
`phishhawk evidence verify DIR` finds it. The last link (the "head") is
printed by verify and written into the message's own report: copied into a
ticket, it pins the log as it was then, since someone able to rewrite the
whole file could also recompute every link after it.
"""

from __future__ import annotations

import datetime as dt
import getpass
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import __version__

if TYPE_CHECKING:
    from .models import Analysis

CUSTODY = "custody.jsonl"
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")  # an Outlook .msg
_FILE_RE = re.compile(r"^[0-9a-f]{64}\.(?:eml|msg)$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_TAIL = 1 << 16  # a custody line is far shorter than this


class EvidenceError(Exception):
    pass


def fingerprint(data: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(), "size": len(data)}


def _link(previous: str, record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "chain"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((previous + "\n" + canonical).encode("utf-8")).hexdigest()


def _analyst() -> str:
    name = os.environ.get("PHISHHAWK_ANALYST", "")
    if not name:
        try:
            name = getpass.getuser()
        except Exception:  # no login name on this system
            name = ""
    return name[:200]


def _open_regular(path: str) -> int:
    """A file descriptor for path, refusing a symlink or anything that is not
    a regular file (a FIFO planted there would hang the read)."""
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise EvidenceError("%s cannot be opened safely (%s)" % (path, exc.strerror or exc)) from exc
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise EvidenceError("%s is not a regular file" % path)
    return fd


def _hash_file(path: str) -> str:
    fd = _open_regular(path)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _store(directory: str, name: str, data: bytes, sha256: str) -> None:
    path = os.path.join(directory, name)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY, 0o400)
    except FileExistsError:
        # Seen before: keep the first copy, but only if it really is this message.
        if _hash_file(path) != sha256:
            raise EvidenceError("%s is already there and does not match the message's SHA-256" % path) from None
        return
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _last_chain(fd: int) -> str:
    size = os.fstat(fd).st_size
    if not size:
        return ""
    os.lseek(fd, max(0, size - _TAIL), os.SEEK_SET)
    lines = os.read(fd, _TAIL).decode("utf-8", "replace").splitlines()
    last = next((line for line in reversed(lines) if line.strip()), "")
    try:
        chain = json.loads(last).get("chain", "")
    except (ValueError, AttributeError):
        chain = ""
    if not isinstance(chain, str) or not re.fullmatch(r"[0-9a-f]{64}", chain):
        raise EvidenceError("the last line of the custody log is damaged: check it with "
                            "`phishhawk evidence verify`")
    return chain


def keep(directory: str, data: bytes, source: str, analysis: Analysis) -> dict[str, Any]:
    """Store data in directory and append its custody record; returns the record.
    The report's evidence block gains the file name and the record's chain value."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    prints = fingerprint(data)
    name = prints["sha256"] + (".msg" if data.startswith(OLE_MAGIC) else ".eml")
    _store(directory, name, data, prints["sha256"])
    record: dict[str, Any] = dict(prints, file=name, source=source,
                                  analysed_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  tool="PhishHawk %s" % __version__, verdict=analysis.verdict,
                                  score=analysis.score, analyst=_analyst())
    log = os.path.join(directory, CUSTODY)
    try:
        fd = os.open(log, os.O_RDWR | os.O_CREAT | os.O_APPEND | _NOFOLLOW | _BINARY, 0o600)
    except OSError as exc:
        raise EvidenceError("%s cannot be opened safely (%s)" % (log, exc.strerror or exc)) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise EvidenceError("%s is not a regular file" % log)
        try:
            import fcntl  # noqa: PLC0415 - POSIX only; elsewhere one writer at a time is assumed

            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:
            pass
        record["previous"] = _last_chain(fd)
        record["chain"] = _link(record["previous"], record)
        os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)  # closing releases the lock
    analysis.evidence.update(file=name, custody=record["chain"])
    return record


@dataclass
class Verification:
    records: int = 0
    head: str = ""
    problems: list[str] = field(default_factory=list)


def verify(directory: str) -> Verification:
    """Check every link of the custody log and every message it names."""
    result = Verification()
    log = os.path.join(directory, CUSTODY)
    if not os.path.isfile(log):
        result.problems.append("no custody log in %s" % directory)
        return result
    previous, checked = "", set()
    with open(log, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            result.records += 1
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError
            except ValueError:
                result.problems.append("record %d: not a valid record" % number)
                continue
            if record.get("previous") != previous:
                result.problems.append("record %d: does not follow the record before it (a record was "
                                       "changed, removed or reordered)" % number)
            if record.get("chain") != _link(str(record.get("previous", "")), record):
                result.problems.append("record %d: was changed after it was written" % number)
            previous = str(record.get("chain", ""))
            result.head = previous
            name = record.get("file")
            if not isinstance(name, str) or not _FILE_RE.match(name):
                result.problems.append("record %d: names no valid evidence file" % number)
                continue
            if name in checked:
                continue
            checked.add(name)
            path = os.path.join(directory, name)
            if not os.path.lexists(path):
                result.problems.append("record %d: evidence file %s is missing" % (number, name))
                continue
            try:
                actual = _hash_file(path)
            except EvidenceError as exc:
                result.problems.append("record %d: %s" % (number, exc))
                continue
            if actual != record.get("sha256") or not name.startswith(actual):
                result.problems.append("record %d: evidence file %s does not match its recorded SHA-256"
                                       % (number, name))
    return result
