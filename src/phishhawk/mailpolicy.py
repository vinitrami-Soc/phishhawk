"""The email policy every message is parsed with.

It is email.policy.default, hardened against headers written to break
CPython's header parser rather than to be read:

* Errors. Some hostile values raise instead of recording a defect: an
  RFC 2231 parameter whose charset name holds a NUL byte
  (filename*=utf\\x00-8''a.exe) or a byte that is not ASCII makes the codec
  lookup raise ValueError, inside message_from_bytes itself, and a charset
  naming a codec that cannot decode with errors="replace" ("idna",
  "undefined") does the same in get_filename(), get_boundary() and, for
  8-bit text, get_payload(). A header
  that will not parse is parsed again with its control characters and
  undecodable bytes removed, and kept as plain text if that fails too; an
  RFC 2231 filename or boundary in a charset that will not decode is read
  as UTF-8.
* Time. The structured-header parser is quadratic on some input: a To:
  header of 50,000 double quotes takes 49 s, and the library parses a header
  again every time it is read (a part's Content-Type is read dozens of
  times). Structured headers longer than any real one are kept as plain
  text, where their parameters are still read the old, linear way; parsed
  headers are cached; and a message is re-serialised with its headers as
  they arrived, which never parses them.

Either way a phishing mail could otherwise turn a verdict into an error or
stall a batch, so both are handled here, where every message is parsed.
"""

from __future__ import annotations

import re
from email.headerregistry import BaseHeader, UnstructuredHeader
from email.message import EmailMessage
from email.policy import EmailPolicy
from email.utils import unquote
from typing import Any

MAX_STRUCTURED = 4096  # a 120-recipient To: header; a real Content-Type is under 1 KB
MAX_PARSED = 64 * 1024  # longer headers of any kind are kept exactly as they arrived
CACHE_SIZE = 512
_UNSAFE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\udc80-\udcff]")
_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
_parsed: dict[tuple[str, str], Any] = {}


class RawHeader(BaseHeader):
    """A header kept as the text it arrived as, without parsing it."""

    max_count = None

    @classmethod
    def parse(cls, value: str, kwds: dict[str, Any]) -> None:
        kwds["parse_tree"] = None
        kwds["decoded"] = value


class TolerantMessage(EmailMessage):
    def _param_as_utf8(self, name: str, header: str) -> str | None:
        value = self.get_param(name, None, header)
        if isinstance(value, tuple):  # (charset, language, text)
            value = bytes(value[2], "raw-unicode-escape").decode("utf-8", errors="replace")
        return unquote(value) if isinstance(value, str) else None

    def get_filename(self, failobj: Any = None) -> Any:
        try:
            return super().get_filename(failobj)
        except (ValueError, LookupError):  # UnicodeError is a ValueError
            name = self._param_as_utf8("filename", "content-disposition") \
                or self._param_as_utf8("name", "content-type")
            return name.strip() if name else failobj

    def get_payload(self, i: Any = None, decode: Any = False) -> Any:
        try:
            return super().get_payload(i, decode)
        except (ValueError, LookupError):  # 8-bit text in a charset the codec lookup rejects
            payload = self._payload  # type: ignore[attr-defined]
            if isinstance(payload, str):
                return payload.encode("ascii", "surrogateescape").decode("utf-8", errors="replace")
            raise

    def get_boundary(self, failobj: Any = None) -> Any:
        try:
            return super().get_boundary(failobj)
        except (ValueError, LookupError):
            boundary = self._param_as_utf8("boundary", "content-type")
            return boundary.rstrip() if boundary else failobj


class TolerantPolicy(EmailPolicy):
    # A message is written back out only to hash or reread it, so a header
    # that came from the source goes out as it came in. Refolding it is worse
    # than pointless: Python's folder never finds a split point for a MIME
    # parameter whose name is longer than a line (_fold_mime_parameters loops
    # for ever), and recent patch releases refold every non-ASCII header even
    # with refold_source="none".
    def fold(self, name: str, value: Any) -> str:
        if hasattr(value, "name"):  # a header object set by code, not read from a message
            return super().fold(name, value)
        return name + ": " + self.linesep.join(_LINE_BREAK_RE.split(value)) + self.linesep

    def fold_binary(self, name: str, value: Any) -> bytes:
        if hasattr(value, "name"):
            return super().fold_binary(name, value)
        return self.fold(name, value).encode("utf-8", "surrogateescape")

    def header_fetch_parse(self, name: str, value: str) -> Any:
        if hasattr(value, "name"):  # already a header object
            return value
        value = _LINE_BREAK_RE.sub("", value)  # unfold, as the library does
        key = (name.lower(), value)
        header = _parsed.get(key)
        if header is None:
            header = self._parse(name, value)
            if len(_parsed) >= CACHE_SIZE:
                _parsed.clear()
            _parsed[key] = header
        return header

    def _parse(self, name: str, value: str) -> Any:
        registry: Any = self.header_factory  # a HeaderRegistry, typed as a plain callable
        structured = not issubclass(registry[name], UnstructuredHeader)
        if len(value) > MAX_PARSED or (structured and len(value) > MAX_STRUCTURED):
            return RawHeader(name, value)
        try:
            return registry(name, value)
        except Exception:
            cleaned = _UNSAFE_RE.sub("", value)
        try:
            return registry(name, cleaned)
        except Exception:
            return RawHeader(name, cleaned)


# refold_source="none": a message written back out (to hash an attached email,
# say) keeps its headers byte for byte instead of parsing them to refold them.
POLICY = TolerantPolicy(message_factory=TolerantMessage, refold_source="none")
