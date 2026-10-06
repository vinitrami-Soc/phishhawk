"""Turn raw .eml bytes into an Analysis: headers, bodies, URLs, attachments.

Three things real SOC mailboxes need that a naive parser misses:

* Users report phish by forwarding it *as an attachment*. The message worth
  triaging is the attached one, not the colleague's covering note, so
  attached messages are unwrapped (up to three layers) and the reporter is
  recorded separately.
* Payloads hide one level down: a ZIP holding a .js, a macro-enabled .docx,
  an HTML attachment that builds its payload in JavaScript. Archives are
  listed and hashed without ever being written to disk, OOXML files are
  checked for VBA projects, HTML attachments are parsed for credential
  forms, redirects, smuggling code and base64 strings that decode to URLs.
* Extensions lie. Every file is typed by its magic bytes.
"""

from __future__ import annotations

import base64
import binascii
import email
import email.header
import email.parser
import email.policy
import email.utils
import html as html_module
import re
from collections.abc import Callable, Iterator
from email.message import Message
from typing import Any

from . import qr as qrcodes
from .attachments import Inspector, file_ioc, password_candidates
from .extract import (
    EMAIL_RE,
    IPV4_RE,
    PRIVATE_IP_RE,
    ZERO_WIDTH_RE,
    clean_url,
    defang_text,
    domain_of_address,
    host_of,
    parse_html,
    refang,
    registrable_domain,
    unwrap_link,
    urls_from_text,
    usable_url,
)
from .formats.msg import MsgError, is_msg, msg_to_message
from .indicators import find_wallets
from .knowledge import FREEMAIL, FREEMAIL_LABELS, is_reserved_domain
from .mailpolicy import POLICY
from .models import MIME_TOO_DEEP, Analysis, FileIoc, UrlIoc

MAX_UNWRAP_DEPTH = 3
MAX_URLS = 1000  # distinct links kept per message; the rest are counted
MAX_URL_CONTEXTS = 20  # sources and anchor texts kept per link
MAX_RECEIVED = 1000
MAX_ATTACHED_TEXT = 2_000_000  # characters read from each body of an attached email
BODY_TEXT_LIMIT = 30_000  # characters of visible text kept for lure matching
_FORWARD_SUBJECT = re.compile(r"^\s*(?:fwd?|fw|enc|rv|wg|tr|i)\s*:", re.I)
# "From: X <a@b> Sent: ..." in the forwarding languages SOC mailboxes see most.
_INLINE_FROM = re.compile(
    r"(?:^|\s)(?:From|De|Von|Da|Van|Från)\s*:\s*(?P<sender>[^:]{3,200}?)\s+"
    r"(?:Sent|Date|Enviado|Enviada|Gesendet|Envoy[ée]|Fecha|Data|Datum|Inviato|Skickat)\s*:", re.I)
SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "data:", "#", "javascript:", "blob:", "about:")
_EVENT_HANDLER_RE = re.compile(r"<[a-z][^>]{0,500}\son(?:load|error|begin|end|click|mouseover|focus)\s*=", re.I)
_ATOB_RE = re.compile(r"""atob\(\s*['"]([A-Za-z0-9+/=\s]{8,})['"]\s*\)""")
_DATA_IMAGE_RE = re.compile(r"^data:image/[a-z0-9.+-]{2,20};base64,", re.I)
MAX_DATA_IMAGE_BYTES = 5 * 1024 * 1024
MAX_QR_IMAGES = 40  # images decoded per message; a newsletter can carry hundreds
_HTML_LINE_BREAK_RE = re.compile(r"<\s*(?:br|/p|/div|/tr|/pre|/li|/h[1-6])\b[^>]{0,200}>", re.I)
_HTML_TAG_RE = re.compile(r"<[^<>]{0,2000}>")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def load_message(data: bytes) -> Message:
    """An .eml, or an Outlook .msg rebuilt as the .eml it was sent as."""
    if is_msg(data):
        try:
            return msg_to_message(data)
        except (MsgError, ValueError, LookupError, RecursionError):
            pass  # a damaged .msg: whatever the email parser makes of it
    try:
        return email.message_from_bytes(data, policy=POLICY)
    except RecursionError:
        return _flattened(data)


def _flattened(data: bytes) -> Message:
    """MIME nested deeper than Python's parser can follow (about a thousand
    levels, which no mail client writes, and which would otherwise hide the
    whole body): the headers, with the entire body read as plain text so its
    links still count."""
    message = email.parser.BytesParser(policy=POLICY).parsebytes(data, headersonly=True)
    body = message.get_payload()
    for name in ("Content-Type", "Content-Transfer-Encoding"):
        del message[name]
    message["Content-Type"] = "text/plain; charset=utf-8"
    message.set_payload(body if isinstance(body, str) else "")
    message.__dict__["_flattened"] = True
    return message


def parse_file(path: str, unwrap: bool = True, protected: list[str] | tuple = (),
               auto_protect: bool = True, qr: bool = True, trusted_authserv: tuple[str, ...] = ()) -> Analysis:
    with open(path, "rb") as handle:
        data = handle.read()
    return parse_bytes(data, path=path, unwrap=unwrap, protected=protected,
                       auto_protect=auto_protect, qr=qr, trusted_authserv=trusted_authserv)


def parse_bytes(data: bytes, path: str = "<memory>", unwrap: bool = True,
                protected: list[str] | tuple = (), auto_protect: bool = True,
                qr: bool = True, trusted_authserv: tuple[str, ...] = ()) -> Analysis:
    return parse_message(load_message(data), path=path, unwrap=unwrap, protected=protected,
                         auto_protect=auto_protect, qr=qr, trusted_authserv=trusted_authserv)


def parse_message(message: Message, path: str = "<memory>", unwrap: bool = True,
                  protected: list[str] | tuple = (), auto_protect: bool = True,
                  qr: bool = True, trusted_authserv: tuple[str, ...] = (),
                  file_hook: Callable[[Analysis, FileIoc, bytes], None] | None = None,
                  open_attached: bool | None = None) -> Analysis:
    """`open_attached`: also check the links and files of attached emails
    that are not unwrapped (by default, whenever unwrapping is on: with it
    off, the covering note alone is analysed)."""
    analysis = Analysis(path=path)
    carriers: list[Message] = []
    if unwrap:
        message, carriers = _unwrap(message, analysis)
    _read_headers(message, analysis, tuple(t.lower() for t in trusted_authserv))
    _read_content(message, analysis, qr, file_hook, unwrap if open_attached is None else open_attached)
    analysis.protected_domains = _protected_domains(message, analysis, protected, auto_protect)
    analysis.__dict__["_carriers"] = carriers  # the unwrapped layers, re-checked by the pipeline; not exported
    return analysis


# ---------------------------------------------------------------------------
# MIME helpers
# ---------------------------------------------------------------------------

def header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        return ""
    if value is None:
        return ""
    try:
        return " ".join(str(value).split())
    except Exception:
        return ""


def _walk_shallow(msg: Message) -> Iterator[Message]:
    """Message.walk() that does not descend into attached messages, without
    recursion: MIME can be nested hundreds of levels deep."""
    for part, _ in _walk_with_depth(msg):
        yield part


def _walk_with_depth(msg: Message) -> Iterator[tuple[Message, int]]:
    stack = [(msg, 0)]
    while stack:
        part, depth = stack.pop()
        yield part, depth
        if part.get_content_maintype() == "multipart":
            payload = part.get_payload()
            if isinstance(payload, list):
                stack.extend((child, depth + 1) for child in reversed(payload) if isinstance(child, Message))


def mime_depth(msg: Message) -> int:
    if msg.__dict__.get("_flattened"):
        return MIME_TOO_DEEP
    return max((depth for _, depth in _walk_with_depth(msg)), default=0)


MAX_ADDRESS_COLONS = 100  # email.utils recurses once per ':'; real address headers hold a handful


def _parseaddr(value: str) -> tuple[str, str]:
    """email.utils.parseaddr, which recursed once per ':' in the value: a
    From: header with a few thousand colons raised RecursionError."""
    if (value or "").count(":") <= MAX_ADDRESS_COLONS:
        try:
            return email.utils.parseaddr(value)
        except (RecursionError, ValueError):
            pass
    match = EMAIL_RE.search(value or "")
    if not match:
        return "", ""
    return " ".join(value[:match.start()].replace("<", " ").replace('"', " ").split())[:200], match.group(0)


def _getaddresses(value: str) -> list[tuple[str, str]]:
    if (value or "").count(":") <= MAX_ADDRESS_COLONS:
        try:
            return email.utils.getaddresses([value])
        except (RecursionError, ValueError):
            pass
    return [("", address) for address in EMAIL_RE.findall(value or "")[:500]]


def _decode_text(part: Message) -> str:
    getter = getattr(part, "get_content", None)  # EmailMessage; compat32 parts lack it
    if getter is not None:
        try:
            content = getter()
            if isinstance(content, str):
                return content
        except Exception:
            pass
    payload = _part_bytes(part)
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):  # unknown charset, or a name with a NUL in it
        return payload.decode("utf-8", errors="replace")


def _part_bytes(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if isinstance(payload, bytes) and payload:
        return payload
    if part.get_content_type() == "message/rfc822":
        inner = _rfc822_payload(part)
        if inner is not None:
            try:
                return inner.as_bytes()
            except Exception:
                return b""
    try:
        return part.as_bytes()
    except Exception:
        return b""


def _rfc822_payload(part: Message) -> Message | None:
    payload = part.get_payload()
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        return payload[0]
    if isinstance(payload, Message):
        return payload
    try:
        raw = part.get_payload(decode=True)
    except Exception:
        raw = None
    return load_message(raw) if isinstance(raw, bytes) and raw else None


def _attached_messages(msg: Message) -> list[tuple[Message, Message]]:
    """(part, message) for every email attached to `msg`."""
    if msg.get_content_type() == "message/rfc822":  # the whole message is another message
        inner = _rfc822_payload(msg)
        return [(msg, inner)] if inner is not None else []
    found = []
    for part in _walk_shallow(msg):
        if part is msg:
            continue
        name = (part.get_filename() or "").lower()
        if part.get_content_type() == "message/rfc822":
            inner = _rfc822_payload(part)
        elif name.endswith((".eml", ".msg")) or part.get_content_type() == "application/vnd.ms-outlook":
            data = _part_bytes(part)  # Outlook reports phish as an attached .msg
            inner = load_message(data) if data else None
        else:
            continue
        if inner is not None and (inner.get("From") or inner.get("Subject")):
            found.append((part, inner))
    return found


def _unwrap(msg: Message, analysis: Analysis) -> tuple[Message, list[Message]]:
    layers: list[dict[str, Any]] = []
    carriers: list[Message] = []
    while len(layers) < MAX_UNWRAP_DEPTH:
        attached = _attached_messages(msg)
        if not attached:
            break
        display, address = _parseaddr(header(msg, "From"))
        layers.append({"from": address.lower(), "display": display,
                       "subject": header(msg, "Subject"), "date": header(msg, "Date"),
                       "attached_messages": len(attached)})
        carriers.append(msg)
        part, inner = attached[0]
        msg.__dict__["_unwrapped_part"] = part  # the carrier's re-check leaves this one alone
        msg = inner
    if layers:
        analysis.reported_by = dict(layers[0], layers=len(layers))
    return msg, carriers


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

_AUTH_MECHANISMS = ("spf", "dkim", "dmarc", "compauth")
_AUTH_HEADERS = ("authentication-results", "received-spf")
MAX_FORGED = 20
MAX_CHECKS = 20
_COMMENT_RE = re.compile(r"\([^()]*\)")
_CHECK_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)  # matched at a clause's start, stripped
# The identity each check vouched for (RFC 8601): SPF the envelope sender,
# DKIM the signing domain (or the agent identity), DMARC the From domain.
_CHECK_PROPERTIES = {"spf": ("smtp.mailfrom", "smtp.helo"), "dkim": ("header.d", "header.i"),
                     "dmarc": ("header.from",)}
_RECEIVED_SPF_DOMAIN_RE = re.compile(r'envelope-from\s*=\s*"?([^\s;"]{1,320})|domain of\s+(\S{1,320})\s+'
                                     r"(?:designates|does not designate)", re.I)
_CHECK_DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


def _header_text(msg: Message, name: str, value: str) -> str:
    try:
        text = str(msg.policy.header_fetch_parse(name, value))
    except Exception:
        try:
            text = str(email.header.make_header(email.header.decode_header(value)))
        except Exception:
            text = str(value)
    return " ".join(text.split())


def _authserv_id(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _check_domain(value: str) -> str:
    value = value.strip().strip('"<>').rsplit("@", 1)[-1].lower().rstrip(".")
    return value if len(value) <= 253 and _CHECK_DOMAIN_RE.fullmatch(value) else ""


def _auth_checks(values: list[str]) -> list[dict[str, str]]:
    """Every SPF, DKIM and DMARC result in the receiver's headers, with the
    domain it is about. Comments are dropped first: Gmail's "(domain of
    x@y designates ...)" is prose, not the identity that was checked."""
    checks: list[dict[str, str]] = []
    for value in values:
        text = value
        for _ in range(4):  # comments can nest
            text = _COMMENT_RE.sub(" ", text)
        clauses = [clause.lstrip() for clause in text.split(";")]
        if clauses and not _CHECK_RE.match(clauses[0]):
            clauses = clauses[1:]  # the authserv-id (Exchange Online writes none)
        for clause in clauses:
            match = _CHECK_RE.match(clause)
            if not match:
                continue
            method, domain = match.group(1).lower(), ""
            for name in _CHECK_PROPERTIES[method]:
                found = re.search(r"\b%s\s*=\s*([^\s;]+)" % re.escape(name), clause, re.I)
                if found:
                    domain = _check_domain(found.group(1))
                    break
            checks.append({"method": method, "result": match.group(2).lower(), "domain": domain})
            if len(checks) >= MAX_CHECKS:
                return checks
    return checks


def _auth_results(msg: Message, trusted: tuple[str, ...] = ()
                  ) -> tuple[dict[str, str], list[dict[str, Any]], list[dict[str, str]]]:
    """SPF/DKIM/DMARC results from the receiving server, any claims that were
    forged below them, and each of the receiver's checks with its domain.

    Only the block of Authentication-Results headers at the top is trusted:
    the receiving server writes it, one header or (ProtonMail) one per check,
    all under its own authserv-id. A header further down was written by the
    sender, and "dmarc=pass" is what an attacker writes there. With
    ``trusted`` authserv-ids, only headers from those servers count at all.
    """
    # Headers are decoded one at a time: one malformed header elsewhere in the
    # message (a phisher's trick or plain sloppiness) must not wipe out the
    # results, and Microsoft 365 base64-encodes them (=?utf-8?B?...?=).
    try:  # only the headers read below are decoded; a message can carry thousands of others
        items = [(str(name).lower(), _header_text(msg, name, value) if str(name).lower() in _AUTH_HEADERS else "")
                 for name, value in msg.raw_items()]
    except Exception:
        items = []
    positions = [i for i, (name, _) in enumerate(items) if name == "authentication-results"]
    trusted_block: list[int] = []
    if trusted:
        trusted_block = [i for i in positions if _authserv_id(items[i][1]) in trusted]
    elif positions:
        first = positions[0]
        trusted_block = [first]
        for i in positions[1:]:
            if i == trusted_block[-1] + 1 and _authserv_id(items[i][1]) == _authserv_id(items[first][1]):
                trusted_block.append(i)
    results: dict[str, str] = {}
    for i in trusted_block:
        for mechanism in _AUTH_MECHANISMS:
            if mechanism not in results:
                match = re.search(r"\b%s\s*=\s*([a-z]+)" % mechanism, items[i][1], re.I)
                if match:
                    results[mechanism] = match.group(1).lower()
    receiver = _authserv_id(items[trusted_block[0]][1]) if trusted_block else ""
    forged: list[dict[str, Any]] = []
    in_block = set(trusted_block)
    for i in positions:
        if i in in_block:
            continue
        if len(forged) >= MAX_FORGED:
            break
        for mechanism in _AUTH_MECHANISMS[:3]:
            if re.search(r"\b%s\s*=\s*pass\b" % mechanism, items[i][1], re.I) and \
                    results.get(mechanism) != "pass":
                server = _authserv_id(items[i][1])
                forged.append({"claim": "%s=pass" % mechanism, "authserv": server[:80],
                               "impersonates": bool(receiver) and server == receiver})
    received_spf: dict[str, str] = {}
    if "spf" not in results:
        # Only the topmost Received-SPF, and only if it sits by the trusted block.
        near = trusted_block[0] if trusted_block else None
        for i, (name, value) in enumerate(items):
            if name == "received-spf" and value:
                if near is None or abs(i - near) <= 3:
                    results["spf"] = value.split()[0].lower().strip(";")
                    found = _RECEIVED_SPF_DOMAIN_RE.search(value)
                    received_spf = {"method": "spf", "result": results["spf"],
                                    "domain": _check_domain(next(g for g in found.groups() if g)) if found else ""}
                break
    checks = _auth_checks([items[i][1] for i in trusted_block])
    if received_spf and not any(check["method"] == "spf" for check in checks):
        checks.insert(0, received_spf)
    return results, forged, checks[:MAX_CHECKS]


def _received(msg: Message) -> list[str]:
    """The Received headers, newest first, unfolded but not parsed: a
    message can carry thousands, and the library parses each on every read."""
    try:
        items = msg.raw_items() if hasattr(msg, "raw_items") else msg.items()
        return [" ".join(str(value).encode("utf-8", "surrogateescape").decode("utf-8", "replace").split())
                for name, value in items if name.lower() == "received"]
    except Exception:
        return []


def _originating_ip(msg: Message, received: list[str]) -> str:
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        for candidate in IPV4_RE.findall(header(msg, name)):
            if not PRIVATE_IP_RE.match(candidate):
                return candidate
    for value in reversed(received[:MAX_RECEIVED]):  # newest-first, so the origin is last
        for candidate in IPV4_RE.findall(value):
            if not PRIVATE_IP_RE.match(candidate):
                return candidate
    return ""


_HOP_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]{1,120})", re.I)
_HOP_BY_RE = re.compile(r"\bby\s+([^\s;()]{1,120})", re.I)
_HOP_WITH_RE = re.compile(r"\bwith\s+([^\s;()]{1,40})", re.I)
_HOP_IP_RE = re.compile(r"\[((?:\d{1,3}\.){3}\d{1,3}|(?:IPv6:)?[0-9A-Fa-f:]{2,39})\]")
MAX_HOPS = 30


def _hops(received: list[str]) -> list[dict[str, Any]]:
    """The Received chain, oldest hop first: who handed the message to whom,
    when, and how long each step took."""
    hops: list[dict[str, Any]] = []
    previous = None
    for value in reversed(received[:MAX_HOPS]):
        head, _, stamp = value.rpartition(";")
        head = head or value
        when = None
        try:
            when = email.utils.parsedate_to_datetime(stamp.strip()) if stamp.strip() else None
            if when is not None and when.tzinfo is None:
                when = None
        except (TypeError, ValueError, IndexError, OverflowError):  # a year too large for C: OverflowError
            when = None
        hop: dict[str, Any] = {}
        for key, pattern in (("from", _HOP_FROM_RE), ("by", _HOP_BY_RE), ("with", _HOP_WITH_RE),
                             ("ip", _HOP_IP_RE)):
            match = pattern.search(head)
            if match:
                hop[key] = match.group(1).removeprefix("IPv6:")[:120]
        hop["time"] = when.isoformat() if when else ""
        if when is not None and previous is not None:
            hop["delay_seconds"] = int((when - previous).total_seconds())
        if when is not None:
            previous = when
        hops.append(hop)
    return hops


# Headers only a list server adds. List-Id and List-Unsubscribe are left out on
# purpose: every bulk-mail service sets them, including the ones phishers rent.
_LIST_HEADERS = ("List-Post", "Mailing-List", "X-Mailing-List", "X-BeenThere")


def _mailing_list(msg: Message) -> tuple[bool, list[str]]:
    """Is this a mailing-list delivery, and which domains does the list live on?
    A list sets Reply-To to itself, which otherwise looks like reply diversion."""
    precedence = header(msg, "Precedence").strip().lower()  # "bulk" is every newsletter's
    if not (any(header(msg, name) for name in _LIST_HEADERS) or precedence == "list"):
        return False, []
    domains: set[str] = set()
    for name in _LIST_HEADERS:
        for address in EMAIL_RE.findall(header(msg, name)):
            domains.add(registrable_domain(domain_of_address(address)))
    list_id = re.search(r"<([^<>\s]+)>", header(msg, "List-Id"))
    if list_id and "." in list_id.group(1):
        domains.add(registrable_domain(list_id.group(1)))
    return True, sorted(d for d in domains if d)


# One whitespace run between the quote and the end: two in a row split a long
# run of spaces every possible way before failing.
_QUOTED_ADDRESS_RE = re.compile(r'"([^"]{0,200}@[^"]{0,200})"\s*(?:@\s*([^\s@<>"]{1,255})\s*)?$')


def _read_headers(msg: Message, analysis: Analysis, trusted_authserv: tuple[str, ...] = ()) -> None:
    analysis.subject = header(msg, "Subject")
    analysis.date = header(msg, "Date")
    analysis.message_id = header(msg, "Message-ID")
    analysis.to = header(msg, "To")

    display, address = _parseaddr(header(msg, "From"))
    analysis.from_display = display
    analysis.from_address = address.strip("\"' ").lower()
    analysis.from_domain = domain_of_address(address)
    # <"service@adac.de"> is one quoted local part with no domain at all, and
    # "a@b.de"@evil.top sends from evil.top: both show a mail client an
    # address no server ever checked.
    quoted = _QUOTED_ADDRESS_RE.match(address.strip())
    if quoted:
        analysis.__dict__["_quoted_from"] = (quoted.group(1).lower(), (quoted.group(2) or "").lower())

    _, reply_to = _parseaddr(header(msg, "Reply-To"))
    analysis.reply_to = reply_to.lower()
    analysis.reply_to_domain = domain_of_address(reply_to)

    _, return_path = _parseaddr(header(msg, "Return-Path"))
    analysis.return_path = return_path.lower()
    analysis.return_path_domain = domain_of_address(return_path)

    analysis.mailing_list, analysis.list_domains = _mailing_list(msg)
    analysis.auth, analysis.forged_auth, analysis.auth_checks = _auth_results(msg, trusted_authserv)
    received = _received(msg)
    analysis.originating_ip = _originating_ip(msg, received)
    analysis.hops = _hops(received)
    analysis.received_hops = len(received)


def _protected_domains(msg: Message, analysis: Analysis, explicit, auto: bool) -> list[str]:
    """Your organisation's domains: never looked up externally, and the
    reference set for business-email-compromise lookalike checks."""
    domains: list[str] = []

    def add(domain: str, guessed: bool = False) -> None:
        base = registrable_domain(domain)
        if not base or base in FREEMAIL or base in domains:
            return
        # A guess from the recipients: yahoo.com.tw is free mail, and a
        # documentation domain (example.net) belongs to nobody.
        if guessed and (base.split(".", 1)[0] in FREEMAIL_LABELS or is_reserved_domain(base)):
            return
        domains.append(base)

    for domain in explicit:
        add(domain.strip().lower())
    if auto:
        for name in ("To", "Cc", "Delivered-To"):
            for _, address in _getaddresses(header(msg, name)):
                add(domain_of_address(address), guessed=True)
        if analysis.reported_by:
            add(domain_of_address(analysis.reported_by.get("from", "")), guessed=True)
    return domains


# ---------------------------------------------------------------------------
# Bodies and URLs
# ---------------------------------------------------------------------------

_SCRIPT_LINK_RE = re.compile(r"^\s*(?:javascript:(?!\s*(?:void\s*\(\s*0?\s*\)|;|$|return\s+false))"
                             r"|data:\s*(?:text/html|application/xhtml|image/svg|text/javascript))", re.I)


def _add_url(bucket: dict[str, UrlIoc], raw: str, source: str, anchor: str = "",
             analysis: Analysis | None = None) -> None:
    if not raw:
        return
    if raw.lower().startswith(SKIP_SCHEMES):
        # A link that runs script or opens a page built from the link itself
        # never reaches a URL filter; mail from real senders does not use them.
        if analysis is not None and _SCRIPT_LINK_RE.match(raw) and len(analysis.script_links) < 20:
            kind = raw.strip()[:40].split(",", 1)[0].split(";", 1)[0]
            analysis.script_links.append({"where": source, "kind": kind.lower(), "size": len(raw)})
        return
    url = clean_url(refang(raw))
    if not usable_url(url):
        return
    for _ in range(3):  # Safe Links around a Google redirect around the payload, and so on
        wrapped = unwrap_link(url)
        if wrapped is None:
            break
        inner, who, kind = wrapped
        if kind == "gateway":
            # A mail-security rewrite: analyse what the sender actually sent.
            source = "%s via %s" % (source, who)
        else:
            outer = _record(bucket, url, source, anchor)
            outer.redirect_to, outer.wrapped_by = inner, who
            source, anchor = "redirect target (%s)" % who, ""
        url = inner
    _record(bucket, url, source, anchor)


class UrlBucket(dict):
    """The links of one message, by normalised URL. Past MAX_URLS new links
    are counted, not kept: 20,000 links took 14 s to check and made a 19 MB
    report, and a flood of links is itself worth a signal."""

    def __init__(self) -> None:
        super().__init__()
        self.dropped = 0


def _record(bucket: dict[str, UrlIoc], url: str, source: str, anchor: str = "") -> UrlIoc:
    key = url.rstrip("/").lower()
    ioc = bucket.get(key)
    if ioc is None:
        host = host_of(url)
        ioc = UrlIoc(url=url, host=host, domain=registrable_domain(host))
        if len(bucket) >= MAX_URLS and isinstance(bucket, UrlBucket):
            bucket.dropped += 1
            return ioc  # checked by nobody: not in the bucket
        bucket[key] = ioc
    if source not in ioc.sources and len(ioc.sources) < MAX_URL_CONTEXTS:
        ioc.sources.append(source)
    anchor = " ".join((anchor or "").split())[:500]
    if anchor and anchor not in ioc.anchor_texts and len(ioc.anchor_texts) < MAX_URL_CONTEXTS:
        ioc.anchor_texts.append(anchor)
    return ioc


def _collect(msg: Message) -> tuple[list[str], list[str], list[Message], list[Message], list[str]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Message] = []
    images: list[Message] = []  # nameless inline images: only looked at for QR codes
    calendars: list[str] = []  # meeting invitations sent as a body part
    for part in _walk_shallow(msg):
        content_type = (part.get_content_type() or "").lower()
        if content_type == "message/rfc822":
            if part is not msg:
                attachments.append(part)
            continue
        if part.get_content_maintype() == "multipart":
            if isinstance(part.get_payload(), str):  # no usable boundary: a mail client shows it as text
                text_parts.append(_decode_text(part))
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and content_type not in ("text/plain", "text/html")):
            attachments.append(part)
        elif content_type == "text/plain":
            text_parts.append(_decode_text(part))
        elif content_type == "text/html":
            html_parts.append(_decode_text(part))
        elif content_type == "text/calendar":
            calendars.append(_decode_text(part))
        elif part.get_content_maintype() == "image":
            images.append(part)
    return text_parts, html_parts, attachments, images, calendars


def _harvest_html(html: str, bucket: dict[str, UrlIoc], prefix: str, analysis: Analysis | None = None) -> Any:
    found = parse_html(html)
    for href, anchor in found.anchors:
        _add_url(bucket, href, prefix + "href", anchor, analysis)
    for resource in found.resources:
        _add_url(bucket, resource, prefix + "resource")
    for redirect in found.redirects:
        _add_url(bucket, redirect, prefix + "redirect")
    for form in found.forms:
        _add_url(bucket, form["action"], prefix + "form-action")
    for url in urls_from_text(found.text):
        _add_url(bucket, url, prefix + "text")
    return found


class _QrScan:
    """Finds QR codes for one message and turns their links into URL IOCs."""

    def __init__(self, analysis: Analysis, bucket: dict[str, UrlIoc], enabled: bool) -> None:
        self.analysis, self.bucket = analysis, bucket
        self.enabled = enabled and qrcodes.available()
        self.images_left = MAX_QR_IMAGES

    def _record(self, payloads: list[str], where: str, ioc: FileIoc | None = None) -> list[str]:
        for payload in payloads:
            url = _qr_url(payload)
            self.analysis.qr_codes.append({"where": where, "payload": payload[:500], "url": url})
            if url:
                _add_url(self.bucket, url, "qr-code in %s" % where)
            if ioc is not None:
                ioc.notes.append("QR code: %s" % defang_text(payload[:200]))
        return payloads

    def image(self, data: bytes, where: str, ioc: FileIoc | None = None) -> list[str]:
        if not self.enabled or self.images_left <= 0:
            return []
        self.images_left -= 1
        return self._record(qrcodes.decode_image(data), where, ioc)

    def pdf(self, data: bytes, where: str, ioc: FileIoc) -> None:
        if self.enabled and self.images_left > 0:
            self.images_left -= 1
            self._record(qrcodes.decode_pdf(data), where, ioc)

    def html(self, found: Any, html: str, where: str) -> None:
        if not self.enabled:
            return
        for resource in found.resources:
            if _DATA_IMAGE_RE.match(resource) and len(resource) < MAX_DATA_IMAGE_BYTES * 4 // 3:
                try:
                    data = base64.b64decode("".join(resource.split(",", 1)[1].split()), validate=False)
                except (binascii.Error, ValueError):
                    continue
                self.image(data, "an image embedded in %s" % where)
        for grid in found.cell_grids[:5]:
            self._record(qrcodes.decode_grid(grid), "a table drawn in %s" % where)
        if "\u2580" in html or "\u2584" in html or "\u2588" in html:
            lines = _HTML_TAG_RE.sub("", _HTML_LINE_BREAK_RE.sub("\n", html[:500_000]))
            self.text(html_module.unescape(lines), where)

    def text(self, text: str, where: str = "the message text") -> None:
        if self.enabled:
            self._record(qrcodes.decode_text_blocks(text[:500_000]), "block characters in %s" % where)


def _qr_url(payload: str) -> str:
    """The link a QR payload leads to. Codes often use upper case, which the
    compact alphanumeric QR mode requires: HTTPS://EVIL.TOP/X."""
    text = payload.strip()
    match = re.match(r"(?i)^(https?://|www\.)([^/?#\s]+)(\S*)$", text)
    if match:
        scheme = match.group(1).lower()
        if scheme == "www.":
            return "https://www." + match.group(2).lower() + match.group(3)
        return scheme + match.group(2).lower() + match.group(3)
    found = urls_from_text(text)
    return found[0] if found else ""


HIDDEN_FILLER_LETTERS = 300  # hidden letters before hidden text counts as filler
_WORDS_RE = re.compile(r"[^\W\d_]{4,}")


def _hidden_filler(visible: str, hidden: str) -> tuple[int, str]:
    """(letters, sample) of hidden text that does not repeat the visible text.
    Newsletters hide a short preview line, and responsive layouts hide a copy
    of what is shown; filler meant for spam filters is long and different."""
    letters = sum(ch.isalpha() for ch in hidden)
    if letters < HIDDEN_FILLER_LETTERS:
        return 0, ""
    seen = {w.lower() for w in _WORDS_RE.findall(visible)}
    words = [w.lower() for w in _WORDS_RE.findall(hidden)]
    if not words or sum(1 for w in words if w not in seen) / len(words) < 0.6:
        return 0, ""
    return letters, " ".join(hidden.split())[:80]


def _read_content(msg: Message, analysis: Analysis, qr: bool = True,
                  file_hook: Callable[[Analysis, FileIoc, bytes], None] | None = None,
                  open_attached: bool = True) -> None:
    text_parts, html_parts, attachment_parts, image_parts, calendar_parts = _collect(msg)
    analysis.mime_depth = mime_depth(msg)
    bucket = UrlBucket()
    scan = _QrScan(analysis, bucket, qr)

    for body in text_parts:
        for url in urls_from_text(body):
            _add_url(bucket, url, "body-text")
        scan.text(body)
    html_found = []
    for body in html_parts:
        found = _harvest_html(body, bucket, "html-", analysis)
        html_found.append(found)
        scan.html(found, body, "the HTML body")
    for name in ("List-Unsubscribe", "X-Originating-URL"):
        for url in urls_from_text(header(msg, name)):
            _add_url(bucket, url, "header:%s" % name)

    all_html_text = [found.text for found in html_found]
    analysis.zero_width_chars = sum(len(ZERO_WIDTH_RE.findall(t)) for t in text_parts + all_html_text)
    # The text as the reader sees it, words put back together, then the hidden
    # text: a hidden preview line still shows in the inbox list.
    visible = " ".join(" ".join(text_parts + [found.visible_text for found in html_found]).split())
    hidden = " ".join(found.hidden_text for found in html_found)
    analysis.body_text = ("%s %s" % (visible, hidden)).strip()[:BODY_TEXT_LIMIT]
    analysis.hidden_splits = sum(found.hidden_splits for found in html_found)
    analysis.tag_splits = sum(found.tag_splits for found in html_found)
    analysis.hidden_filler, analysis.hidden_sample = _hidden_filler(visible, hidden)

    unwrapped = msg.__dict__.get("_unwrapped_part")
    already_analysed = _part_bytes(unwrapped) if unwrapped is not None and unwrapped is not msg else None

    def open_message(inspector: Inspector, ioc: FileIoc, data: bytes, depth: int) -> None:
        if depth == 0 and data == already_analysed:
            return
        _inspect_message(inspector, ioc, data, depth, bucket)

    inspector = Inspector(
        analysis, lambda url, source: _add_url(bucket, url, source), scan,
        lambda ioc, data: _inspect_html(ioc, data, bucket, scan),
        password_candidates("%s\n%s" % (analysis.subject, analysis.body_text)), file_hook,
        open_message if open_attached else None)
    for part in attachment_parts:
        content_type = part.get_content_type() or "application/octet-stream"
        default_name = "attached-message.eml" if content_type == "message/rfc822" else "(unnamed)"
        disposition = (part.get_content_disposition() or "").lower()
        inspector.attach(part.get_filename() or default_name, content_type, _part_bytes(part),
                         inline=disposition == "inline" and part.get_content_maintype() == "image")
    for text in calendar_parts:
        inspector.calendar(text, "the message")
    for part in image_parts:
        data = _part_bytes(part)
        payloads = scan.image(data, "an inline image")
        if payloads:
            ioc = file_ioc("(inline image)", part.get_content_type(), data)
            ioc.inline = True
            ioc.notes.extend("QR code: %s" % defang_text(payload[:200]) for payload in payloads)
            analysis.attachments.append(ioc)
    if inspector.extra_text:  # the body Outlook hid inside winmail.dat
        extra = " ".join(" ".join(inspector.extra_text).split())
        analysis.body_text = ("%s %s" % (analysis.body_text, extra)).strip()[:BODY_TEXT_LIMIT]

    analysis.urls = list(bucket.values())
    analysis.urls_dropped = bucket.dropped
    analysis.wallets = find_wallets("%s\n%s" % (analysis.subject, analysis.body_text))
    if _FORWARD_SUBJECT.match(analysis.subject or ""):
        match = _INLINE_FROM.search(analysis.body_text[:6000])
        if match:
            display, address = _parseaddr(match.group("sender"))
            if "@" in address:
                analysis.forwarded_from = {"display": display, "address": address.lower(),
                                           "domain": domain_of_address(address)}

    seen: dict[str, None] = {}
    for address in EMAIL_RE.findall(refang("\n".join(text_parts + html_parts))):
        seen.setdefault(address.lower())
        if len(seen) >= 25:
            break
    analysis.body_emails = list(seen)

    domains: dict[str, None] = {}  # ordered and O(1): a message can carry 50,000 links
    for candidate in [analysis.from_domain, analysis.reply_to_domain, analysis.return_path_domain]:
        if candidate:
            domains.setdefault(candidate)
    for url_ioc in analysis.urls:
        if url_ioc.host:
            domains.setdefault(url_ioc.host)
    analysis.domains = list(domains)


# ---------------------------------------------------------------------------
# HTML attachments
# ---------------------------------------------------------------------------

def _inspect_message(inspector: Inspector, ioc: FileIoc, data: bytes, depth: int,
                     bucket: dict[str, UrlIoc]) -> None:
    """An email attached below the layers that are unwrapped (or beside the
    one that was): its links, invitations and files are checked too, so a
    phish cannot hide one attachment deeper than PhishHawk looks."""
    try:
        inner = load_message(data)
        text_parts, html_parts, attachment_parts, _, calendar_parts = _collect(inner)
    except Exception:
        return
    source = "attachment:%s " % ioc.filename
    for text in text_parts:
        for url in urls_from_text(text[:MAX_ATTACHED_TEXT]):
            _add_url(bucket, url, source + "text")
    for html in html_parts:
        _harvest_html(html[:MAX_ATTACHED_TEXT], bucket, source)
    for text in calendar_parts:
        inspector.calendar(text, ioc.filename)
    for part in attachment_parts:
        content_type = part.get_content_type() or "application/octet-stream"
        name = part.get_filename() or ("attached-message.eml" if content_type == "message/rfc822" else "(unnamed)")
        inspector.child(ioc, name, _part_bytes(part), depth)


def _inspect_html(ioc: FileIoc, data: bytes, bucket: dict[str, UrlIoc], scan: _QrScan) -> None:
    source = "attachment:%s" % ioc.filename
    text = data.decode("utf-8", errors="replace")
    found = _harvest_html(text, bucket, source + " ")
    scan.html(found, text, ioc.filename)
    for url in urls_from_text(found.script_text):
        _add_url(bucket, url, source + " script")

    decoded_urls: list[str] = []
    for match in _ATOB_RE.finditer(found.script_text):
        try:
            plain = base64.b64decode("".join(match.group(1).split()), validate=False)
        except (binascii.Error, ValueError):
            continue
        for url in urls_from_text(plain.decode("utf-8", errors="replace")):
            _add_url(bucket, url, source + " atob-decoded")
            decoded_urls.append(url)

    ioc.html = {
        "forms": found.forms,
        "password_inputs": found.password_inputs,
        "smuggling": found.smuggling_markers,
        "redirects": found.redirects,
        "decoded_urls": decoded_urls,
        "scripts": bool(found.script_text.strip()) or bool(_EVENT_HANDLER_RE.search(text[:2_000_000])),
    }
