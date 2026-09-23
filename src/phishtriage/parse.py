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
import email.policy
import email.utils
import hashlib
import io
import mimetypes
import os
import re
import zipfile
from collections.abc import Iterator
from email.message import Message
from typing import Any

from .extract import (
    EMAIL_RE,
    IPV4_RE,
    PRIVATE_IP_RE,
    ZERO_WIDTH_RE,
    clean_url,
    domain_of_address,
    host_of,
    parse_html,
    refang,
    registrable_domain,
    sniff_type,
    urls_from_pdf,
    urls_from_text,
    usable_url,
)
from .knowledge import FREEMAIL
from .models import Analysis, FileIoc, UrlIoc

MAX_UNWRAP_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 200
MAX_MEMBER_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 100 * 1024 * 1024
OOXML_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm", ".xlam"}
HTML_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".svg"}
SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "data:", "#", "javascript:", "blob:", "about:")
_ATOB_RE = re.compile(r"""atob\(\s*['"]([A-Za-z0-9+/=\s]{8,})['"]\s*\)""")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def load_message(data: bytes) -> Message:
    return email.message_from_bytes(data, policy=email.policy.default)


def parse_file(path: str, unwrap: bool = True, protected: list[str] | tuple = (),
               auto_protect: bool = True) -> Analysis:
    with open(path, "rb") as handle:
        data = handle.read()
    return parse_bytes(data, path=path, unwrap=unwrap, protected=protected,
                       auto_protect=auto_protect)


def parse_bytes(data: bytes, path: str = "<memory>", unwrap: bool = True,
                protected: list[str] | tuple = (), auto_protect: bool = True) -> Analysis:
    analysis = Analysis(path=path)
    message = load_message(data)
    if unwrap:
        message = _unwrap(message, analysis)
    _read_headers(message, analysis)
    _read_content(message, analysis)
    analysis.protected_domains = _protected_domains(message, analysis, protected, auto_protect)
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
    """Message.walk() that does not descend into attached messages."""
    yield msg
    if msg.get_content_maintype() == "multipart":
        payload = msg.get_payload()
        if isinstance(payload, list):
            for part in payload:
                yield from _walk_shallow(part)


def _decode_text(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass
    payload = _part_bytes(part)
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _part_bytes(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload:
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
    if isinstance(payload, list) and payload:
        return payload[0]
    if isinstance(payload, Message):
        return payload
    try:
        raw = part.get_payload(decode=True)
    except Exception:
        raw = None
    return load_message(raw) if raw else None


def _attached_messages(msg: Message) -> list[Message]:
    found = []
    for part in _walk_shallow(msg):
        if part is msg:
            continue
        if part.get_content_type() == "message/rfc822":
            inner = _rfc822_payload(part)
        elif (part.get_filename() or "").lower().endswith(".eml"):
            data = _part_bytes(part)
            inner = load_message(data) if data else None
        else:
            continue
        if inner is not None and (inner.get("From") or inner.get("Subject")):
            found.append(inner)
    return found


def _unwrap(msg: Message, analysis: Analysis) -> Message:
    layers: list[dict[str, Any]] = []
    while len(layers) < MAX_UNWRAP_DEPTH:
        attached = _attached_messages(msg)
        if not attached:
            break
        display, address = email.utils.parseaddr(header(msg, "From"))
        layers.append({"from": address.lower(), "display": display,
                       "subject": header(msg, "Subject"), "date": header(msg, "Date"),
                       "attached_messages": len(attached)})
        msg = attached[0]
    if layers:
        analysis.reported_by = dict(layers[0], layers=len(layers))
    return msg


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def _auth_results(msg: Message) -> dict[str, str]:
    results: dict[str, str] = {}
    try:
        headers = msg.get_all("Authentication-Results", []) or []
    except Exception:
        headers = []
    for value in headers:
        text = str(value)
        for mechanism in ("spf", "dkim", "dmarc", "compauth"):
            if mechanism not in results:
                match = re.search(r"\b%s\s*=\s*([a-z]+)" % mechanism, text, re.I)
                if match:
                    results[mechanism] = match.group(1).lower()
    if "spf" not in results:
        received_spf = header(msg, "Received-SPF")
        if received_spf:
            results["spf"] = received_spf.split()[0].lower().strip(";")
    return results


def _originating_ip(msg: Message) -> str:
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        for candidate in IPV4_RE.findall(header(msg, name)):
            if not PRIVATE_IP_RE.match(candidate):
                return candidate
    try:
        received = [str(h) for h in (msg.get_all("Received", []) or [])]
    except Exception:
        received = []
    for value in reversed(received):  # newest-first, so the origin is last
        for candidate in IPV4_RE.findall(value):
            if not PRIVATE_IP_RE.match(candidate):
                return candidate
    return ""


def _read_headers(msg: Message, analysis: Analysis) -> None:
    analysis.subject = header(msg, "Subject")
    analysis.date = header(msg, "Date")
    analysis.message_id = header(msg, "Message-ID")
    analysis.to = header(msg, "To")

    display, address = email.utils.parseaddr(header(msg, "From"))
    analysis.from_display = display
    analysis.from_address = address.lower()
    analysis.from_domain = domain_of_address(address)

    _, reply_to = email.utils.parseaddr(header(msg, "Reply-To"))
    analysis.reply_to = reply_to.lower()
    analysis.reply_to_domain = domain_of_address(reply_to)

    _, return_path = email.utils.parseaddr(header(msg, "Return-Path"))
    analysis.return_path = return_path.lower()
    analysis.return_path_domain = domain_of_address(return_path)

    analysis.auth = _auth_results(msg)
    analysis.originating_ip = _originating_ip(msg)
    try:
        analysis.received_hops = len(msg.get_all("Received", []) or [])
    except Exception:
        analysis.received_hops = 0


def _protected_domains(msg: Message, analysis: Analysis, explicit, auto: bool) -> list[str]:
    """Your organisation's domains: never looked up externally, and the
    reference set for business-email-compromise lookalike checks."""
    domains: list[str] = []

    def add(domain: str) -> None:
        base = registrable_domain(domain)
        if base and base not in FREEMAIL and base not in domains:
            domains.append(base)

    for domain in explicit:
        add(domain.strip().lower())
    if auto:
        for name in ("To", "Cc", "Delivered-To"):
            for _, address in email.utils.getaddresses([header(msg, name)]):
                add(domain_of_address(address))
        if analysis.reported_by:
            add(domain_of_address(analysis.reported_by.get("from", "")))
    return domains


# ---------------------------------------------------------------------------
# Bodies and URLs
# ---------------------------------------------------------------------------

def _add_url(bucket: dict[str, UrlIoc], raw: str, source: str, anchor: str = "") -> None:
    if not raw or raw.lower().startswith(SKIP_SCHEMES):
        return
    url = clean_url(refang(raw))
    if not usable_url(url):
        return
    key = url.rstrip("/").lower()
    ioc = bucket.get(key)
    if ioc is None:
        host = host_of(url)
        ioc = UrlIoc(url=url, host=host, domain=registrable_domain(host))
        bucket[key] = ioc
    if source not in ioc.sources:
        ioc.sources.append(source)
    anchor = " ".join((anchor or "").split())
    if anchor and anchor not in ioc.anchor_texts:
        ioc.anchor_texts.append(anchor)


def _collect(msg: Message) -> tuple[list[str], list[str], list[Message]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Message] = []
    for part in _walk_shallow(msg):
        content_type = (part.get_content_type() or "").lower()
        if content_type == "message/rfc822":
            if part is not msg:
                attachments.append(part)
            continue
        if part.get_content_maintype() == "multipart":
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and content_type not in ("text/plain", "text/html")):
            attachments.append(part)
        elif content_type == "text/plain":
            text_parts.append(_decode_text(part))
        elif content_type == "text/html":
            html_parts.append(_decode_text(part))
    return text_parts, html_parts, attachments


def _harvest_html(html: str, bucket: dict[str, UrlIoc], prefix: str) -> Any:
    found = parse_html(html)
    for href, anchor in found.anchors:
        _add_url(bucket, href, prefix + "href", anchor)
    for resource in found.resources:
        _add_url(bucket, resource, prefix + "resource")
    for redirect in found.redirects:
        _add_url(bucket, redirect, prefix + "redirect")
    for form in found.forms:
        _add_url(bucket, form["action"], prefix + "form-action")
    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", html, flags=re.S | re.I)
    for url in urls_from_text(visible):
        _add_url(bucket, url, prefix + "text")
    return found


def _read_content(msg: Message, analysis: Analysis) -> None:
    text_parts, html_parts, attachment_parts = _collect(msg)
    bucket: dict[str, UrlIoc] = {}

    for body in text_parts:
        for url in urls_from_text(body):
            _add_url(bucket, url, "body-text")
    for body in html_parts:
        _harvest_html(body, bucket, "html-")
    for name in ("List-Unsubscribe", "X-Originating-URL"):
        for url in urls_from_text(header(msg, name)):
            _add_url(bucket, url, "header:%s" % name)

    for part in attachment_parts:
        _process_attachment(part, analysis, bucket)

    analysis.urls = list(bucket.values())

    visible_html = [re.sub(r"<[^>]+>", " ", body) for body in html_parts]
    analysis.zero_width_chars = sum(len(ZERO_WIDTH_RE.findall(t)) for t in text_parts + visible_html)

    seen: list[str] = []
    for address in EMAIL_RE.findall(refang("\n".join(text_parts + html_parts))):
        address = address.lower()
        if address not in seen:
            seen.append(address)
    analysis.body_emails = seen[:25]

    domains: list[str] = []
    for candidate in [analysis.from_domain, analysis.reply_to_domain, analysis.return_path_domain]:
        if candidate and candidate not in domains:
            domains.append(candidate)
    for ioc in analysis.urls:
        if ioc.host and ioc.host not in domains:
            domains.append(ioc.host)
    analysis.domains = domains


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------

def _file_ioc(filename: str, content_type: str, data: bytes, parent: str = "") -> FileIoc:
    return FileIoc(
        filename=" ".join(str(filename).split()) or "(unnamed)",
        content_type=content_type or "application/octet-stream",
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        true_type=sniff_type(data),
        parent=parent,
    )


def _process_attachment(part: Message, analysis: Analysis, bucket: dict[str, UrlIoc]) -> None:
    content_type = part.get_content_type() or "application/octet-stream"
    data = _part_bytes(part)
    default_name = "attached-message.eml" if content_type == "message/rfc822" else "(unnamed)"
    ioc = _file_ioc(part.get_filename() or default_name, content_type, data)
    disposition = (part.get_content_disposition() or "").lower()
    ioc.inline = disposition == "inline" and part.get_content_maintype() == "image"
    analysis.attachments.append(ioc)
    _inspect(ioc, data, analysis, bucket, depth=0)


def _inspect(ioc: FileIoc, data: bytes, analysis: Analysis, bucket: dict[str, UrlIoc],
             depth: int) -> None:
    extension = os.path.splitext(ioc.filename.lower())[1]
    if ioc.true_type == "zip" and extension in OOXML_EXTENSIONS:
        _inspect_ooxml(ioc, data)
    elif ioc.true_type == "zip":
        _inspect_zip(ioc, data, analysis, bucket, depth)
    if ioc.true_type in ("html", "svg") or extension in HTML_EXTENSIONS:
        _inspect_html(ioc, data, bucket)
    if ioc.true_type == "pdf":
        for url in urls_from_pdf(data):
            _add_url(bucket, url, "attachment:%s" % ioc.filename)
    if ioc.content_type == "message/rfc822" or extension == ".eml":
        ioc.notes.append("attached email message")


def _inspect_ooxml(ioc: FileIoc, data: bytes) -> None:
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        ioc.notes.append("corrupt Office container")
        return
    if any(name.lower().endswith("vbaproject.bin") for name in names):
        ioc.notes.append("contains a VBA macro project")
        ioc.flagged = True


def _inspect_zip(ioc: FileIoc, data: bytes, analysis: Analysis, bucket: dict[str, UrlIoc],
                 depth: int) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = [info for info in archive.infolist() if not info.is_dir()]
    except (zipfile.BadZipFile, OSError, ValueError):
        ioc.notes.append("corrupt or unreadable archive")
        return
    summary: dict[str, Any] = {
        "members": len(infos),
        "encrypted": any(info.flag_bits & 0x1 for info in infos),
        "listing": [info.filename for info in infos[:MAX_ARCHIVE_MEMBERS]],
        "truncated": len(infos) > MAX_ARCHIVE_MEMBERS,
        "skipped": 0,
    }
    ioc.archive = summary
    total = 0
    for info in infos[:MAX_ARCHIVE_MEMBERS]:
        if info.flag_bits & 0x1 or info.file_size > MAX_MEMBER_BYTES \
                or total + info.file_size > MAX_ARCHIVE_TOTAL:
            summary["skipped"] += 1
            continue
        try:
            # ZipExtFile stops at the declared size, so a lying header
            # cannot inflate this beyond MAX_MEMBER_BYTES.
            content = archive.read(info)
        except Exception:
            summary["skipped"] += 1
            continue
        total += len(content)
        guessed = mimetypes.guess_type(info.filename)[0] or "application/octet-stream"
        member = _file_ioc(info.filename, guessed, content, parent=ioc.filename)
        analysis.attachments.append(member)
        if depth < 1:
            _inspect(member, content, analysis, bucket, depth + 1)


def _inspect_html(ioc: FileIoc, data: bytes, bucket: dict[str, UrlIoc]) -> None:
    source = "attachment:%s" % ioc.filename
    text = data.decode("utf-8", errors="replace")
    found = _harvest_html(text, bucket, source + " ")
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
    }
