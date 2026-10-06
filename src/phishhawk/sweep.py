"""Mailbox sweep: who else received a reported message, and what they did.

Searches mailboxes through Microsoft Graph or the Gmail API for copies of a
reported message (its Message-ID, sender and reply-to addresses, subject,
and the phishing domains it links to) and reports, for each copy, where it
sits, whether it was read and whether the mailbox's owner replied to the
attacker in its thread. Read-only, like the graph and gmail commands: GET
requests only, the token only in the Authorization header and only to the
API's own host. Graph's search matches loosely, so its hits are checked
against what was asked for before they are reported; so are Gmail's, except
a domain found in a message's body, which Gmail's own search vouches for.
One failed search or lookup is a warning on its mailbox, not the end of it.
Whether anyone opened an attachment or clicked a link is not in the
mailbox: that is in EDR and proxy logs.
"""

from __future__ import annotations

import datetime as dt
import email.utils
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .campaign import KNOWN_PLATFORMS, _traits, normalise_subject
from .mailapi import GMAIL, GRAPH, MAX_PAGES, ApiSource, MailApiError, NotFound, _Client
from .models import Analysis

MAX_MAILBOXES = 10_000
MAX_LOOKUPS = 200  # copies per mailbox whose folder, reply and (Gmail) details are looked up
MAX_TERM = 200  # characters of an address, subject, domain or Message-ID searched for
GRAPH_FIELDS = ("id,subject,from,replyTo,receivedDateTime,isRead,conversationId,internetMessageId,"
                "parentFolderId")
_MAILBOX_RE = re.compile(r"[A-Za-z0-9._%+=@-]{1,320}")  # an address, a user id, a GUID or "me"
_KQL_OPERATOR_RE = re.compile(r"\b(AND|OR|NOT|NEAR|ONEAR)\b")
_FRACTION_RE = re.compile(r"\.(\d+)")
GMAIL_FOLDERS = (("SPAM", "Spam"), ("TRASH", "Trash"), ("INBOX", "Inbox"), ("SENT", "Sent"), ("DRAFT", "Drafts"))
GMAIL_DOMAIN_NOTE = " (Gmail's search, not checked again)"
_ANSWER_ERRORS = (MailApiError, ValueError, TypeError, AttributeError, KeyError)


@dataclass
class Criteria:
    senders: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    message_ids: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.senders or self.subjects or self.domains or self.message_ids)


def criteria_from(a: Analysis) -> Criteria:
    """What to look for, from a reported message: never a brand's own domain
    or address, a shared service, a platform as a whole (only its customer's
    host), or a subject too short to mean anything."""
    found, under = _traits(a)
    senders = [address for address in (a.from_address.lower(), a.reply_to.lower())
               if address and address in found.get("sender", set()) | found.get("reply-to", set())]
    domains: set[str] = set()
    for base in found.get("domain", set()):
        domains |= under.get(base, set()) if base in KNOWN_PLATFORMS else {base}
    domains |= {host for host in found.get("host", set()) if "/" not in host}
    subject = " ".join(a.subject.split())
    return Criteria(senders=list(dict.fromkeys(senders)),
                    subjects=[subject] if normalise_subject(subject) else [],
                    domains=sorted(domains)[:10],
                    message_ids=[a.message_id] if a.message_id else [])


def _clean(value: str) -> str:
    return " ".join(str(value).replace('"', " ").replace("\\", " ").split())[:MAX_TERM]


def _kql(value: str) -> str:
    """A $search value that stays inside its quotes and whose words stay words
    (KQL operators are upper case); hits are checked afterwards anyway."""
    return '"%s"' % _KQL_OPERATOR_RE.sub(lambda m: m.group(1).lower(), _clean(value))


def _odata(value: str) -> str:
    return "'%s'" % str(value)[:MAX_TERM * 2].replace("'", "''")


def _gmail_phrase(value: str) -> str:
    return '"%s"' % _clean(value)


def names_domain(text: str, domain: str) -> bool:
    """Whether text names domain or a host under it: login.evil.example names
    evil.example; notevil.example and evil.example.attacker.net do not."""
    text, domain = text.lower(), domain.lower()
    start = text.find(domain)
    while start != -1:
        end = start + len(domain)
        before = text[start - 1] if start else ""
        after = text[end:end + 2]
        if not (before.isalnum() or before in ("-", "_")) and not (
                after[:1].isalnum() or after[:1] in ("-", "_")
                or (after[:1] == "." and (after[1:2].isalnum() or after[1:2] == "-"))):
            return True
        start = text.find(domain, start + 1)
    return False


def _subject_matches(subject: str, wanted: str) -> bool:
    asked = normalise_subject(wanted)
    return bool(asked) and asked in normalise_subject(subject)


def _field_is(name: str, wanted: str) -> Callable[[dict[str, Any]], bool]:
    return lambda match: match[name] == wanted


def _subject_is(wanted: str) -> Callable[[dict[str, Any]], bool]:
    return lambda match: _subject_matches(match["subject"], wanted)


def _iso(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    # Python 3.10 reads three or six fraction digits only; Graph writes up to seven.
    value = _FRACTION_RE.sub(lambda m: "." + (m.group(1) + "000000")[:6], value.replace("Z", "+00:00"), count=1)
    try:
        moment = dt.datetime.fromisoformat(value)
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    try:
        return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


def _since_ok(received: str, since: dt.date | None) -> bool:
    return since is None or not received or received[:10] >= since.isoformat()


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _merge(found: dict[str, dict[str, Any]], match: dict[str, Any], label: str) -> None:
    """One entry per copy, however many searches found it; a search that
    asked for more (Graph's replyTo) adds what it learnt."""
    entry = found.setdefault(match["id"], match)
    if entry is not match:
        entry["_reply_to"] = sorted(set(entry.get("_reply_to", [])) | set(match.get("_reply_to", [])))
    if label not in entry["matched"]:
        entry["matched"].append(label)


def _checked(mailbox: str) -> str:
    if not _MAILBOX_RE.fullmatch(mailbox) or set(mailbox) <= {"."}:
        raise MailApiError("not a mailbox address or id: %r" % mailbox[:80])
    return mailbox


def _problem(label: str, exc: Exception) -> str:
    detail = str(exc) if isinstance(exc, MailApiError) else "an answer of an unexpected shape (%s)" % (
        type(exc).__name__)
    return "%s: %s" % (label, detail)


def _mailbox_result(mailbox: str, found: dict[str, dict[str, Any]], error: str = "",
                    warnings: list[str] | None = None) -> dict[str, Any]:
    matches = sorted(found.values(), key=lambda m: m["received"], reverse=True)
    for match in matches:
        match["matched"].sort()
        for private in [key for key in match if key.startswith("_")]:
            del match[private]
    return {"mailbox": mailbox, "matches": matches, "error": error, "warnings": warnings or []}


def _run(mailboxes: list[str], search: Callable[[str], tuple[dict[str, dict[str, Any]], list[str]]]
         ) -> list[dict[str, Any]]:
    results = []
    for mailbox in mailboxes[:MAX_MAILBOXES]:
        try:
            found, warnings = search(_checked(mailbox))
            results.append(_mailbox_result(mailbox, found, warnings=warnings))
        except _ANSWER_ERRORS as exc:
            results.append(_mailbox_result(mailbox, {}, _problem("search", exc).split(": ", 1)[1]))
    return results


# ------------------------------------------------------------------- Graph --

def _graph_hits(client: _Client, url: str, params: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    next_url, query = url, dict(params, **{"$top": min(limit, 100)})
    for _ in range(MAX_PAGES):
        if not next_url or len(hits) >= limit:
            break
        page = client.json(next_url, query)
        hits += [item for item in _list(page.get("value")) if isinstance(item, dict) and item.get("id")]
        next_url, query = str(page.get("@odata.nextLink") or ""), {}
        if not next_url.startswith(GRAPH + "/"):
            break  # the token goes to Graph and nowhere else
    return hits[:limit]


def _graph_address(value: Any) -> str:
    return str(_dict(_dict(value).get("emailAddress")).get("address") or "").lower()


def _graph_match(item: dict[str, Any]) -> dict[str, Any]:
    reply_to = {_graph_address(entry) for entry in _list(item.get("replyTo"))} - {""}
    return {"id": str(item["id"]), "message_id": str(item.get("internetMessageId") or ""),
            "received": _iso(item.get("receivedDateTime")), "from": _graph_address(item.get("from")),
            "subject": str(item.get("subject") or ""), "folder": "", "read": bool(item.get("isRead")),
            "replied": None, "matched": [], "_folder_id": str(item.get("parentFolderId") or ""),
            "_thread": str(item.get("conversationId") or ""), "_reply_to": sorted(reply_to)}


def _graph_replied(client: _Client, base: str, thread: str, attacker: set[str]) -> bool | None:
    """Whether the mailbox's owner wrote to the sender or reply-to address in
    this conversation; a forward of the phish to the SOC is not a reply."""
    sent = client.json(base + "/mailFolders/sentitems/messages",
                       {"$filter": "conversationId eq " + _odata(thread),
                        "$select": "id,toRecipients,ccRecipients,bccRecipients", "$top": 50})
    value = sent.get("value")
    if not isinstance(value, list):
        return None
    for message in value:
        message = _dict(message)
        for role in ("toRecipients", "ccRecipients", "bccRecipients"):
            if {_graph_address(entry) for entry in _list(message.get(role))} & attacker:
                return True
    return False


def _graph_mailbox(client: _Client, mailbox: str, criteria: Criteria, since: dt.date | None,
                   limit: int) -> tuple[dict[str, dict[str, Any]], list[str]]:
    base = GRAPH + "/me" if mailbox == "me" else "%s/users/%s" % (GRAPH, quote(mailbox, safe="@"))
    url = base + "/messages"
    found: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    checks: list[tuple[str, dict[str, Any], Callable[[dict[str, Any]], bool]]] = []
    for message_id in criteria.message_ids:
        wanted = {"$filter": "internetMessageId eq " + _odata(message_id), "$select": GRAPH_FIELDS}
        checks.append(("message-id " + message_id, wanted, _field_is("message_id", message_id)))
    for sender in criteria.senders:
        checks.append(("sender " + sender, {"$search": _kql("from:" + sender), "$select": GRAPH_FIELDS},
                       _field_is("from", sender.lower())))
    for subject in criteria.subjects:
        checks.append(("subject " + subject, {"$search": _kql(subject), "$select": GRAPH_FIELDS},
                       _subject_is(subject)))
    for domain in criteria.domains:
        checks.append(("domain " + domain, {"$search": _kql("body:" + domain), "$select": GRAPH_FIELDS + ",body"},
                       lambda m: True))
    answered = 0
    for label, params, accept in checks:
        try:
            hits = _graph_hits(client, url, params, limit)
            answered += 1
            for item in hits:
                match = _graph_match(item)
                if label.startswith("domain "):
                    body = str(_dict(item.get("body")).get("content") or "")  # read, never kept
                    if not names_domain(body, label[len("domain "):]):
                        continue
                if accept(match) and _since_ok(match["received"], since):
                    _merge(found, match, label)
        except _ANSWER_ERRORS as exc:
            warnings.append(_problem(label, exc))
    if checks and not answered:
        raise MailApiError(warnings[0].split(": ", 1)[1])
    folders: dict[str, str] = {}
    replies: dict[str, bool | None] = {}
    copies = list(found.values())
    if len(copies) > MAX_LOOKUPS:
        warnings.append("folder and reply checks for the first %d copies only" % MAX_LOOKUPS)
    for match in copies[:MAX_LOOKUPS]:
        folder_id, thread = match["_folder_id"], match["_thread"]
        if folder_id and folder_id not in folders:
            try:
                folder = client.json("%s/mailFolders/%s" % (base, quote(folder_id, safe="")),
                                     {"$select": "displayName"})
                folders[folder_id] = str(folder.get("displayName") or "")
            except _ANSWER_ERRORS:
                folders[folder_id] = ""
        match["folder"] = folders.get(folder_id, "")
        attacker = ({match["from"]} | set(match["_reply_to"])) - {""}
        key = "%s|%s" % (thread, ",".join(sorted(attacker)))
        if thread and attacker and key not in replies:
            try:
                replies[key] = _graph_replied(client, base, thread, attacker)
            except _ANSWER_ERRORS:
                replies[key] = None
        match["replied"] = replies.get(key)
    return found, warnings


def sweep_graph(token: str, mailboxes: list[str], criteria: Criteria, since: dt.date | None = None,
                limit: int = 100, session: Any = None, timeout: float = 30) -> list[dict[str, Any]]:
    client = _Client(ApiSource(token=token, timeout=timeout), "Graph", session)
    return _run(mailboxes, lambda mailbox: _graph_mailbox(client, mailbox, criteria, since, limit))


# ------------------------------------------------------------------- Gmail --

_ADDRESS_RE = re.compile(r"[^\s<>,;:\"'()\[\]]{1,64}@[^\s<>,;:\"'()\[\]]{1,255}")


def _addresses(*values: str) -> set[str]:
    """The addresses in address headers. Recent Python releases refuse a
    whole header they find ambiguous, so a refused one is searched instead."""
    found: set[str] = set()
    for value in values:
        if not value:
            continue
        try:
            parsed = {address.lower() for _, address in email.utils.getaddresses([value]) if "@" in address}
        except Exception:  # a header too broken to name anyone
            parsed = set()
        found |= parsed or {address.lower() for address in _ADDRESS_RE.findall(value[:20_000])}
    return found


def _gmail_headers(message: dict[str, Any]) -> dict[str, str]:
    return {str(h.get("name", "")).lower(): str(h.get("value", ""))
            for h in _list(_dict(message.get("payload")).get("headers")) if isinstance(h, dict)}


def _gmail_replied(client: _Client, base: str, thread: str, attacker: set[str]) -> bool | None:
    messages = _list(client.json("%s/threads/%s" % (base, quote(thread, safe="")),
                                 {"format": "metadata", "metadataHeaders": ["To", "Cc", "Bcc"]}).get("messages"))
    for message in messages:
        message = _dict(message)
        if "SENT" not in _list(message.get("labelIds")):
            continue
        headers = _gmail_headers(message)
        if _addresses(*(headers.get(name, "") for name in ("to", "cc", "bcc"))) & attacker:
            return True
    return False


def _gmail_verified(match: dict[str, Any], label: str) -> str:
    """The label if the copy's own headers bear it out, else ""; a domain in
    the body is Gmail's word for it."""
    kind, _, wanted = label.partition(" ")
    if kind == "sender":
        return label if wanted in ({match["from"]} | set(match["_reply_to"])) else ""
    if kind == "subject":
        return label if _subject_matches(match["subject"], wanted) else ""
    if kind == "message-id":
        return label if match["message_id"].replace(" ", "") == wanted.replace(" ", "") else ""
    return label + GMAIL_DOMAIN_NOTE


def _gmail_mailbox(client: _Client, mailbox: str, criteria: Criteria, since: dt.date | None,
                   limit: int) -> tuple[dict[str, dict[str, Any]], list[str]]:
    base = "%s/users/%s" % (GMAIL, quote(mailbox or "me", safe="@"))
    after = " after:%s" % since.strftime("%Y/%m/%d") if since else ""
    searches = [("message-id " + m, "rfc822msgid:" + _clean(m).replace(" ", "")) for m in criteria.message_ids]
    searches += [("sender " + s, "from:" + _clean(s).replace(" ", "")) for s in criteria.senders]
    searches += [("subject " + s, "subject:" + _gmail_phrase(s)) for s in criteria.subjects]
    searches += [("domain " + d, _gmail_phrase(d)) for d in criteria.domains]
    hits: dict[str, list[str]] = {}
    warnings: list[str] = []
    answered = 0
    for label, term in searches:
        params: dict[str, Any] = {"q": "in:anywhere %s%s" % (term, after), "maxResults": min(limit, 500)}
        listed = 0
        try:
            for _ in range(MAX_PAGES):
                if listed >= limit:
                    break
                page = client.json(base + "/messages", params)
                for item in _list(page.get("messages")):
                    if isinstance(item, dict) and item.get("id") and listed < limit:
                        hits.setdefault(str(item["id"]), []).append(label)
                        listed += 1
                if not page.get("nextPageToken"):
                    break
                params = dict(params, pageToken=str(page["nextPageToken"]))
            answered += 1
        except _ANSWER_ERRORS as exc:
            warnings.append(_problem(label, exc))
    if searches and not answered:
        raise MailApiError(warnings[0].split(": ", 1)[1])
    found: dict[str, dict[str, Any]] = {}
    replies: dict[str, bool | None] = {}
    if len(hits) > MAX_LOOKUPS:
        warnings.append("details for the first %d copies only" % MAX_LOOKUPS)
    for message_id, labels in list(hits.items())[:MAX_LOOKUPS]:
        try:
            meta = client.json("%s/messages/%s" % (base, quote(message_id, safe="")),
                               {"format": "metadata",
                                "metadataHeaders": ["From", "Reply-To", "Subject", "Date", "Message-ID"]})
        except NotFound:
            continue  # deleted since the search found it: no longer a copy
        except _ANSWER_ERRORS as exc:
            warnings.append(_problem("message " + message_id, exc))
            continue
        headers = _gmail_headers(meta)
        tags = [str(tag) for tag in _list(meta.get("labelIds"))]
        try:
            received = dt.datetime.fromtimestamp(int(meta.get("internalDate") or 0) / 1000, dt.timezone.utc)
            when = received.strftime("%Y-%m-%dT%H:%M:%SZ") if received.year > 1970 else ""
        except (ValueError, TypeError, OverflowError, OSError):
            when = ""
        sender = email.utils.parseaddr(headers.get("from", ""))[1].lower()
        match: dict[str, Any] = {"id": message_id, "message_id": headers.get("message-id", ""), "received": when,
                 "from": sender, "subject": headers.get("subject", ""),
                 "folder": next((name for tag, name in GMAIL_FOLDERS if tag in tags), "Archive"),
                 "read": "UNREAD" not in tags, "replied": None, "matched": [],
                 "_reply_to": sorted(_addresses(headers.get("reply-to", "")))}
        verified = [checked for checked in (_gmail_verified(match, label) for label in labels) if checked]
        if not verified:
            continue
        thread = str(meta.get("threadId") or "")
        attacker = ({sender} | set(match["_reply_to"])) - {""}
        key = "%s|%s" % (thread, ",".join(sorted(attacker)))
        if thread and attacker and key not in replies:
            try:
                replies[key] = _gmail_replied(client, base, thread, attacker)
            except _ANSWER_ERRORS:
                replies[key] = None
        match["replied"] = replies.get(key)
        for label in verified:
            _merge(found, match, label)
    return found, warnings


def sweep_gmail(token: str, mailboxes: list[str], criteria: Criteria, since: dt.date | None = None,
                limit: int = 100, session: Any = None, timeout: float = 30) -> list[dict[str, Any]]:
    client = _Client(ApiSource(token=token, timeout=timeout), "Gmail", session)
    return _run(mailboxes, lambda mailbox: _gmail_mailbox(client, mailbox, criteria, since, limit))
