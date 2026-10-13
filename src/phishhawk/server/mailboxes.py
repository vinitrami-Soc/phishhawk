"""Report mailboxes an admin connects, read-only (spec 6.3): what each kind needs, its credential sealed with the
encryption key and bound to the mailbox, and the view the API and the pages show, which never holds it."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import Box
from .models import Mailbox

KINDS = ("imap", "graph", "gmail")
# Where a mailbox is: changing one of these starts its cursor again; what it has seen stays seen.
CONNECTION = {"imap": ("host", "port", "starttls", "user", "folder"),
              "graph": ("tenant_id", "client_id", "address", "folder"),
              "gmail": ("address", "label")}
MIN_INTERVAL, MAX_INTERVAL = 5, 1440

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOST = re.compile(r"(?=.{1,253}$)%s(?:\.%s)*" % (_LABEL, _LABEL))
DOMAIN = re.compile(r"(?=.{1,253}$)(?:%s\.)+[A-Za-z]{2,63}" % _LABEL)
GUID = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}")
ADDRESS = re.compile(r"[^\s@\"<>()\[\],;:\\]{1,64}@" + DOMAIN.pattern)


class MailboxError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _text(value: Any, what: str, limit: int = 200, required: bool = True) -> str:
    text = str(value if value is not None else "").strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):  # a CR or LF would end an IMAP command early
        raise MailboxError(422, "%s has control characters" % what)
    if required and not text:
        raise MailboxError(422, "%s is required" % what)
    if len(text) > limit:
        raise MailboxError(422, "%s is longer than %d characters" % (what, limit))
    return text


def _name(value: Any) -> str:
    return _text(value, "name", 48)


def _interval(value: Any) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        minutes = 0
    if not MIN_INTERVAL <= minutes <= MAX_INTERVAL:
        raise MailboxError(422, "interval must be between %d and %d minutes" % (MIN_INTERVAL, MAX_INTERVAL))
    return minutes


def _host(value: Any) -> str:
    host = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not HOST.fullmatch(host):
        raise MailboxError(422, "host must be a host name or an IP address, without imaps:// or a path")
    return host.lower()


def _address(value: Any) -> str:
    address = str(value or "").strip()
    if not ADDRESS.fullmatch(address):
        raise MailboxError(422, "address must be the report mailbox's address")
    return address


def _config(kind: str, given: dict[str, Any]) -> dict[str, Any]:
    if kind == "imap":
        starttls = bool(given.get("starttls", False))
        try:
            port = int(given["port"]) if given.get("port") not in (None, "") else (143 if starttls else 993)
        except (TypeError, ValueError):
            port = 0
        if not 1 <= port <= 65535:
            raise MailboxError(422, "port must be between 1 and 65535")
        return {"host": _host(given.get("host")), "port": port, "starttls": starttls,
                "user": _text(given.get("user"), "user", 320),
                "folder": _text(given.get("folder") or "INBOX", "folder")}
    if kind == "graph":
        tenant = str(given.get("tenant_id") or "").strip()
        if not (GUID.fullmatch(tenant) or DOMAIN.fullmatch(tenant)):
            raise MailboxError(422, "tenant must be a directory (tenant) ID or a domain such as "
                                    "contoso.onmicrosoft.com")
        client = str(given.get("client_id") or "").strip()
        if not GUID.fullmatch(client):
            raise MailboxError(422, "client ID must be the application (client) ID, a GUID")
        address, folder = _address(given.get("address")), _text(given.get("folder") or "inbox", "folder")
        return {"tenant_id": tenant.lower(), "client_id": client.lower(), "address": address, "folder": folder}
    return {"address": _address(given.get("address")), "label": _text(given.get("label") or "INBOX", "label")}


def _secret(kind: str, value: str) -> tuple[str, dict[str, Any]]:
    """The credential as it is kept, and what the config learns from it (a service account's address)."""
    if kind == "imap":
        if not value:
            raise MailboxError(422, "a password is required")
        return _text(value, "password", 1024), {}
    if kind == "graph":
        if not value.strip():
            raise MailboxError(422, "a client secret is required")
        return _text(value, "client secret", 1024), {}
    try:
        key = json.loads(value)
    except ValueError:
        key = None
    if not (isinstance(key, dict) and key.get("type") == "service_account"
            and isinstance(key.get("private_key"), str) and ADDRESS.fullmatch(str(key.get("client_email", "")))):
        raise MailboxError(422, "the key must be the JSON key file of a service account")
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415 - the server extra
    from cryptography.hazmat.primitives.serialization import load_pem_private_key  # noqa: PLC0415

    try:
        private = load_pem_private_key(key["private_key"].encode("ascii"), password=None)
    except (ValueError, TypeError, UnicodeError):
        private = None
    if not isinstance(private, rsa.RSAPrivateKey):
        raise MailboxError(422, "the service account's private key cannot be read")
    # its token_uri and the rest are not kept: the token is asked for at Google's own address
    kept = {"client_email": key["client_email"], "private_key": key["private_key"]}
    return json.dumps(kept), {"service_account": key["client_email"]}


def _bound_to(mailbox: Mailbox) -> str:
    return "mailbox:%d" % mailbox.id


def _seal(box: Box, mailbox: Mailbox, secret: str) -> None:
    mailbox.secret = base64.b64encode(box.seal(secret.encode("utf-8"), _bound_to(mailbox))).decode("ascii")


def secret_of(box: Box, mailbox: Mailbox) -> str:
    if not mailbox.secret:
        return ""
    return box.open(base64.b64decode(mailbox.secret), _bound_to(mailbox)).decode("utf-8")


def _unique(db: Session, workspace_id: int, name: str, mailbox_id: int | None = None) -> None:
    """Names are unique within a workspace."""
    taken = db.scalars(select(Mailbox.id).where(Mailbox.workspace_id == workspace_id,
                                                Mailbox.name == name)).first()
    if taken is not None and taken != mailbox_id:
        raise MailboxError(409, "a mailbox called %r exists" % name)


def create(db: Session, box: Box, data: dict[str, Any], workspace_id: int) -> Mailbox:
    name, kind = _name(data.get("name")), str(data.get("kind") or "")
    if kind not in KINDS:
        raise MailboxError(422, "kind must be imap, graph or gmail")
    interval = _interval(data.get("interval_minutes", MIN_INTERVAL))
    config = _config(kind, dict(data.get("config") or {}))
    secret, learnt = _secret(kind, str(data.get("secret") or ""))
    _unique(db, workspace_id, name)
    mailbox = Mailbox(workspace_id=workspace_id, name=name, kind=kind, enabled=bool(data.get("enabled", True)),
                      interval_minutes=interval, config=config | learnt, cursor={}, last_counts={})
    db.add(mailbox)
    db.flush()  # its ID, which the sealed secret is bound to
    _seal(box, mailbox, secret)
    return mailbox


def update(db: Session, box: Box, mailbox: Mailbox, data: dict[str, Any]) -> list[str]:
    """What changed, by name (the secret as "secret"; never its value)."""
    if data.get("kind") not in (None, mailbox.kind):
        raise MailboxError(422, "a mailbox keeps its kind: add another mailbox for another kind")
    changed: list[str] = []
    if data.get("name") is not None and _name(data["name"]) != mailbox.name:
        _unique(db, mailbox.workspace_id, _name(data["name"]), mailbox.id)
        mailbox.name = _name(data["name"])
        changed.append("name")
    if data.get("interval_minutes") is not None:
        interval = _interval(data["interval_minutes"])
        if interval != mailbox.interval_minutes:
            mailbox.interval_minutes = interval
            changed.append("interval_minutes")
    if data.get("enabled") is not None and bool(data["enabled"]) != mailbox.enabled:
        mailbox.enabled = bool(data["enabled"])
        changed.append("enabled")
    learnt = {k: v for k, v in mailbox.config.items() if k == "service_account"}
    if data.get("config"):
        config = _config(mailbox.kind, {**mailbox.config, **data["config"]})
        moved = [key for key in CONNECTION[mailbox.kind] if config[key] != mailbox.config.get(key)]
        if moved:
            mailbox.config, mailbox.cursor, mailbox.next_poll_at = config | learnt, {}, None
            changed += moved
    if data.get("secret"):
        secret, learnt = _secret(mailbox.kind, str(data["secret"]))
        _seal(box, mailbox, secret)
        mailbox.config = {**mailbox.config, **learnt}
        mailbox.failures, mailbox.next_poll_at = 0, None  # a new credential is tried at the next round
        changed.append("secret")
    return changed


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def view(mailbox: Mailbox) -> dict[str, Any]:
    return {"id": mailbox.id, "name": mailbox.name, "kind": mailbox.kind, "enabled": mailbox.enabled,
            "interval_minutes": mailbox.interval_minutes, "config": dict(mailbox.config),
            "secret_set": bool(mailbox.secret), "status": mailbox.status, "error": mailbox.error,
            "last_poll_at": _iso(mailbox.last_poll_at), "next_poll_at": _iso(mailbox.next_poll_at),
            "last_counts": dict(mailbox.last_counts or {}), "created_at": _iso(mailbox.created_at)}
