"""Settings an admin changes in the web app: providers and their keys,
domains, and the limits whose defaults come from the environment. Keys and
the trait key are sealed with the encryption key.

Each workspace has its own providers, keys, domain lists, retention and
campaign window. The upload limits and the trait key belong to the whole
server (workspace SERVER): only its owner changes the limits."""

from __future__ import annotations

import base64
import os
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..analysis import PROVIDERS, AnalysisOptions
from .config import ServerSettings
from .crypto import Box
from .models import SERVER, Setting

LISTS = ("providers", "protected_domains", "allow_domains", "block_domains", "trusted_authserv")
WORKSPACE_LIMITS = ("retention_days", "campaign_window_days")
SERVER_LIMITS = ("max_upload_mb", "max_batch_messages")
LIMITS = WORKSPACE_LIMITS + SERVER_LIMITS
KEYED = ("virustotal", "urlscan", "abuseipdb")  # RDAP needs no key
PROVIDERS_ALL = PROVIDERS


def get_value(db: Session, workspace_id: int, key: str, default: Any = None) -> Any:
    row = db.get(Setting, (workspace_id, key))
    return default if row is None else row.value


def set_value(db: Session, workspace_id: int, key: str, value: Any) -> None:
    row = db.get(Setting, (workspace_id, key))
    if row is None:
        db.add(Setting(workspace_id=workspace_id, key=key, value=value))
    else:
        row.value = value


def get_secret(db: Session, box: Box, workspace_id: int, name: str) -> str:
    sealed = get_value(db, workspace_id, "secret:" + name)
    return box.open(base64.b64decode(sealed), "setting:" + name).decode("utf-8") if sealed else ""


def set_secret(db: Session, box: Box, workspace_id: int, name: str, value: str) -> None:
    sealed = box.seal(value.encode("utf-8"), "setting:" + name) if value else None
    set_value(db, workspace_id, "secret:" + name, base64.b64encode(sealed).decode("ascii") if sealed else None)


def limit(db: Session, settings: ServerSettings, name: str, workspace_id: int = SERVER) -> int:
    """A server limit is the same for every workspace; a workspace limit needs the workspace."""
    if name in SERVER_LIMITS:
        workspace_id = SERVER
    elif workspace_id == SERVER:
        raise ValueError("%s is a workspace's limit: say which workspace" % name)
    value = get_value(db, workspace_id, name)
    return int(value) if value is not None else int(getattr(settings, name))


def trait_key(db: Session, box: Box) -> bytes:
    """One for the server, made once and never changed (see the spec, section 5.2)."""
    existing = get_secret(db, box, SERVER, "trait_key")
    if existing:
        return base64.b64decode(existing)
    key = os.urandom(32)
    try:
        with db.begin_nested():  # another worker may be making it at this moment: the first stored is kept
            set_secret(db, box, SERVER, "trait_key", base64.b64encode(key).decode("ascii"))
    except IntegrityError:
        return base64.b64decode(get_secret(db, box, SERVER, "trait_key"))
    return key


def analysis_options(db: Session, box: Box, settings: ServerSettings, offline: bool,
                     workspace_id: int) -> AnalysisOptions:
    """The workspace's own providers, keys and domain lists."""
    enabled = frozenset(p for p in get_value(db, workspace_id, "providers", []) if p in PROVIDERS)
    return AnalysisOptions(
        providers=frozenset() if offline else enabled,
        keys={name: get_secret(db, box, workspace_id, "key:" + name) for name in KEYED if name in enabled},
        protected=list(get_value(db, workspace_id, "protected_domains", [])),
        allow_domains=list(get_value(db, workspace_id, "allow_domains", [])),
        block_domains=list(get_value(db, workspace_id, "block_domains", [])),
        trusted_authserv=list(get_value(db, workspace_id, "trusted_authserv", [])),
        cache_path=str(settings.data_dir / ("lookups-%d.sqlite3" % workspace_id)),  # made with its own keys
    )


def public_view(db: Session, box: Box, settings: ServerSettings, workspace_id: int) -> dict[str, Any]:
    """Everything the Settings page shows; keys only as their last four characters. server_limits names the limits
    only the server's owner can change."""
    view: dict[str, Any] = {name: list(get_value(db, workspace_id, name, [])) for name in LISTS}
    view.update({name: limit(db, settings, name, workspace_id) for name in LIMITS})
    view["server_limits"] = list(SERVER_LIMITS)
    view["keys"] = {}
    for name in KEYED:
        key = get_secret(db, box, workspace_id, "key:" + name)
        view["keys"][name] = ("..." + key[-4:]) if key else ""
    return view
