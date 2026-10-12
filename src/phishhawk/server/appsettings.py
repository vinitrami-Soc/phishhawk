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
