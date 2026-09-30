"""Settings a SOC sets once: its domains, its mail server, partners to
trust, domains to always flag, extra brands and lure phrases.

Read from --config, $PHISHHAWK_CONFIG, or the user's config folder
(~/.config/phishhawk/config.toml or config.json). Never from the current
directory: a config dropped into a folder of reported mail must not be
able to allowlist an attacker's domain.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import knowledge

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None

FAIL_LEVELS = ("never", "suspicious", "likely", "malicious")
MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    path: str = ""
    protect: list[str] = field(default_factory=list)
    trusted_authserv: list[str] = field(default_factory=list)
    allow_domains: list[str] = field(default_factory=list)  # your partners: never lookalikes, never IOCs
    block_domains: list[str] = field(default_factory=list)  # always flagged when seen
    brands: dict[str, list[str]] = field(default_factory=dict)
    lures: dict[str, list[str]] = field(default_factory=dict)
    yara: str = ""
    fail_on: str = ""
    offline: bool = False
    max_size: int = 0
    vt_rate: int = 0
    vt_budget: int = 0
    tlp: str = "amber"


_STRING_LISTS = ("protect", "trusted_authserv", "allow_domains", "block_domains")
_KEYS = set(_STRING_LISTS) | {"brands", "lures", "yara", "fail_on", "offline", "max_size", "vt_rate", "vt_budget",
                               "tlp"}


def default_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    for name in ("config.toml", "config.json"):
        candidate = os.path.join(base, "phishhawk", name)
        if os.path.isfile(candidate):
            return candidate
    return ""


def _domain(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 253 \
            or any(c.isspace() for c in value.strip()):
        raise ConfigError("%s: %r is not a domain" % (key, value))
    return value.strip().lower().rstrip(".")


def _strings(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key, [])
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ConfigError("%s must be a list of strings" % key)
    return [_domain(item, key) if key != "trusted_authserv" else str(item).strip().lower() for item in value]


def parse(data: dict[str, Any], path: str = "") -> Config:
    unknown = sorted(set(data) - _KEYS)
    if unknown:
        raise ConfigError("unknown setting(s): %s (known: %s)" % (", ".join(unknown), ", ".join(sorted(_KEYS))))
    config = Config(path=path)
    for key in _STRING_LISTS:
        setattr(config, key, _strings(data, key))
    for key in ("brands", "lures"):
        table = data.get(key, {})
        if not isinstance(table, dict):
            raise ConfigError("%s must be a table of name = [values]" % key)
        cleaned: dict[str, list[str]] = {}
        for name, values in table.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(values, list) or not values:
                raise ConfigError("%s.%s must be a non-empty list" % (key, name))
            if key == "brands":
                cleaned[name.strip().lower()] = [_domain(v, "brands.%s" % name) for v in values]
            else:
                phrases = [str(v).strip().lower() for v in values if str(v).strip()]
                if any(len(p) < 4 for p in phrases):
                    raise ConfigError("lures.%s: phrases must be at least 4 characters" % name)
                cleaned[name.strip().lower()] = phrases
        setattr(config, key, cleaned)
    config.yara = str(data.get("yara", "") or "")
    fail_on = str(data.get("fail_on", "") or "").lower()
    if fail_on and fail_on not in FAIL_LEVELS:
        raise ConfigError("fail_on must be one of %s" % ", ".join(FAIL_LEVELS))
    config.fail_on = fail_on
    config.offline = bool(data.get("offline", False))
    for key in ("max_size", "vt_rate", "vt_budget"):
        value = data.get(key, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ConfigError("%s must be a whole number" % key)
        setattr(config, key, value)
    tlp = str(data.get("tlp", "amber")).lower()
    if tlp not in ("clear", "white", "green", "amber", "amber+strict", "red"):
        raise ConfigError("tlp must be clear, green, amber, amber+strict or red")
    config.tlp = tlp
    return config


def load(path: str = "") -> Config:
    """The config at `path`, else $PHISHHAWK_CONFIG, else the user default,
    else built-in defaults."""
    path = path or os.environ.get("PHISHHAWK_CONFIG", "") or default_path()
    if not path:
        return Config()
    try:
        if not os.path.isfile(path):
            raise ConfigError("%s is not a file" % path)
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc.strerror or exc)) from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("%s is larger than 1 MB" % path)
    try:
        if path.lower().endswith(".toml"):
            if tomllib is None:
                raise ConfigError("TOML settings need Python 3.11 or newer; use a .json file instead")
            data = tomllib.loads(raw.decode("utf-8"))
        else:
            data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError("%s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise ConfigError("%s must hold a table of settings" % path)
    return parse(data, path)


def apply_knowledge(config: Config) -> None:
    """Add the configured brands and lures to the built-in lists."""
    knowledge.extend(brands=config.brands, lures=config.lures)
