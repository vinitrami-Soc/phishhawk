"""SQLite lookup cache, so a re-run of the same mail (or the same campaign
hitting fifty inboxes) does not burn the 500-a-day VirusTotal quota."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import time
from collections.abc import Callable
from typing import Any


def default_cache_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "phishhawk", "lookups.sqlite3")


class Cache:
    """Key/value store with a read-time TTL. Failure to open is not fatal:
    the cache silently disables itself and every lookup goes to the API."""

    def __init__(self, path: str | None, ttl_hours: float = 24.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = path or ""
        self.ttl = max(0.0, ttl_hours) * 3600
        self.clock = clock
        self.hits = 0
        self._conn: sqlite3.Connection | None = None
        if not path:
            return
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, mode=0o700, exist_ok=True)
            # The cache records every URL and file hash looked up, victims'
            # addresses inside URLs included: readable by this user only.
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
            os.chmod(path, 0o600)
            self._conn = sqlite3.connect(path)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS lookups ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL, stored REAL NOT NULL)"
            )
            self._conn.commit()
        except (sqlite3.Error, OSError):
            self._conn = None

    @property
    def enabled(self) -> bool:
        return self._conn is not None

    def get(self, key: str) -> dict[str, Any] | None:
        if self._conn is None:
            return None
        try:
            row = self._conn.execute("SELECT value, stored FROM lookups WHERE key = ?", (key,)).fetchone()
        except sqlite3.Error:
            return None
        if row is None or self.clock() - row[1] > self.ttl:
            return None
        self.hits += 1
        return json.loads(row[0])

    def set(self, key: str, value: dict[str, Any]) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute("INSERT OR REPLACE INTO lookups (key, value, stored) VALUES (?, ?, ?)",
                               (key, json.dumps(value), self.clock()))
            self._conn.commit()
        except sqlite3.Error:
            pass

    def purge(self, provider: str | None = None) -> int:
        """Delete every entry, or only one provider's ("virustotal", "rdap", ...)."""
        if self._conn is None:
            return 0
        if provider:
            cursor = self._conn.execute("DELETE FROM lookups WHERE key LIKE ?", (provider + ":%",))
        else:
            cursor = self._conn.execute("DELETE FROM lookups")
        self._conn.commit()
        return cursor.rowcount

    def stats(self) -> dict[str, Any]:
        """Entry counts per provider, how many are still fresh, and file size."""
        info: dict[str, Any] = {"path": self.path, "enabled": self.enabled, "entries": 0,
                                   "fresh": 0, "providers": {}, "bytes": 0}
        if self._conn is None:
            return info
        now = self.clock()
        providers: dict[str, int] = {}
        fresh = 0
        for key, stored in self._conn.execute("SELECT key, stored FROM lookups"):
            name = key.split(":", 1)[0]
            providers[name] = providers.get(name, 0) + 1
            fresh += now - stored <= self.ttl
        info.update(entries=sum(providers.values()), fresh=fresh, providers=providers)
        with contextlib.suppress(OSError):
            info["bytes"] = os.path.getsize(self.path)
        return info

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
