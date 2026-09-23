"""Shared plumbing for reputation providers: HTTP, pacing, caching."""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from typing import Any

from .. import __version__
from ..cache import Cache

USER_AGENT = "phishhawk/%s (+https://github.com/vinitrami-Soc/vinitrami-Soc.github.io)" % __version__
CACHEABLE = ("ok", "not_found")


class RateLimiter:
    """Sliding one-minute window. 0 disables pacing."""

    def __init__(self, per_minute: int, sleep: Callable[[float], None] = time.sleep) -> None:
        self.per_minute = max(0, int(per_minute))
        self._sleep = sleep
        self._hits: deque[float] = deque()

    def wait(self) -> None:
        if not self.per_minute:
            return
        while True:
            now = time.monotonic()
            while self._hits and now - self._hits[0] >= 60:
                self._hits.popleft()
            if len(self._hits) < self.per_minute:
                self._hits.append(now)
                return
            self._sleep(max(0.1, 60 - (now - self._hits[0]) + 0.1))


def new_session() -> Any:
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError("enrichment needs the 'requests' package "
                           "(pip install phishhawk) - or run with --offline") from exc
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


class Provider:
    name = "provider"
    default_rate = 0

    def __init__(self, *, timeout: float = 20, rate_per_minute: int | None = None,
                 session: Any = None, cache: Cache | None = None) -> None:
        self.timeout = timeout
        self.limiter = RateLimiter(self.default_rate if rate_per_minute is None else rate_per_minute)
        self.session = session if session is not None else new_session()
        self.cache = cache
        self.calls = 0
        self._memo: dict[str, dict[str, Any]] = {}

    def _lookup(self, key: str, fetch: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        """Memo -> disk cache -> network, caching only definitive answers."""
        if key in self._memo:
            return self._memo[key]
        cache_key = "%s:%s" % (self.name, key)
        if self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                result = dict(cached, cached=True)
                self._memo[key] = result
                return result
        result = fetch()
        if self.cache is not None and result.get("status") in CACHEABLE:
            self.cache.set(cache_key, result)
        self._memo[key] = result
        return result

    def _http(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        self.limiter.wait()
        self.calls += 1
        try:
            response = getattr(self.session, method)(url, timeout=self.timeout, **kwargs)
        except Exception as exc:  # network failures are data, not crashes
            return {"status": "error", "detail": "%s: %s" % (type(exc).__name__, exc)}
        code = response.status_code
        if code == 404:
            return {"status": "not_found"}
        if code == 429:
            return {"status": "rate_limited", "detail": "%s quota exhausted" % self.name}
        if code in (401, 403):
            return {"status": "auth_error", "detail": "%s rejected the API key" % self.name}
        if code >= 400:
            return {"status": "error", "detail": "HTTP %s" % code}
        try:
            return {"status": "ok", "body": response.json()}
        except ValueError:
            return {"status": "error", "detail": "invalid JSON from %s" % self.name}
