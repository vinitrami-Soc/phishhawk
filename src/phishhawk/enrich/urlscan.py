"""urlscan.io: read-only search by default; submission is opt-in."""

from __future__ import annotations

from typing import Any

from ..extract import is_ip
from .base import Provider

API = "https://urlscan.io/api/v1"


class UrlScan(Provider):
    name = "urlscan"
    default_rate = 30

    def __init__(self, api_key: str = "", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        return headers

    def search_host(self, host: str) -> dict[str, Any]:
        field = "page.ip" if is_ip(host) else "page.domain"
        return self._lookup("search:" + host, lambda: self._search('%s:"%s"' % (field, host), host))

    def _search(self, query: str, host: str) -> dict[str, Any]:
        result = self._http("get", API + "/search/", params={"q": query, "size": 5},
                            headers=self._headers())
        if result["status"] != "ok":
            return {key: value for key, value in result.items() if key != "body"}
        body = result["body"] or {}
        results = body.get("results") or []
        summary: dict[str, Any] = {
            "status": "ok",
            "total": int(body.get("total", len(results))),
            "malicious_hits": sum(
                1 for item in results
                if ((item.get("verdicts") or {}).get("overall") or {}).get("malicious")),
            "link": "https://urlscan.io/search/#" + host,
        }
        if results:
            newest = results[0]
            summary["latest_scan"] = {
                "url": (newest.get("page") or {}).get("url", ""),
                "time": (newest.get("task") or {}).get("time", ""),
                "report": newest.get("result", ""),
            }
        return summary

    def submit(self, url: str, visibility: str = "unlisted") -> dict[str, Any]:
        """Queue a live scan. Sends the full URL to a third party: opt-in only."""
        if not self.api_key:
            return {"status": "auth_error", "detail": "urlscan.io submission needs an API key"}
        result = self._http("post", API + "/scan/", json={"url": url, "visibility": visibility},
                            headers={**self._headers(), "Content-Type": "application/json"})
        if result["status"] != "ok":
            return {key: value for key, value in result.items() if key != "body"}
        return {"status": "submitted", "report": (result["body"] or {}).get("result", ""),
                "visibility": visibility}
