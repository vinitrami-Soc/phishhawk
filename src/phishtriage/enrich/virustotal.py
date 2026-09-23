"""VirusTotal v3, lookup-only: URLs by their base64url id, files by SHA256.
Nothing is ever uploaded."""

from __future__ import annotations

import base64
import time
from typing import Any

from .base import Provider

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


class VirusTotal(Provider):
    name = "virustotal"
    default_rate = 4  # the free public API allows 4 requests a minute

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key

    @staticmethod
    def url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _get(self, path: str) -> dict[str, Any]:
        return self._http("get", API + path,
                          headers={"x-apikey": self.api_key, "accept": "application/json"})

    @staticmethod
    def summarise(result: dict[str, Any], link: str) -> dict[str, Any]:
        summary: dict[str, Any] = {"status": result["status"], "link": link}
        if result["status"] != "ok":
            if result.get("detail"):
                summary["detail"] = result["detail"]
            return summary
        attributes = (result["body"].get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        summary.update(
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            engines=sum(int(v) for v in stats.values() if isinstance(v, (int, float))),
            reputation=attributes.get("reputation"),
        )
        if attributes.get("last_analysis_date"):
            summary["last_analysis"] = time.strftime(
                "%Y-%m-%d %H:%M UTC", time.gmtime(int(attributes["last_analysis_date"])))
        classification = attributes.get("popular_threat_classification") or {}
        if classification.get("suggested_threat_label"):
            summary["threat_label"] = classification["suggested_threat_label"]
        for key in ("meaningful_name", "type_description"):
            if attributes.get(key):
                summary[key] = attributes[key]
        return summary

    def lookup_url(self, url: str) -> dict[str, Any]:
        identifier = self.url_id(url)
        return self._lookup("url:" + identifier, lambda: self.summarise(
            self._get("/urls/" + identifier), "%s/url/%s" % (GUI, identifier)))

    def lookup_file(self, sha256: str) -> dict[str, Any]:
        return self._lookup("file:" + sha256, lambda: self.summarise(
            self._get("/files/" + sha256), "%s/file/%s" % (GUI, sha256)))
