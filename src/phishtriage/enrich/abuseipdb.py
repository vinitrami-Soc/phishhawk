"""AbuseIPDB v2 reputation for the originating IP."""

from __future__ import annotations

from typing import Any

from .base import Provider

API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Provider):
    name = "abuseipdb"
    default_rate = 30

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key

    def check_ip(self, ip: str) -> dict[str, Any]:
        return self._lookup("ip:" + ip, lambda: self._fetch(ip))

    def _fetch(self, ip: str) -> dict[str, Any]:
        link = "https://www.abuseipdb.com/check/" + ip
        result = self._http("get", API, params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": self.api_key, "Accept": "application/json"})
        if result["status"] != "ok":
            return dict({k: v for k, v in result.items() if k != "body"}, link=link)
        data = (result["body"] or {}).get("data") or {}
        return {
            "status": "ok",
            "score": int(data.get("abuseConfidenceScore") or 0),
            "reports": int(data.get("totalReports") or 0),
            "country": data.get("countryCode") or "",
            "isp": data.get("isp") or "",
            "usage": data.get("usageType") or "",
            "is_tor": bool(data.get("isTor")),
            "last_reported": data.get("lastReportedAt") or "",
            "link": link,
        }
