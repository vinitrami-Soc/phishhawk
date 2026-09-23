"""Domain registration date over RDAP, the keyless successor to WHOIS.
A domain registered this week sending mail about your mailbox is one of the
strongest phishing signals there is."""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from typing import Any

from .base import Provider

BOOTSTRAP = "https://rdap.org/domain/"
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def _registrar(entities: list[dict[str, Any]]) -> str:
    for entity in entities or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray") or []
        for item in (vcard[1] if len(vcard) > 1 else []):
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return ""


class Rdap(Provider):
    name = "rdap"
    default_rate = 20

    def __init__(self, today: Callable[[], dt.date] = dt.date.today, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.today = today

    def domain_age(self, domain: str) -> dict[str, Any]:
        record = dict(self._lookup("domain:" + domain, lambda: self._fetch(domain)))
        # Age is computed at read time so a cached record never goes stale.
        if record.get("status") == "ok" and record.get("registered"):
            registered = dt.date.fromisoformat(record["registered"])
            record["age_days"] = (self.today() - registered).days
        return record

    def _fetch(self, domain: str) -> dict[str, Any]:
        link = BOOTSTRAP + domain
        result = self._http("get", link, headers={"Accept": "application/rdap+json"})
        if result["status"] != "ok":
            return dict({k: v for k, v in result.items() if k != "body"}, link=link)
        body = result["body"] or {}
        registered = ""
        for event in body.get("events") or []:
            if event.get("eventAction") == "registration":
                match = _DATE_RE.search(str(event.get("eventDate", "")))
                if match:
                    registered = "-".join(match.groups())
                break
        if not registered:
            return {"status": "no_date", "link": link}
        return {"status": "ok", "registered": registered,
                "registrar": _registrar(body.get("entities") or []), "link": link}
