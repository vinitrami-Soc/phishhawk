"""The sender's domain in DNS, asked of Cloudflare's resolver (1.1.1.1) over
DNS over HTTPS, in its JSON form: `GET https://cloudflare-dns.com/dns-query
?name=...&type=...` with `Accept: application/dns-json`. The answer's
`Status` is the DNS response code (0 an answer, 3 no such name).

Mail from a domain that does not exist cannot be answered, and a domain with
neither an MX nor an address record has nowhere to receive mail (RFC 5321
falls back from MX to the address). Only domain names are sent, never the
message, and only for senders that are not free mail, well-known brands or
your own domains.
"""

from __future__ import annotations

from typing import Any

from .base import Provider

RESOLVER = "https://cloudflare-dns.com/dns-query"
NOERROR, NXDOMAIN = 0, 3
MAX_MX = 5


class Dns(Provider):
    name = "dns"
    default_rate = 60

    def records(self, domain: str) -> dict[str, Any]:
        """{'status': 'ok', 'exists': False} for a name that does not exist;
        {'status': 'ok', 'exists': True, 'mx': [...], 'address': bool}
        otherwise; or a failed lookup's status, never a guess."""
        return dict(self._lookup("domain:" + domain, lambda: self._fetch(domain)))

    def _ask(self, domain: str, kind: str) -> dict[str, Any]:
        result = self._http("get", RESOLVER, params={"name": domain, "type": kind},
                            headers={"Accept": "application/dns-json"})
        if result["status"] != "ok":
            return result
        body = result["body"] if isinstance(result.get("body"), dict) else {}
        status = body.get("Status")
        if status not in (NOERROR, NXDOMAIN):
            return {"status": "error", "detail": "the resolver answered with DNS code %s" % status}
        wanted = {"MX": 15, "A": 1}[kind]
        answers = [str(item.get("data", "")) for item in body.get("Answer") or []
                   if isinstance(item, dict) and item.get("type") == wanted]
        return {"status": "ok", "exists": status == NOERROR, "answers": answers}

    def _fetch(self, domain: str) -> dict[str, Any]:
        mx = self._ask(domain, "MX")
        if mx["status"] != "ok":
            return mx
        if not mx["exists"]:
            return {"status": "ok", "exists": False}
        hosts = []
        for data in mx["answers"]:
            parts = data.split()
            if len(parts) == 2 and parts[1].rstrip(".") and parts[1] != ".":  # "10 mx.example." ("0 ." is null MX)
                hosts.append(parts[1].rstrip(".").lower())
        if hosts:
            return {"status": "ok", "exists": True, "mx": hosts[:MAX_MX], "address": False}
        address = self._ask(domain, "A")
        if address["status"] != "ok":
            return address
        return {"status": "ok", "exists": True, "mx": [], "address": bool(address["answers"])}
