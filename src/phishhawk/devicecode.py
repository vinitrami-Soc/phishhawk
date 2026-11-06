"""Sign in to Microsoft Graph from the command line: the OAuth 2.0 device
authorization grant (RFC 8628), as Microsoft's own MSAL library does it.

`phishhawk graph --sign-in --client-id ID` reads Microsoft's sign-in
endpoints from https://login.microsoftonline.com/<tenant>/v2.0/.well-known/
openid-configuration, asks for a code, and shows the reader where to enter
it. It then asks for the token every few seconds ("authorization_pending";
"slow_down" adds five seconds) until the reader has signed in in a browser,
on any device. The token is kept in memory for this run only: nothing is
written to disk. The client id is an app registration of your own in your
Microsoft Entra tenant that allows this flow for a public client; PhishHawk
ships none.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .enrich.base import new_session

AUTHORITY = "login.microsoftonline.com"
DISCOVERY = "https://%s/%%s/v2.0/.well-known/openid-configuration" % AUTHORITY
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
MAIL_READ = "https://graph.microsoft.com/Mail.Read"
MAIL_READ_SHARED = "https://graph.microsoft.com/Mail.Read.Shared"
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


class SignInError(Exception):
    pass


def _json(response: Any, what: str) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise SignInError("%s: Microsoft's answer is not JSON (HTTP %s)" % (what, response.status_code))
    return body


def _endpoint(config: dict[str, Any], name: str) -> str:
    url = str(config.get(name) or "")
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() != AUTHORITY:
        raise SignInError("the %s is not on https://%s: %r" % (name.replace("_", " "), AUTHORITY, url[:80]))
    return url


def sign_in(client_id: str, tenant: str = "organizations", shared: bool = False, session: Any = None,
            show: Callable[[str], Any] = print, sleep: Callable[[float], Any] = time.sleep,
            clock: Callable[[], float] = time.monotonic, timeout: float = 30) -> str:
    """An access token for Graph with Mail.Read (and Mail.Read.Shared for
    another mailbox), once the reader has entered the code shown."""
    if not _TENANT_RE.fullmatch(tenant or ""):
        raise SignInError("--tenant must be a tenant id or domain, or organizations, common or consumers")
    if not client_id.strip():
        raise SignInError("--client-id (or $PHISHHAWK_GRAPH_CLIENT_ID) must name your app registration")
    session = session if session is not None else new_session()
    try:
        config = _json(session.get(DISCOVERY % tenant, timeout=timeout), "tenant discovery")
        device_url, token_url = _endpoint(config, "device_authorization_endpoint"), \
            _endpoint(config, "token_endpoint")
        scope = MAIL_READ + (" " + MAIL_READ_SHARED if shared else "")
        flow = _json(session.post(device_url, data={"client_id": client_id, "scope": scope}, timeout=timeout,
                                  allow_redirects=False), "device code")
        if not flow.get("device_code"):
            raise SignInError("Microsoft gave no device code: %s" % (flow.get("error_description")
                                                                      or flow.get("error") or "no reason given"))
        show(str(flow.get("message") or "To sign in, open %s and enter the code %s"
                 % (flow.get("verification_uri"), flow.get("user_code"))))
        interval = max(1, int(flow.get("interval") or 5))
        deadline = clock() + int(flow.get("expires_in") or 900)
        while True:
            sleep(interval)
            answer = _json(session.post(token_url, timeout=timeout, allow_redirects=False, data={
                "grant_type": GRANT_TYPE, "client_id": client_id, "device_code": flow["device_code"]}), "token")
            if answer.get("access_token"):
                return str(answer["access_token"])
            error = str(answer.get("error") or "")
            if error == "slow_down":
                interval += 5
            elif error != "authorization_pending":
                raise SignInError("sign-in ended: %s" % (answer.get("error_description") or error or "no token"))
            if clock() >= deadline:
                raise SignInError("the code expired before anyone signed in; run the command again")
    except SignInError:
        raise
    except Exception as exc:  # the network: say what failed rather than crash
        raise SignInError("could not reach %s: %s: %s" % (AUTHORITY, type(exc).__name__, exc)) from exc
