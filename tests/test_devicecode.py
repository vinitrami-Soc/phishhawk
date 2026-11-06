"""Signing in to Microsoft Graph from the command line with the device code flow."""

import pytest

from phishhawk import devicecode

from conftest import FakeResponse, FakeSession

BASE = "https://login.microsoftonline.com/contoso.example/oauth2/v2.0/"
DISCOVERY = {"device_authorization_endpoint": BASE + "devicecode", "token_endpoint": BASE + "token"}
FLOW = {"device_code": "DC-1", "user_code": "ABCD-EFGH", "verification_uri": "https://microsoft.com/devicelogin",
        "expires_in": 900, "interval": 5,
        "message": "To sign in, open https://microsoft.com/devicelogin and enter ABCD-EFGH"}


def flow_session(*token_answers):
    answers = list(token_answers)

    def respond(method, url, kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return FakeResponse(200, DISCOVERY)
        if url.endswith("/devicecode"):
            return FakeResponse(200, FLOW)
        return answers.pop(0)
    return FakeSession(respond)


def test_the_user_is_shown_the_code_and_the_token_comes_back_once_they_sign_in():
    shown, slept = [], []
    session = flow_session(FakeResponse(400, {"error": "authorization_pending"}),
                           FakeResponse(400, {"error": "slow_down"}),
                           FakeResponse(200, {"access_token": "eyJ0.token", "token_type": "Bearer"}))
    token = devicecode.sign_in("11111111-2222-3333-4444-555555555555", tenant="contoso.example", session=session,
                               show=shown.append, sleep=slept.append, clock=lambda: 0)
    assert token == "eyJ0.token"
    assert shown == [FLOW["message"]]
    assert slept == [5, 5, 10]  # slow_down adds five seconds to the interval
    calls = session.calls
    assert calls[0][1] == "https://login.microsoftonline.com/contoso.example/v2.0/.well-known/openid-configuration"
    assert calls[1][2]["data"] == {"client_id": "11111111-2222-3333-4444-555555555555",
                                   "scope": "https://graph.microsoft.com/Mail.Read"}
    assert calls[2][2]["data"]["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
    assert calls[2][2]["data"]["device_code"] == "DC-1"


def test_another_mailbox_asks_for_shared_mail_too():
    session = flow_session(FakeResponse(200, {"access_token": "t"}))
    devicecode.sign_in("cid", tenant="organizations", shared=True, session=session, show=lambda m: None,
                       sleep=lambda s: None, clock=lambda: 0)
    assert session.calls[1][2]["data"]["scope"] == \
        "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Read.Shared"


@pytest.mark.parametrize("error", ["authorization_declined", "expired_token", "bad_verification_code"])
def test_a_refusal_ends_the_sign_in(error):
    session = flow_session(FakeResponse(400, {"error": error, "error_description": "AADSTS: " + error}))
    with pytest.raises(devicecode.SignInError, match=error):
        devicecode.sign_in("cid", session=session, show=lambda m: None, sleep=lambda s: None, clock=lambda: 0)


def test_waiting_stops_when_the_code_expires():
    ticks = iter([0, 400, 800, 1000])
    session = flow_session(*[FakeResponse(400, {"error": "authorization_pending"})] * 5)
    with pytest.raises(devicecode.SignInError, match="expired"):
        devicecode.sign_in("cid", session=session, show=lambda m: None, sleep=lambda s: None,
                           clock=lambda: next(ticks))


@pytest.mark.parametrize("tenant", ["contoso.example/../evil", "a b", "", "x" * 300])
def test_a_tenant_is_a_name_or_an_id(tenant):
    with pytest.raises(devicecode.SignInError):
        devicecode.sign_in("cid", tenant=tenant, session=FakeSession(), show=print, sleep=print, clock=lambda: 0)


def test_endpoints_off_microsoft_s_sign_in_host_are_refused():
    def respond(method, url, kwargs):
        return FakeResponse(200, {"device_authorization_endpoint": "https://evil.example/devicecode",
                                  "token_endpoint": "https://evil.example/token"})
    with pytest.raises(devicecode.SignInError, match="login.microsoftonline.com"):
        devicecode.sign_in("cid", session=FakeSession(respond), show=print, sleep=print, clock=lambda: 0)


def test_graph_sign_in_uses_the_token_for_this_run_only(monkeypatch, capsys):
    from phishhawk import mailapi
    from phishhawk.cli import main
    asked, tokens = [], []
    monkeypatch.delenv("PHISHHAWK_GRAPH_TOKEN", raising=False)
    monkeypatch.setenv("PHISHHAWK_GRAPH_CLIENT_ID", "app-1")

    def fake_sign_in(client_id, tenant="organizations", shared=False, show=print, **kwargs):
        asked.append((client_id, tenant, shared))
        show("To sign in, open https://microsoft.com/devicelogin and enter ABCD")
        return "signed-in-token"

    def fake_fetch(source, limit, seen=frozenset(), **kwargs):
        tokens.append(source.token)
        return iter(())

    monkeypatch.setattr(devicecode, "sign_in", fake_sign_in)
    monkeypatch.setattr(mailapi, "fetch_graph", fake_fetch)
    assert main(["graph", "--sign-in", "--tenant", "contoso.example", "--mailbox", "soc@contoso.example",
                 "--offline", "--no-color", "--quiet"]) == 0
    assert asked == [("app-1", "contoso.example", True)]
    assert tokens == ["signed-in-token"]
    assert "devicelogin" in capsys.readouterr().err


def test_graph_sign_in_needs_a_client_id(monkeypatch):
    from phishhawk.cli import main
    monkeypatch.delenv("PHISHHAWK_GRAPH_TOKEN", raising=False)
    monkeypatch.delenv("PHISHHAWK_GRAPH_CLIENT_ID", raising=False)
    with pytest.raises(SystemExit):
        main(["graph", "--sign-in", "--offline"])
