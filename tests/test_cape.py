"""Handing a sandbox pack to a self-hosted CAPE sandbox (apiv2)."""

import pytest

from phishhawk import cape

from conftest import FakeResponse, FakeSession

OK = {"error": [], "errors": [], "data": {"task_ids": [41, 42], "message": "Task IDs 41, 42 have been submitted"}}


def test_a_pack_is_posted_to_the_file_endpoint_with_its_password(tmp_path):
    pack = tmp_path / "ab12.zip"
    pack.write_bytes(b"PK\x03\x04 pack")
    session = FakeSession(queue=[FakeResponse(200, OK)])
    result = cape.submit("https://cape.example-corp.co.uk/", "t0k3n", str(pack), session=session)
    assert result == {"status": "ok", "task_ids": [41, 42], "message": "Task IDs 41, 42 have been submitted"}
    method, url, kwargs = session.calls[0]
    assert (method, url) == ("post", "https://cape.example-corp.co.uk/apiv2/tasks/create/file/")
    assert kwargs["headers"]["Authorization"] == "Token t0k3n"
    name, data = kwargs["files"]["file"][:2]
    assert (name, data) == ("ab12.zip", b"PK\x03\x04 pack")
    assert kwargs["data"]["options"] == "password=infected"
    assert kwargs["allow_redirects"] is False  # the token goes to CAPE and nowhere else


def test_without_a_token_no_authorization_header_is_sent(tmp_path):
    pack = tmp_path / "p.zip"
    pack.write_bytes(b"PK")
    session = FakeSession(queue=[FakeResponse(200, OK)])
    cape.submit("http://10.0.0.5:8000", "", str(pack), session=session)
    assert "Authorization" not in session.calls[0][2]["headers"]


@pytest.mark.parametrize("answer, detail", [
    (FakeResponse(200, {"error": True, "error_value": "File Create API is Disabled"}),
     "File Create API is Disabled"),
    (FakeResponse(401, {"detail": "Invalid token."}), "HTTP 401"),
    (FakeResponse(200, None), "not JSON"),
])
def test_cape_s_refusals_are_reported(tmp_path, answer, detail):
    pack = tmp_path / "p.zip"
    pack.write_bytes(b"PK")
    result = cape.submit("https://cape.example-corp.co.uk", "t", str(pack), session=FakeSession(queue=[answer]))
    assert result["status"] == "error" and detail in result["detail"]


@pytest.mark.parametrize("url", ["http://cape.example.com", "ftp://10.0.0.5", "https://", "cape.example.com"])
def test_a_token_is_never_sent_in_clear_text_over_the_internet(url):
    with pytest.raises(cape.CapeError):
        cape.check_url(url)


def test_plain_http_is_allowed_on_this_machine_and_the_local_network():
    for url in ("http://127.0.0.1:8000", "http://localhost:8000", "http://10.0.0.5", "http://192.168.1.20:8000",
                "https://cape.example.com"):
        cape.check_url(url)


def test_the_sandbox_command_submits_each_pack_and_reports_its_tasks(tmp_path, monkeypatch, capsys):
    from phishhawk.cli import main
    first, second = tmp_path / "a.zip", tmp_path / "b.zip"
    first.write_bytes(b"PK")
    second.write_bytes(b"PK")
    session = FakeSession(queue=[FakeResponse(200, OK), FakeResponse(200, {"error": True, "error_value": "busy"})])
    monkeypatch.setattr(cape, "new_session", lambda: session)
    monkeypatch.setenv("PHISHHAWK_CAPE_TOKEN", "t0k3n")
    code = main(["sandbox", "submit", "--cape", "https://cape.example-corp.co.uk", str(first), str(second),
                 "--no-color"])
    out = capsys.readouterr()
    assert code == 3  # one pack was not taken
    assert "a.zip: CAPE tasks 41, 42" in out.out
    assert "b.zip: busy" in out.err
    assert all(kwargs["headers"]["Authorization"] == "Token t0k3n" for _, _, kwargs in session.calls)


def test_the_token_is_never_taken_on_the_command_line():
    from phishhawk.cli import main
    with pytest.raises(SystemExit):
        main(["sandbox", "submit", "--cape", "https://cape.example.org", "--token", "x", "a.zip"])
