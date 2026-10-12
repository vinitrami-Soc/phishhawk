"""Campaigns in the web app: rebuilt from the records kept for each message (tier 2), shown with what links them;
a subject or display name in clear only while a message's content still exists (spec 6.4)."""

from phishhawk.campaign import correlate
from phishhawk.pipeline import triage_bytes
from phishhawk.server import worker

from conftest import build_eml

DOC = (b"%PDF-1.4 invoice 7731", "application", "pdf", "invoice.pdf")


def _lure(href):
    return ('<p>Your mailbox is full. Verify your account now or it will be suspended.</p>'
            '<a href="%s">https://outlook.office.com/verify</a>' % href)


def _messages():
    """Three campaigns and two loners: a shared attachment, a shared phishing domain, and two weak traits
    (subject and display name) together."""
    date = "Mon, 05 Oct 2026 09:00:00 +0000"
    return [
        build_eml(subject="Invoice %d" % i, sender="<a%d@one%d.example>" % (i, i), to="alice@corp.example",
                  attachments=[DOC], headers=[("Date", date)]) for i in range(3)
    ] + [
        build_eml(subject="Mailbox", sender="<s%d@sender%d.example>" % (i, i), to="bob@corp.example",
                  html=_lure("https://login.evil-portal.example/%d" % i),
                  headers=[("Date", "Tue, 06 Oct 2026 1%d:00:00 +0000" % i)]) for i in range(2)
    ] + [
        build_eml(subject="Payroll update for October", sender='"HR Desk" <hr%d@desk%d.example>' % (i, i),
                  headers=[("Date", date)]) for i in range(2)
    ] + [build_eml(subject="Lunch?", sender="<friend@clean.example>"),
         build_eml(subject="Hi", sender="<x@y.example>")]


def _submit_all(client, services, messages):
    files = [("files", ("m%d.eml" % i, m, "message/rfc822")) for i, m in enumerate(messages)]
    batch = client.post("/api/v1/submissions", files=files, data={"offline": "true"}).json()["batch_id"]
    while worker.run_one(services):
        pass
    return {m["position"]: m for m in client.get("/api/v1/batches/%d" % batch).json()["messages"]}


def test_the_campaigns_match_what_the_cli_reports_for_the_same_messages(alice, services):
    messages = _messages()
    rows = _submit_all(alice, services, messages)
    sha = {i: alice.get("/api/v1/analyses/%d" % rows[i + 1]["analysis_id"]).json()["sha256"]
           for i in range(len(messages))}
    expected = correlate([("m%d.eml" % i, triage_bytes(m, "m%d.eml" % i)) for i, m in enumerate(messages)])
    campaigns = alice.get("/api/v1/campaigns").json()
    assert len(campaigns) == len(expected["clusters"]) == 3

    def members(detail):
        return sorted(m["sha256"] for m in detail["messages"])

    got = {tuple(members(alice.get("/api/v1/campaigns/%d" % c["id"]).json())): c for c in campaigns}
    for cluster in expected["clusters"]:
        key = tuple(sorted(sha[int(m["path"][1:-4])] for m in cluster["messages"]))
        campaign = got[key]
        assert (campaign["size"], campaign["first_seen"], campaign["last_seen"], campaign["worst_verdict"],
                campaign["verdicts"]) == (cluster["size"], cluster["first_seen"], cluster["last_seen"],
                                          cluster["worst_verdict"], cluster["verdicts"])
        assert [s["kind"] for s in campaign["shared"]] == [s["kind"] for s in cluster["shared"]]
        assert campaign["senders"] == cluster["senders"]


def test_a_campaign_shows_what_links_it_and_who_received_it(alice, services):
    _submit_all(alice, services, _messages())
    by_kind = {c["shared"][0]["kind"]: c for c in alice.get("/api/v1/campaigns").json()}
    invoice = alice.get("/api/v1/campaigns/%d" % by_kind["attachment"]["id"]).json()
    assert invoice["recipients"] == ["alice@corp.example"] and invoice["recipients_complete"]
    assert invoice["recipient_count"] == 3 and len(invoice["messages"]) == 3
    assert invoice["messages"][0]["subject"].startswith("Invoice")
    payroll = alice.get("/api/v1/campaigns/%d" % by_kind["subject"]["id"]).json()
    assert {(s["kind"], s["value"]) for s in payroll["shared"]} == {("subject", "payroll update for october"),
                                                                    ("display name", "hr desk")}


def test_after_its_messages_are_deleted_a_campaign_keeps_its_shape_but_not_their_words(alice, admin, services):
    _submit_all(alice, services, _messages())
    payroll = next(c for c in alice.get("/api/v1/campaigns").json() if c["shared"][0]["kind"] == "subject")
    for message in alice.get("/api/v1/campaigns/%d" % payroll["id"]).json()["messages"]:
        alice.delete("/api/v1/messages/%d" % message["message_id"])
    detail = alice.get("/api/v1/campaigns/%d" % payroll["id"]).json()
    assert detail["size"] == 2 and {s["value"] for s in detail["shared"]} == {None}  # same subject, same name
    assert detail["recipients"] == [] and not detail["recipients_complete"]
    assert all(m["subject"] is None for m in detail["messages"])
    page = alice.get("/campaigns/%d" % payroll["id"]).text
    assert "Same subject" in page and "payroll" not in page.lower()


def test_one_rebuild_at_a_time_and_a_campaign_keeps_its_id_as_it_grows(alice, services):
    from sqlalchemy import select

    from phishhawk.server.db import transaction
    from phishhawk.server.models import Job

    first = _submit_all(alice, services, _messages()[:2])
    campaign = alice.get("/api/v1/campaigns").json()[0]
    _submit_all(alice, services, _messages()[2:3] + _messages()[-1:])  # one more invoice, and a loner
    grown = alice.get("/api/v1/campaigns").json()[0]
    assert (grown["id"], grown["size"]) == (campaign["id"], 3) and campaign["id"] == first[1]["message_id"]
    with transaction(services.sessions) as s:
        rebuilds = s.scalars(select(Job).where(Job.kind == "campaign_rebuild")).all()
        assert len(rebuilds) <= 3  # not one per message: at most one waits at a time


def test_the_campaign_pages(alice, services):
    _submit_all(alice, services, _messages())
    listing = alice.get("/campaigns")
    assert listing.status_code == 200 and listing.text.count('href="/campaigns/') == 3
    first = alice.get("/api/v1/campaigns").json()[0]
    page = alice.get("/campaigns/%d" % first["id"])
    assert page.status_code == 200 and page.text.count('href="/analyses/') == first["size"]


def test_deleting_a_message_completely_rebuilds_its_campaign(alice, admin, services):
    rows = _submit_all(alice, services, _messages()[5:7] + _messages()[-1:])  # the payroll pair, and a loner
    [campaign] = alice.get("/api/v1/campaigns").json()
    assert admin.delete("/api/v1/messages/%d?scope=all" % rows[1]["message_id"]).status_code == 200
    while worker.run_one(services):
        pass
    assert alice.get("/api/v1/campaigns").json() == [] and campaign["size"] == 2


def test_the_campaigns_are_rebuilt_hourly_as_messages_leave_the_window(alice, services):
    import datetime as dt

    from sqlalchemy import select

    from phishhawk.server.db import transaction
    from phishhawk.server.models import Job

    _submit_all(alice, services, _messages()[5:7])
    with transaction(services.sessions) as s:
        for job in s.scalars(select(Job).where(Job.kind == "campaign_rebuild")):
            job.finished_at -= dt.timedelta(minutes=61)
    worker.schedule(services)
    with transaction(services.sessions) as s:
        assert s.scalars(select(Job).where(Job.kind == "campaign_rebuild", Job.status == "queued")).one()
