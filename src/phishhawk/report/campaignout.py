"""Campaign correlation in the terminal, as CSV and as a Markdown ticket note.
Every value came from attacker mail: hosts and links are defanged, text is
made printable, and CSV cells cannot start a formula."""

from __future__ import annotations

import csv
import io
import os
from typing import Any

from .common import defang_ioc, plural, printable
from .console import Palette
from .csvout import _safe
from .markdown import _cell, _code

_IOC_KIND = {"link": "url", "domain": "domain", "host": "domain", "sender domain": "domain", "sender": "email",
             "reply-to": "email", "attachment": "sha256", "wallet": "crypto-wallet", "phone": "phone",
             "originating IP": "ipv4"}
_TONE = {"MALICIOUS": "red", "LIKELY PHISHING": "red", "SUSPICIOUS": "amber"}
CSV_FIELDS = ["cluster", "path", "date", "from", "subject", "verdict", "score", "sha256"]


def shown(kind: str, value: str) -> str:
    if kind == "qr":
        value = defang_ioc("url", value) if value.lower().startswith(("http://", "https://")) else value
    elif kind in _IOC_KIND:
        value = defang_ioc(_IOC_KIND[kind], value)
    return printable(value)[:160]


def _name(path: str) -> str:
    """A message's file name (mbox#n and mailbox labels as they are): the full path is in the JSON and CSV."""
    return os.path.basename(path) or path


def _span(cluster: dict[str, Any]) -> str:
    first, last = cluster["first_seen"], cluster["last_seen"]
    if not first:
        return "dates unknown"
    first, last = first.replace("T", " ")[:16], last.replace("T", " ")[:16]
    return first if first == last else "%s to %s" % (first, last)


def render_console(result: dict[str, Any], colour: Palette) -> str:
    clusters = result["clusters"]
    out = [colour("CAMPAIGNS: %s across %s (%d not in any campaign)"
                  % (plural(len(clusters), "cluster"), plural(result["messages"], "message"),
                     len(result["unclustered"])), "bold")]
    for cluster in clusters:
        out += ["", "%s  %s  %s  %s  %s" % (
            colour(cluster["id"], "cyan"), plural(cluster["size"], "message"),
            colour(cluster["worst_verdict"], _TONE.get(cluster["worst_verdict"], "green")), _span(cluster),
            plural(len(cluster["recipients"]), "recipient"))]
        links = ", ".join("%s %s (%d)" % (item["kind"], shown(item["kind"], item["value"]), item["messages"])
                          for item in cluster["shared"][:6])
        out.append("    shared    : %s" % links)
        out.append("    senders   : %s" % ", ".join(shown("sender", s) for s in cluster["senders"][:6]))
        out.append("    messages  : %s" % ", ".join(printable(_name(m["path"])) for m in cluster["messages"][:6])
                   + (" ..." if cluster["size"] > 6 else ""))
    return "\n".join(out)


def render_csv(result: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    rows = [(c["id"], m) for c in result["clusters"] for m in c["messages"]]
    rows += [("", m) for m in result["unclustered"]]
    for cluster, message in rows:
        row = {"cluster": cluster, "path": printable(message["path"]), "date": printable(message["date"]),
               "from": printable(message["from"]), "subject": printable(message["subject"]),
               "verdict": message["verdict"], "score": message["score"], "sha256": message["sha256"]}
        writer.writerow({key: _safe(cell) for key, cell in row.items()})
    return buffer.getvalue()


def render_markdown(result: dict[str, Any]) -> str:
    out = ["# Campaign correlation", "",
           "%s across %s; %d not in any campaign." % (plural(len(result["clusters"]), "campaign"),
                                                          plural(result["messages"], "message"),
                                                          len(result["unclustered"])), ""]
    for cluster in result["clusters"]:
        out += ["## Campaign %s: %s, %s" % (cluster["id"], plural(cluster["size"], "message"),
                                           cluster["worst_verdict"]), "",
                "- **Seen:** %s" % _span(cluster),
                "- **Recipients (%d):** %s" % (len(cluster["recipients"]),
                                               ", ".join(_code(printable(r)) for r in cluster["recipients"][:30])),
                "- **Senders:** %s" % ", ".join(_code(shown("sender", s)) for s in cluster["senders"][:30]), "",
                "| Shared | Value | Messages |", "|---|---|---|"]
        out += ["| %s | %s | %d |" % (item["kind"], _code(shown(item["kind"], item["value"])), item["messages"])
                for item in cluster["shared"]]
        out += ["", "| Message | Date | Verdict |", "|---|---|---|"]
        out += ["| %s | %s | %s |" % (_cell(printable(_name(m["path"]))), _cell(printable(m["date"])),
                                         m["verdict"])
                for m in cluster["messages"]]
        out.append("")
    return "\n".join(out)
