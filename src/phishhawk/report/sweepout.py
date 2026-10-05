"""Mailbox sweep results in the terminal and as CSV. Subjects and senders
were written by the attacker: made printable, addresses defanged in the
terminal, and CSV cells cannot start a formula."""

from __future__ import annotations

import csv
import io
from typing import Any

from ..extract import defang_host
from .common import printable
from .console import Palette
from .csvout import _safe

CSV_FIELDS = ["mailbox", "received", "folder", "read", "replied", "from", "subject", "matched", "message_id", "id"]


def _yes_no(value: Any) -> str:
    return {True: "yes", False: "no"}.get(value, "unknown")


def _count(number: int, one: str, many: str) -> str:
    return "%d %s" % (number, one if number == 1 else many)


def totals(result: dict[str, Any]) -> dict[str, int]:
    matches = [m for box in result["mailboxes"] for m in box["matches"]]
    return {"copies": len(matches), "mailboxes": sum(1 for box in result["mailboxes"] if box["matches"]),
            "unread": sum(1 for m in matches if not m["read"]), "replied": sum(1 for m in matches if m["replied"]),
            "errors": sum(1 for box in result["mailboxes"] if box["error"])}


def render_console(result: dict[str, Any], colour: Palette) -> str:
    count = totals(result)
    out = [colour("SWEEP (%s): %s in %s of %s; %d unread, %d replied to"
                  % (result["service"], _count(count["copies"], "copy", "copies"),
                     _count(count["mailboxes"], "mailbox", "mailboxes"),
                     len(result["mailboxes"]), count["unread"], count["replied"]), "bold")]
    for box in result["mailboxes"]:
        if box["error"]:
            out.append(colour("  %s: %s" % (printable(box["mailbox"]), printable(box["error"])), "red"))
            continue
        if not box["matches"]:
            continue
        out += ["", colour("  %s" % printable(box["mailbox"]), "cyan")]
        for m in box["matches"]:
            state = colour("unread", "amber") if not m["read"] else "read"
            replied = colour("  REPLIED", "red") if m["replied"] else ""
            out.append("    %s  %-12s %s%s  %s  %s" % (m["received"][:16].replace("T", " ") or "?",
                                                      printable(m["folder"] or "?")[:12], state, replied,
                                                      defang_host(printable(m["from"]))[:60],
                                                      printable(m["subject"])[:70]))
            out.append(colour("      matched: %s" % printable(", ".join(m["matched"]))[:160], "dim"))
    return "\n".join(out)


def render_csv(result: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for box in result["mailboxes"]:
        for m in box["matches"]:
            row = {"mailbox": box["mailbox"], "received": m["received"], "folder": m["folder"],
                   "read": _yes_no(m["read"]), "replied": _yes_no(m["replied"]), "from": m["from"],
                   "subject": m["subject"], "matched": "; ".join(m["matched"]), "message_id": m["message_id"],
                   "id": m["id"]}
            writer.writerow({key: _safe(printable(str(cell))) for key, cell in row.items()})
    return buffer.getvalue()
