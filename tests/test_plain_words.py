"""Every family of finding has plain words for someone checking their own mail
(frontend/src/app/plain.ts), so a new family cannot be left without a reason."""

import re
from pathlib import Path

from phishhawk.models import FAMILIES

PLAIN = Path(__file__).resolve().parents[1] / "frontend" / "src" / "app" / "plain.ts"


def test_every_family_of_finding_has_a_plain_reason():
    block = PLAIN.read_text("utf-8").split("export const REASONS", 1)[1].split("};", 1)[0]
    assert set(re.findall(r"^\s*(\w+): '", block, re.M)) == set(FAMILIES)
