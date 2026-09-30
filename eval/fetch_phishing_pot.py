#!/usr/bin/env python3
"""Fetch the real-phishing samples used in eval/README.md.

    python eval/fetch_phishing_pot.py WORKDIR           the first evaluation: 2 x 200 messages
    python eval/fetch_phishing_pot.py WORKDIR --full    the 2026 evaluation: every message

Partial-clones rf-peixoto/phishing_pot (CC BY-NC 4.0), then checks out only
two disjoint, seeded random samples of 200 messages each:

    WORKDIR/tune     seed 42  (the set detections were developed against)
    WORKDIR/holdout  seed 7   (never looked at while developing; the honest number)

With --full it checks out the corpus at the commit pinned in
eval/splits/phishing_pot_2026.json and copies the split recorded there:

    WORKDIR/pot2026/tune     2,500 messages (developed against)
    WORKDIR/pot2026/holdout  5,714 messages (scored once, at the end)

The full checkout fetches about 600 MB through git and can take an hour.

The samples are real phishing email. They are only ever parsed, never
executed, and must not be committed to this repository.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys

REPO = "https://github.com/rf-peixoto/phishing_pot"


def git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


SPLIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "splits", "phishing_pot_2026.json")


def full(work: str, clone: str) -> int:
    with open(SPLIT, encoding="utf-8") as handle:
        split = json.load(handle)
    git("fetch", "--depth", "1", "origin", split["commit"], cwd=clone)
    for label in ("tune", "holdout"):
        picked = ["email/sample-%d.eml" % number for number in split[label]]
        for start in range(0, len(picked), 500):  # the blobs arrive in batches
            git("checkout", split["commit"], "--", *picked[start:start + 500], cwd=clone)
        target = os.path.join(work, "pot2026", label)
        os.makedirs(target, exist_ok=True)
        for name in picked:
            shutil.copy(os.path.join(clone, name), target)
        print("%-8s %d messages in %s" % (label, len(picked), target))
    print("\nnext: python eval/run_eval.py --phish %s/pot2026/holdout" % work)
    return 0


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--full"):
        print(__doc__)
        return 2
    work = os.path.abspath(sys.argv[1])
    clone = os.path.join(work, "phishing_pot")
    if not os.path.isdir(os.path.join(clone, ".git")):
        os.makedirs(work, exist_ok=True)
        env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1")
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--no-checkout", REPO, clone],
                       check=True, env=env)
    if len(sys.argv) == 3:
        return full(work, clone)
    names = sorted(n for n in git("ls-tree", "-r", "--name-only", "HEAD", cwd=clone).split() if n.endswith(".eml"))
    tune = sorted(random.Random(42).sample(names, 200))
    holdout = sorted(random.Random(7).sample([n for n in names if n not in set(tune)], 200))
    for label, picked in (("tune", tune), ("holdout", holdout)):
        git("checkout", "HEAD", "--", *picked, cwd=clone)
        target = os.path.join(work, label)
        os.makedirs(target, exist_ok=True)
        for name in picked:
            shutil.copy(os.path.join(clone, name), target)
        print("%-8s %d messages in %s" % (label, len(picked), target))
    print("\nnext: python eval/run_eval.py --phish %s/holdout" % work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
