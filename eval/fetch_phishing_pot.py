#!/usr/bin/env python3
"""Fetch the real-phishing samples used in eval/README.md.

    python eval/fetch_phishing_pot.py WORKDIR

Partial-clones rf-peixoto/phishing_pot (CC BY-NC 4.0), then checks out only
two disjoint, seeded random samples of 200 messages each:

    WORKDIR/tune     seed 42  (the set detections were developed against)
    WORKDIR/holdout  seed 7   (never looked at while developing; the honest number)

The samples are real phishing email. They are only ever parsed, never
executed, and must not be committed to this repository.
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys

REPO = "https://github.com/rf-peixoto/phishing_pot"


def git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    work = os.path.abspath(sys.argv[1])
    clone = os.path.join(work, "phishing_pot")
    if not os.path.isdir(os.path.join(clone, ".git")):
        os.makedirs(work, exist_ok=True)
        env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1")
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--no-checkout", REPO, clone],
                       check=True, env=env)
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
