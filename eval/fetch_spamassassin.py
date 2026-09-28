#!/usr/bin/env python3
"""Fetch the legitimate-mail samples used in eval/README.md.

    python eval/fetch_spamassassin.py WORKDIR

Downloads the ham folders of the SpamAssassin public corpus: 4,150 real
legitimate emails from 2002, with full headers. hard_ham is legitimate mail
that looks like spam (newsletters, offers, mailing-list digests). They are
split into:

    WORKDIR/tune/easy      easy_ham, 2,500      the false-positive fixes were developed against these
    WORKDIR/tune/hard      hard_ham, 125        (a seeded half)
    WORKDIR/holdout/easy   easy_ham_2, 1,400    never looked at while developing: the honest number
    WORKDIR/holdout/hard   hard_ham, 125        (the other half)

Every file's name carries its MD5, which is checked. When
spamassassin.apache.org cannot be reached, the same files are taken from the
@stdlib/datasets-spam-assassin npm package (Apache-2.0), which ships them
byte for byte. The messages must not be committed to this repository.
"""

from __future__ import annotations

import hashlib
import io
import os
import random
import re
import shutil
import sys
import tarfile
import urllib.request

OFFICIAL = "https://spamassassin.apache.org/old/publiccorpus/20030228_%s.tar.bz2"
NPM = "https://registry.npmjs.org/@stdlib/datasets-spam-assassin/-/datasets-spam-assassin-0.2.3.tgz"
FOLDERS = {"easy_ham": "easy-ham-1", "easy_ham_2": "easy-ham-2", "hard_ham": "hard-ham-1"}  # official: npm
NAME_RE = re.compile(r"^(\d{5}\.([0-9a-f]{32}))(?:\.txt)?$")
SEED = 2026


def download(url: str) -> bytes:
    print("fetching", url)
    with urllib.request.urlopen(url, timeout=300) as response:
        return response.read()


def messages(archive: bytes, mode: str, folder: str) -> dict[str, bytes]:
    """name -> raw message, for the files directly inside `folder`. Members
    are read, never extracted, so archive paths cannot escape WORKDIR."""
    found: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode=mode) as tar:
        for member in tar:
            parent, _, base = member.name.rpartition("/")
            match = NAME_RE.match(base)
            if member.isfile() and match and parent.endswith(folder):
                found[match.group(1)] = tar.extractfile(member).read()
    return found


def fetch_all() -> dict[str, dict[str, bytes]]:
    try:
        return {folder: messages(download(OFFICIAL % folder), "r:bz2", folder) for folder in FOLDERS}
    except OSError as exc:
        print("official corpus unreachable (%s); using the npm copy" % exc)
    package = download(NPM)
    return {folder: messages(package, "r:gz", "data/" + npm) for folder, npm in FOLDERS.items()}


def write(folder: str, names: list[str], corpus: dict[str, bytes]) -> None:
    shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(folder)
    for name in names:
        with open(os.path.join(folder, name + ".eml"), "wb") as handle:
            handle.write(corpus[name])


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    work = os.path.abspath(sys.argv[1])
    corpus = fetch_all()
    for folder, files in corpus.items():
        bad = [name for name, data in files.items() if hashlib.md5(data).hexdigest() != name.split(".")[1]]
        print("%-10s %4d messages, %d not matching the MD5 in their name %s"
              % (folder, len(files), len(bad), bad[:3]))
    hard = sorted(corpus["hard_ham"])
    random.Random(SEED).shuffle(hard)
    half = len(hard) // 2
    write(os.path.join(work, "tune", "easy"), sorted(corpus["easy_ham"]), corpus["easy_ham"])
    write(os.path.join(work, "tune", "hard"), hard[:half], corpus["hard_ham"])
    write(os.path.join(work, "holdout", "easy"), sorted(corpus["easy_ham_2"]), corpus["easy_ham_2"])
    write(os.path.join(work, "holdout", "hard"), hard[half:], corpus["hard_ham"])
    print("wrote %s/{tune,holdout}/{easy,hard}" % work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
