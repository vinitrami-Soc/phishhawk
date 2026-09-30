#!/usr/bin/env python3
"""Fetch the fresh held-out sets used for PhishHawk 2.0 in eval/README.md.

    python eval/fetch_fresh.py WORKDIR

Four sets, none of them looked at while developing 2.0, each from a public
repository pinned to a commit in eval/splits/fresh_2026.json:

    WORKDIR/nazario    2,279 phishing emails from 2005 to 2007 (Jose Nazario's corpus)
    WORKDIR/enron      4,279 legitimate business emails from Enron, 2000 to 2002
    WORKDIR/fixtures   136 legitimate edge-case emails from four mail libraries' tests
    WORKDIR/msg        5 Outlook .msg files

Repositories are downloaded as tarballs of the pinned commit, and members are
read, never extracted, so archive paths cannot escape WORKDIR. Each set is
checked against the sha256 recorded when it was scored. The messages must not
be committed to this repository.

Then score them:

    python eval/run_eval.py --phish WORKDIR/nazario --benign WORKDIR/enron
"""

from __future__ import annotations

import hashlib
import io
import json
import mailbox
import os
import sys
import tarfile
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SPLIT = os.path.join(HERE, "splits", "fresh_2026.json")
TARBALL = "https://codeload.github.com/%s/tar.gz/%s"


def download(repo: str, commit: str) -> tarfile.TarFile:
    url = TARBALL % (repo, commit)
    print("fetching", url)
    with urllib.request.urlopen(url, timeout=600) as response:
        return tarfile.open(fileobj=io.BytesIO(response.read()), mode="r:gz")


def member(tar: tarfile.TarFile, path: str) -> bytes:
    """A file by its path inside the repository (tarballs add a top folder)."""
    for info in tar:
        if info.isfile() and info.name.split("/", 1)[-1] == path:
            handle = tar.extractfile(info)
            if handle is not None:
                return handle.read()
    raise SystemExit("%s is not in the tarball" % path)


def write(folder: str, name: str, data: bytes) -> None:
    if os.sep in name or name.startswith("."):
        raise SystemExit("unsafe file name %r" % name)
    with open(os.path.join(folder, name), "wb") as handle:
        handle.write(data)


def digest(folder: str) -> str:
    h = hashlib.sha256()
    for name in sorted(os.listdir(folder)):
        with open(os.path.join(folder, name), "rb") as handle:
            h.update(name.encode() + b"\0" + hashlib.sha256(handle.read()).digest())
    return h.hexdigest()


def from_mbox(tar: tarfile.TarFile, spec: dict, folder: str) -> None:
    with tempfile.NamedTemporaryFile(suffix=".mbox") as handle:
        handle.write(member(tar, spec["mbox"]))
        handle.flush()
        box = mailbox.mbox(handle.name, create=False)
        for number, key in enumerate(box.keys(), 1):
            write(folder, "%s-%05d.eml" % (spec["prefix"], number), box.get_bytes(key))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    workdir = sys.argv[1]
    with open(SPLIT, encoding="utf-8") as handle:
        sets = json.load(handle)["sets"]
    tarballs: dict[tuple[str, str], tarfile.TarFile] = {}

    def tarball(repo: str, commit: str) -> tarfile.TarFile:
        if (repo, commit) not in tarballs:
            tarballs[(repo, commit)] = download(repo, commit)
        return tarballs[(repo, commit)]

    for name, spec in sets.items():
        folder = os.path.join(workdir, name)
        os.makedirs(folder, exist_ok=True)
        if "mbox" in spec:
            from_mbox(tarball(spec["repo"], spec["commit"]), spec, folder)
        else:
            for source in spec["sources"]:
                tar = tarball(source["repo"], source["commit"])
                prefix = source["repo"].replace("/", "_")
                for path in source["paths"]:
                    flat = path.split("/")[-1] if name == "msg" else \
                        "%s-%s" % (prefix, path.replace("/", "_").replace(" ", "_"))
                    write(folder, flat, member(tar, path))
        count, got = len(os.listdir(folder)), digest(folder)
        status = "ok" if got == spec["sha256"] and count == spec["count"] else "MISMATCH"
        print("%-9s %5d files  %s" % (name, count, status))
        if status != "ok":
            raise SystemExit("%s does not match the set that was scored (expected %d files, sha256 %s)"
                             % (name, spec["count"], spec["sha256"]))


if __name__ == "__main__":
    main()
