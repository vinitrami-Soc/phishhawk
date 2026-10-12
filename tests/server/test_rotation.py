"""Key rotation re-encrypts every tier-1 blob and every stored secret, and can
be run again after a crash."""

import pytest
from sqlalchemy import select

from phishhawk.server import appsettings, audit, intake, rotation, worker
from phishhawk.server.crypto import Box, DecryptError, new_key
from phishhawk.server.db import transaction
from phishhawk.server.models import Analysis, AuditRecord, Message
from phishhawk.server.store import BlobStore

from conftest import sample


def _analysed(services):
    with open(sample("sample_phish.eml"), "rb") as handle:
        raw = handle.read()
    with transaction(services.sessions) as s:
        intake.accept(s, services.store, raw, source="upload", user_id=None, actor="alice", offline=True,
                      max_bytes=25 * 1024 * 1024)
        appsettings.set_secret(s, services.box, "key:virustotal", "vt-key-1234")
        appsettings.trait_key(s, services.box)
    assert worker.run_one(services)


def _blob_ids(s):
    ids = [m.raw_blob for m in s.scalars(select(Message))]
    for analysis in s.scalars(select(Analysis)):
        ids += [analysis.data_blob, analysis.state_blob] + [f["blob"] for f in analysis.files]
    return ids


def test_rotation_moves_every_blob_and_secret_to_the_new_key(services):
    _analysed(services)
    new_box = Box.from_b64(new_key())
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli") == {"blobs": 10, "secrets": 2}
    moved = BlobStore(services.store.root, new_box)
    with transaction(services.sessions) as s:
        for blob_id in _blob_ids(s):
            moved.get(blob_id)
            with pytest.raises(DecryptError):
                services.store.get(blob_id)
        assert appsettings.get_secret(s, new_box, "key:virustotal") == "vt-key-1234"
        with pytest.raises(DecryptError):
            appsettings.get_secret(s, services.box, "key:virustotal")
        entry = s.scalars(select(AuditRecord).where(AuditRecord.action == "rotate_key")).one()
        assert entry.actor == "cli" and entry.details == {"blobs": 10, "secrets": 2}
        assert audit.verify(s) == []


def test_rotation_run_again_after_a_crash_skips_what_already_moved(services):
    _analysed(services)
    new_box = Box.from_b64(new_key())
    with transaction(services.sessions) as s:
        first = _blob_ids(s)[0]
    services.store.reseal(first, new_box)  # the crash happened after one blob
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli") == {"blobs": 9, "secrets": 2}
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli") == {"blobs": 0, "secrets": 0}


def test_a_blob_neither_key_opens_stops_the_rotation_and_deletes_nothing(services):
    _analysed(services)
    with transaction(services.sessions) as s:
        damaged = _blob_ids(s)[0]
    services.store._path(damaged).write_bytes(b"PHB1" + b"\0" * 40)
    with transaction(services.sessions) as s, pytest.raises(DecryptError):
        rotation.rotate(s, services.store, Box.from_b64(new_key()), actor="cli")
    with transaction(services.sessions) as s:
        assert all(services.store._path(blob_id).exists() for blob_id in _blob_ids(s))


def test_rotation_moves_a_batchs_combined_exports_too(services):
    from phishhawk.server.models import Batch

    blob = services.store.put(b"combined report")
    with transaction(services.sessions) as s:
        s.add(Batch(total=2, files=[{"name": "r.html", "kind": "html", "blob": blob}]))
    new_box = Box.from_b64(new_key())
    with transaction(services.sessions) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli")["blobs"] == 1
    assert BlobStore(services.store.root, new_box).get(blob) == b"combined report"
