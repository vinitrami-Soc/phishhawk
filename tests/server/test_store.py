"""Tier-1 data is sealed with AES-256-GCM, bound to its blob ID."""

import os
import stat

import pytest

from phishhawk.server.crypto import Box, DecryptError, new_key


def test_a_blob_round_trips_and_is_not_stored_in_clear(store):
    blob_id = store.put(b"Subject: payroll\r\n\r\nsecret body")
    assert store.get(blob_id) == b"Subject: payroll\r\n\r\nsecret body"
    on_disk = store._path(blob_id).read_bytes()
    assert b"payroll" not in on_disk and b"secret body" not in on_disk
    assert stat.S_IMODE(os.stat(store._path(blob_id)).st_mode) == 0o600


def test_a_blob_copied_onto_another_id_does_not_open(store):
    one, two = store.put(b"one"), store.put(b"two")
    store._path(two).write_bytes(store._path(one).read_bytes())
    with pytest.raises(DecryptError):
        store.get(two)


def test_the_wrong_key_does_not_open_a_blob(store, settings):
    blob_id = store.put(b"evidence")
    other = Box.from_b64(new_key())
    with pytest.raises(DecryptError):
        other.open(store._path(blob_id).read_bytes(), blob_id)


def test_reseal_moves_a_blob_to_a_new_key(store):
    blob_id = store.put(b"evidence")
    new_box = Box.from_b64(new_key())
    store.reseal(blob_id, new_box)
    assert new_box.open(store._path(blob_id).read_bytes(), blob_id) == b"evidence"


def test_blob_ids_cannot_reach_outside_the_store(store):
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")
