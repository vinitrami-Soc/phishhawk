"""AES-256-GCM sealing: a fresh nonce every time, and keys checked."""

import pytest

from phishhawk.server.crypto import Box, DecryptError, new_key


def test_a_sealed_value_opens_only_with_its_key_and_its_id(box):
    sealed = box.seal(b"evidence", "a" * 32)
    assert box.open(sealed, "a" * 32) == b"evidence"
    for other_box, bound_to, value in ((box, "b" * 32, sealed), (Box.from_b64(new_key()), "a" * 32, sealed),
                                       (box, "a" * 32, b"not a sealed value at all, just bytes")):
        with pytest.raises(DecryptError):
            other_box.open(value, bound_to)


def test_each_seal_uses_a_fresh_nonce(box):
    first, second = box.seal(b"same", "a" * 32), box.seal(b"same", "a" * 32)
    assert first != second and first[4:16] != second[4:16]


def test_a_bad_key_or_blob_id_is_refused():
    with pytest.raises(ValueError):
        Box.from_b64("too-short")
    with pytest.raises(ValueError):
        Box(b"x" * 16)
