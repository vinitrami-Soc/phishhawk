"""Encrypted blob store: tier-1 data (raw messages, full JSON reports and
exports) as sealed files under <data_dir>/blobs, named by random IDs."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .crypto import Box, DecryptError


class BlobStore:
    def __init__(self, root: Path, box: Box) -> None:
        self.root = root
        self.box = box

    def _path(self, blob_id: str) -> Path:
        if len(blob_id) != 32 or not all(c in "0123456789abcdef" for c in blob_id):
            raise ValueError("not a blob ID")
        return self.root / blob_id[:2] / blob_id

    def put(self, data: bytes) -> str:
        blob_id = secrets.token_hex(16)
        path = self._path(blob_id)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.box.seal(data, blob_id))
        os.replace(temp, path)
        return blob_id

    def get(self, blob_id: str) -> bytes:
        return self.box.open(self._path(blob_id).read_bytes(), blob_id)

    def delete(self, blob_id: str | None) -> None:
        if blob_id:
            self._path(blob_id).unlink(missing_ok=True)

    def reseal(self, blob_id: str, new_box: Box) -> bool:
        """Re-encrypt one blob under a new key (key rotation). False when it
        already opens under the new key, so a rotation can be run again."""
        path = self._path(blob_id)
        sealed = path.read_bytes()
        try:
            new_box.open(sealed, blob_id)
            return False
        except DecryptError:
            pass
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(new_box.seal(self.box.open(sealed, blob_id), blob_id))
        os.replace(temp, path)
        return True
