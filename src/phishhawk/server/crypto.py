"""AES-256-GCM sealing for blobs and stored secrets. Each sealed value has a
fresh 96-bit nonce and is bound to its ID as associated data, so a value
copied onto another record does not decrypt."""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PHB1"


class DecryptError(Exception):
    """Wrong key, a value bound to another ID, or a damaged value."""


def new_key() -> str:
    """A fresh key in the form PHISHHAWK_ENCRYPTION_KEY expects."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


class Box:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("the encryption key must be 32 bytes")
        self._aead = AESGCM(key)

    @classmethod
    def from_b64(cls, text: str) -> Box:
        try:
            return cls(base64.b64decode(text.strip(), validate=True))
        except (binascii.Error, ValueError) as exc:
            raise ValueError("PHISHHAWK_ENCRYPTION_KEY must be 32 bytes in base64") from exc

    def seal(self, data: bytes, bound_to: str) -> bytes:
        nonce = os.urandom(12)
        return MAGIC + nonce + self._aead.encrypt(nonce, data, bound_to.encode("utf-8"))

    def open(self, sealed: bytes, bound_to: str) -> bytes:
        if not sealed.startswith(MAGIC) or len(sealed) < len(MAGIC) + 12 + 16:
            raise DecryptError("not a sealed value")
        nonce, body = sealed[4:16], sealed[16:]
        try:
            return self._aead.decrypt(nonce, body, bound_to.encode("utf-8"))
        except InvalidTag as exc:
            raise DecryptError("wrong key, wrong record, or damaged") from exc
