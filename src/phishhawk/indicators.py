"""Indicators beyond links and files: the cryptocurrency wallets extortion
and investment scams ask victims to pay into.

Bitcoin, Litecoin and TRON addresses carry checksums and are only reported
when the checksum holds, so a random token in a newsletter is never taken
for a wallet. Ethereum and Monero addresses are matched by shape.
"""

from __future__ import annotations

import hashlib
import re

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_RE = r"[1-9A-HJ-NP-Za-km-z]"
_WALLET_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?P<btc>[13]" + _BASE58_RE + r"{25,34})"
    r"|(?P<bech>(?:bc|ltc)1[ac-hj-np-z02-9]{11,87})"
    r"|(?P<ltc>[LM]" + _BASE58_RE + r"{26,33})"
    r"|(?P<trx>T" + _BASE58_RE + r"{33})"
    r"|(?P<eth>0x[0-9a-fA-F]{40})"
    r"|(?P<xmr>[48][0-9AB]" + _BASE58_RE + r"{93})"
    r")(?![A-Za-z0-9])")
MAX_WALLETS = 20


def _base58_decode(text: str) -> bytes | None:
    value = 0
    for char in text:
        index = _BASE58.find(char)
        if index < 0:
            return None
        value = value * 58 + index
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw


def _base58check(text: str, versions: tuple[int, ...]) -> bool:
    raw = _base58_decode(text)
    if raw is None or len(raw) != 25 or raw[0] not in versions:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            check ^= generator[i] if (top >> i) & 1 else 0
    return check


def _bech32_valid(address: str) -> bool:
    """BIP-173 (bech32) and BIP-350 (bech32m) checksums."""
    if address.lower() != address and address.upper() != address:
        return False
    address = address.lower()
    prefix, _, data = address.rpartition("1")
    if not prefix or len(data) < 6:
        return False
    values = [_BECH32_CHARSET.find(char) for char in data]
    if -1 in values:
        return False
    expanded = [ord(c) >> 5 for c in prefix] + [0] + [ord(c) & 31 for c in prefix]
    return _bech32_polymod(expanded + values) in (1, 0x2BC830A3)


def find_wallets(text: str) -> list[dict[str, str]]:
    """[{'currency', 'address'}] for every valid wallet address in `text`."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _WALLET_RE.finditer(text[:200_000]):
        address = match.group(0)
        if address in seen:
            continue
        kind = match.lastgroup
        if kind == "btc" and _base58check(address, (0x00, 0x05)):
            currency = "bitcoin"
        elif kind == "bech" and _bech32_valid(address):
            currency = "bitcoin" if address.lower().startswith("bc1") else "litecoin"
        elif kind == "ltc" and _base58check(address, (0x30, 0x32)):
            currency = "litecoin"
        elif kind == "trx" and _base58check(address, (0x41,)):
            currency = "tron"
        elif kind == "eth" and len(set(address[2:].lower())) > 4:  # not 0x000...0
            currency = "ethereum"
        elif kind == "xmr":
            currency = "monero"
        else:
            continue
        seen.add(address)
        found.append({"currency": currency, "address": address})
        if len(found) >= MAX_WALLETS:
            break
    return found
