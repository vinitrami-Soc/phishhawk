"""Classify links to infrastructure an attacker can stand up for free."""

from __future__ import annotations

from urllib.parse import urlsplit

from .knowledge import FILE_SHARING, FREE_HOSTING, IPFS_GATEWAYS, TUNNELS_AND_IPFS


def hosting_kind(url: str) -> str:
    """"tunnel or IPFS", "free hosting", "file sharing" or ""."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if host.endswith(TUNNELS_AND_IPFS) or (host in IPFS_GATEWAYS and path.startswith("/ipfs/")):
        return "tunnel or IPFS"
    if host.endswith(FREE_HOSTING) or host.endswith(".s3.amazonaws.com") or \
            (host.startswith("s3.") and host.endswith(".amazonaws.com")) or \
            host.endswith(".blob.core.windows.net"):
        return "free hosting"
    bare = host[4:] if host.startswith("www.") else host
    for share_host, prefixes in FILE_SHARING:
        if bare == share_host and path.startswith(prefixes):
            return "file sharing"
    return ""
