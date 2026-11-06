"""Classify links to infrastructure an attacker can stand up for free."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .knowledge import FILE_SHARING, FREE_HOSTING, IPFS_GATEWAYS, TUNNELS_AND_IPFS

# Object storage: buckets of files anyone can rent, most with a free tier.
# A web page there is a file someone uploaded, the commonest way to put up a
# phishing page without a website of one's own (Oracle, DigitalOcean,
# Backblaze, Wasabi, Linode, IBM, Alibaba, Google, Amazon, Azure).
_BUCKET_HOST_RE = re.compile(
    r"(?:^|\.)objectstorage\.[a-z0-9-]+\.(?:oraclecloud\.com|oci\.customer-oci\.com)$"
    r"|\.digitaloceanspaces\.com$|\.backblazeb2\.com$|\.wasabisys\.com$|\.linodeobjects\.com$"
    r"|\.cloud-object-storage\.appdomain\.cloud$|\.oss-[a-z0-9-]+\.aliyuncs\.com$"
    r"|\.storage\.googleapis\.com$|\.blob\.core\.windows\.net$"
    r"|(?:^|\.)s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$|\.s3\.dualstack\.[a-z0-9-]+\.amazonaws\.com$")
_BUCKET_HOSTS = {"storage.googleapis.com", "firebasestorage.googleapis.com"}
_SUPABASE_STORAGE = "/storage/v1/object/"
# What a browser shows as a page, not as a file to save.
_PAGE_EXTENSIONS = (".html", ".htm", ".shtml", ".xhtml", ".svg")


def _parts(url: str) -> tuple[str, str]:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", "/"
    return (parts.hostname or "").lower(), parts.path or "/"


def on_object_storage(url: str) -> bool:
    host, path = _parts(url)
    return bool(_BUCKET_HOST_RE.search(host)) or host in _BUCKET_HOSTS or \
        (host.endswith(".supabase.co") and path.startswith(_SUPABASE_STORAGE))


def stored_web_page(url: str) -> bool:
    """A web page kept as a file in a cloud storage bucket."""
    return on_object_storage(url) and _parts(url)[1].rstrip("/").lower().endswith(_PAGE_EXTENSIONS)


def hosting_kind(url: str) -> str:
    """"tunnel or IPFS", "free hosting", "file sharing" or ""."""
    host, path = _parts(url)
    if not host:
        return ""
    if host.endswith(TUNNELS_AND_IPFS) or (host in IPFS_GATEWAYS and path.startswith("/ipfs/")):
        return "tunnel or IPFS"
    if host.endswith(FREE_HOSTING) or _BUCKET_HOST_RE.search(host):
        return "free hosting"
    if host.endswith(".supabase.co") and path.startswith(_SUPABASE_STORAGE):
        return "file sharing"
    bare = host[4:] if host.startswith("www.") else host
    for share_host, prefixes in FILE_SHARING:
        if bare == share_host and path.startswith(prefixes):
            return "file sharing"
    return ""
