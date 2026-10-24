"""Server settings, read from PHISHHAWK_* environment variables and, when it
exists, from Docker secret files in /run/secrets. Secrets are never defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

SECRETS_DIR = "/run/secrets"


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISHHAWK_", extra="ignore")

    data_dir: Path = Path("/var/lib/phishhawk")
    database_url: str = ""  # empty: SQLite at <data_dir>/phishhawk.sqlite3; postgresql://... for Postgres
    secret_key: SecretStr  # keys the session HMAC; a new value logs everyone out
    encryption_key: SecretStr  # 32 bytes, base64: encrypts every blob and stored secret
    retention_days: int = 30
    max_upload_mb: int = 25
    max_batch_messages: int = 500
    campaign_window_days: int = 90
    host: str = "127.0.0.1"
    port: int = 8000
    tls_cert: str = ""
    tls_key: str = ""
    session_idle_minutes: int = 480
    analysis_memory_mb: int = 2048
    analysis_cpu_seconds: int = 120
    cookie_secure: bool = True  # False only for plain-HTTP local testing
    frontend_dir: str = ""  # a frontend's build, served at /app/ (docs/FRONTEND.md)
    trusted_proxies: str = "127.0.0.1"  # reverse proxies (addresses or networks) whose X-Forwarded-* count
    index_public_pages: bool = False  # true: search engines may list the product, privacy and help pages
    # who runs this server and where to write about one's data, for the privacy page: whoever set it up says
    operator_name: str = ""  # Example Security Ltd, United Kingdom
    operator_email: str = ""  # privacy@example.org
    # Mail, for confirming addresses and resetting passwords (docs/SERVER.md, "Email and password reset"): off
    # until the SMTP host, the From address and the public URL are all set.
    public_url: str = ""  # https://phishhawk.example.org: links in mail are built from it, never from the request
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: Literal["starttls", "ssl", "none"] = "starttls"  # none: a relay on this machine only
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from: str = ""  # PhishHawk <no-reply@example.org>

    @property
    def db_url(self) -> str:
        """Postgres through psycopg 3 (the postgres extra), whichever way the URL names it."""
        url = self.database_url or "sqlite:///%s" % (self.data_dir / "phishhawk.sqlite3")
        for prefix in ("postgresql://", "postgres://"):
            if url.startswith(prefix):
                return "postgresql+psycopg://" + url[len(prefix):]
        return url


def load_settings() -> ServerSettings:
    """Settings from the environment and, when the folder exists, from Docker
    secret files; a variable wins over a file."""
    build: Any = ServerSettings  # the required fields come from outside, where mypy cannot see them
    settings: ServerSettings = build(_secrets_dir=SECRETS_DIR if os.path.isdir(SECRETS_DIR) else None)
    return settings
