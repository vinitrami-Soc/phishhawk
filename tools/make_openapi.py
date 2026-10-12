#!/usr/bin/env python3
"""Write docs/api/openapi.json from the web app's routes.

    python tools/make_openapi.py

Needs the server extra (pip install -e ".[dev,server]"). The app is built with
throwaway keys in a temporary folder; nothing is stored. tests/server/
test_openapi.py fails when the routes change and this has not been run.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from phishhawk.server.app import create_app, openapi_json
from phishhawk.server.config import ServerSettings
from phishhawk.server.crypto import new_key

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCUMENT = os.path.join(ROOT, "docs", "api", "openapi.json")


def main() -> None:
    with tempfile.TemporaryDirectory() as data:
        settings = ServerSettings(data_dir=Path(data), secret_key=new_key(), encryption_key=new_key())
        text = openapi_json(create_app(settings))
    os.makedirs(os.path.dirname(DOCUMENT), exist_ok=True)
    with open(DOCUMENT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print("wrote %s" % os.path.relpath(DOCUMENT, ROOT))


if __name__ == "__main__":
    main()
