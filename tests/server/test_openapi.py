"""docs/api/openapi.json is the contract other tools build on, so it must
match the routes. After changing an API route: python tools/make_openapi.py"""

import json
import os

from phishhawk.server.app import openapi_json

DOCUMENT = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "api", "openapi.json")


def test_the_published_openapi_document_matches_the_routes(app):
    with open(DOCUMENT, encoding="utf-8") as handle:
        assert handle.read() == openapi_json(app), "run: python tools/make_openapi.py"


def test_it_describes_the_api_and_health_but_not_the_pages(app):
    paths = app.openapi()["paths"]
    assert "/healthz" in paths and "/api/v1/submissions" in paths
    assert all(path == "/healthz" or path.startswith("/api/v1/") for path in paths)


def test_it_carries_the_api_version_not_the_release(app):
    # info.version is required by OpenAPI; the release number would change it on every bump.
    assert json.loads(openapi_json(app))["info"]["version"] == "v1"
