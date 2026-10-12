"""Helpers the server tests share."""

PASSWORD = "correct horse battery"


def login(app, username):
    """A client logged in as username, sending its CSRF token on every request."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post("/api/v1/session", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client
