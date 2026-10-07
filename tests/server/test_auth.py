"""Users, sessions, API tokens and the login throttle."""

import datetime as dt

import pytest
from sqlalchemy import select

from phishhawk.server import auth
from phishhawk.server.crypto import new_key
from phishhawk.server.db import transaction
from phishhawk.server.models import ApiToken, Session, User

PASSWORD = "correct horse battery"
SECRET = new_key()  # made at run time: no key-like literals for the secret scanner


def _user(db, name="alice", role="analyst"):
    with transaction(db) as s:
        return auth.create_user(s, name, PASSWORD, role).id


def test_passwords_are_argon2_and_checked(db):
    _user(db)
    with transaction(db) as s:
        assert s.scalars(select(User)).one().password_hash.startswith("$argon2id$")
        assert auth.check_login(s, "alice", PASSWORD).username == "alice"
        assert auth.check_login(s, "alice", "wrong password!") is None
        assert auth.check_login(s, "nobody", PASSWORD) is None


@pytest.mark.parametrize("name, password, role", [("A", PASSWORD, "analyst"), ("bob", "short", "analyst"),
                                                  ("bob", PASSWORD, "root")])
def test_bad_usernames_passwords_and_roles_are_refused(db, name, password, role):
    with transaction(db) as s, pytest.raises(auth.AuthError):
        auth.create_user(s, name, password, role)


def test_a_session_cookie_is_stored_only_as_its_hash_and_expires_when_idle(db):
    user_id = _user(db)
    with transaction(db) as s:
        cookie, session = auth.open_session(s, s.get(User, user_id), SECRET)
        assert session.id == auth.session_id(SECRET, cookie) and cookie not in session.id
    with transaction(db) as s:
        actor = auth.find_session(s, cookie, SECRET, idle_minutes=480)
        assert actor.username == "alice" and actor.via == "session" and actor.csrf
    with transaction(db) as s:
        s.scalars(select(Session)).one().last_seen_at -= dt.timedelta(hours=9)
    with transaction(db) as s:
        assert auth.find_session(s, cookie, SECRET, idle_minutes=480) is None
        assert s.scalars(select(Session)).first() is None  # an expired session is removed


def test_a_new_secret_key_ends_every_session(db):
    user_id = _user(db)
    with transaction(db) as s:
        cookie, _ = auth.open_session(s, s.get(User, user_id), SECRET)
    with transaction(db) as s:
        assert auth.find_session(s, cookie, new_key(), 480) is None


def test_a_disabled_user_loses_their_session(db):
    user_id = _user(db)
    with transaction(db) as s:
        cookie, _ = auth.open_session(s, s.get(User, user_id), SECRET)
        s.get(User, user_id).disabled = True
    with transaction(db) as s:
        assert auth.find_session(s, cookie, SECRET, 480) is None


def test_api_tokens_are_shown_once_stored_hashed_scoped_and_revocable(db):
    user_id = _user(db, "bot", "analyst")
    with transaction(db) as s:
        token = auth.create_token(s, s.get(User, user_id), "intelpulse", "read")
    assert token.startswith("phk_")
    with transaction(db) as s:
        row = s.scalars(select(ApiToken)).one()
        assert row.token_hash == auth.digest(token)
        actor = auth.find_token(s, token)
        assert (actor.via, actor.scope, actor.label) == ("token", "read", "token:intelpulse")
        row.revoked_at = row.created_at
    with transaction(db) as s:
        assert auth.find_token(s, token) is None


def test_the_throttle_doubles_the_wait_after_three_failures():
    now = [100.0]
    throttle = auth.LoginThrottle(clock=lambda: now[0])
    for _ in range(3):
        assert throttle.wait("user:alice") == 0
        throttle.failed("user:alice", "ip:10.0.0.1")
    assert throttle.wait("user:alice") == 1.0 and throttle.wait("ip:10.0.0.1") == 1.0
    now[0] += 1.0
    throttle.failed("user:alice")
    assert throttle.wait("user:alice") == 2.0
    throttle.succeeded("user:alice")
    assert throttle.wait("user:alice") == 0
